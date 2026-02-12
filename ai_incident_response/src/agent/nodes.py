"""This module contains all the defined nodes of the graph for the AI incident response agent."""
import json
import os
from collections import deque
from datetime import datetime, timedelta
from email.message import EmailMessage
from pathlib import Path

from aiosmtplib import send
from dotenv import load_dotenv

from src.agent.llm import invoke_llm
from src.agent.rag import retrieve_soc_policy
from src.agent.states import Incident_Details, Ip_Findings
from src.agent.utils import serialize_for_json, supply_logs

load_dotenv()


# --- Constants ---
SENSITIVE_PORTS = {22, 3306, 6379, 3389, 5432}

# Time window
TIME_WINDOW = timedelta(minutes=3)   

# file path to incident records
BASE_DIR = Path(__file__).resolve().parents[2]
INCIDENT_RECORD_FILE = BASE_DIR / "static" / "incident_records" / "incidents.json"
REPORT_FILE = BASE_DIR / "static" / "reports" / "incident_response_report.txt"




# To keep track of recent logs for context
recent_logs = deque(maxlen=1000)
log_iterator = None
read_all_logs = False




# --- Nodes ---


def get_logs(state):
    """Retrieve logs in time windows and update state."""
    state.current_step = "get_logs"

    global log_iterator
    if log_iterator is None:
        log_iterator = supply_logs()
    
    batch = []
    window_start = None

    try:
        while True:
            item = next(log_iterator)
            log_entry = item["log"]
            timestamp_str = log_entry.split()[0]

            #-- format timestamp
            timestamp = datetime.fromisoformat(timestamp_str)

            #-- initialize window start
            if window_start is None:
                window_start = timestamp
            
            #-- break if outside time window
            if timestamp - window_start > TIME_WINDOW:
                break

            batch.append(log_entry)
            recent_logs.append(log_entry)
        state.current_logs = {"logs": batch}
        
        
               
        return state

    except StopIteration:
        state.logs_read = True
        state.current_step = "all logs read"

        if not state.scanner_ips:
            state.done = True
        return state



def parse_logs(state):
    """Parse raw logs and the required fileds into structured format."""
    state.current_step = "parse_logs"

    #-- check if logs are present
    if not state.current_logs or "logs" not in state.current_logs:
        return state

    parsed_logs = []
    parts = []
    #-- parse each log entry-- 
    for log in state.current_logs["logs"]:
        parts = log.strip().split()
        parsed_log = {  
            "timestamp": datetime.fromisoformat(parts[0]),
            "source": parts[1],
            "src_ip": parts[2].split("=")[1],
            "dest_port": int(parts[3].split("=")[1]),
            "protocol": parts[4].split("=")[1],
            "tcp_flags": parts[4].split("=")[2] if "tcp_flags" in parts[4] else None,
            "action": parts[5].split("=")[1],
            "unique ports": set()
        }

        parsed_logs.append(parsed_log)
    
    state.current_logs = {"parsed_logs": parsed_logs}
    

    
    return state

def collect_features(state):
    """Collect features from parsed logs for IP behavior analysis."""
    state.current_step = "collect_features"
    if not state.current_logs:
        return state

    parsed_logs = state.current_logs.get("parsed_logs", [])

    if not parsed_logs:
        return state
    for log in parsed_logs:

        if log.get("src_ip") is None:
            continue
        
        #-- initialize ip stats if not present --
        if log["src_ip"] not in state.ip_window_stats:
            state.ip_window_stats[log["src_ip"]] ={
                "fin_scan_attempts":0,
                "syn_scan_attempts":0,
                "sensitive_port_count":0,
                "classification": "normal",
                "unique_ports": set()
            }
        
        #--unique ports accessed --
        state.ip_window_stats[log["src_ip"]]["unique_ports"].add(log["dest_port"])
        

        #--parse the tcp flags and actionn
        if log["protocol"] == "TCP" and log["tcp_flags"]:

            flags = log["tcp_flags"].split(",")
            action = log["action"]


            #-- syn scan count --
            if "SYN" in flags and action == "BLOCKED":
                state.ip_window_stats[log["src_ip"]]["syn_scan_attempts"] +=1
            
            #-- fin scan count --
            if "FIN" in flags and action == "BLOCKED":
                state.ip_window_stats[log["src_ip"]]["fin_scan_attempts"] +=1
            
        
        


        #-- sensitive port access count --
        if log["dest_port"] in SENSITIVE_PORTS:
            state.ip_window_stats[log["src_ip"]]["sensitive_port_count"] +=1    
    return state


def classify_ip(state):
    """Classify IPs based on collected features as normal, suspicious, or scanner."""
    state.current_step = "classify_ip"

    for ip, stats in state.ip_window_stats.items():

        syn_scan_attempts = stats["syn_scan_attempts"]
        fin_scan_attempts = stats["fin_scan_attempts"]
        sensitive_port_count = stats["sensitive_port_count"]

        if syn_scan_attempts + fin_scan_attempts >= 3:
            stats["classification"] = "scanner"
        
        elif syn_scan_attempts + fin_scan_attempts >= 1:
            stats["classification"] = "suspicious"

        
        elif len(stats["unique_ports"]) > 4 or sensitive_port_count > 3:
            stats["classification"] = "scanner"
        
        else:
            stats["classification"] = "normal"

    return state


def collect_scanner_ip(state):
    """Collect scanner IPs  of current window and update state."""
    state.current_step = "collect_scanner_ips"

    for ip, stats in state.ip_window_stats.items():

        if stats["classification"] == "scanner" and ip not in state.scanner_ips:
            state.scanner_ips.append(ip)

            if ip not in state.suspicious_ip:
                state.suspicious_ip[ip] = {
                    "windows": 1,
                    "syn_scan_attempts": stats["syn_scan_attempts"],
                    "fin_scan_attempts": stats["fin_scan_attempts"],
                    "sensitive_port_count": stats["sensitive_port_count"]
                }
            
            else:
                state.suspicious_ip[ip]["windows"] +=1
                state.suspicious_ip[ip]["fin_scan_attempts"] += stats["fin_scan_attempts"]
                state.suspicious_ip[ip]["syn_scan_attempts"] += stats["syn_scan_attempts"]
                state.suspicious_ip[ip]["sensitive_port_count"] += stats["sensitive_port_count"]
        
        elif stats["classification"] == "suspicious":
            if ip not in state.suspicious_ip:
                state.suspicious_ip[ip] = {
                    "windows": 1,
                    "syn_scan_attempts": stats["syn_scan_attempts"],
                    "fin_scan_attempts": stats["fin_scan_attempts"],
                    "sensitive_port_count": stats["sensitive_port_count"],
                    "unique_ports": set(stats["unique_ports"])
                }
            else:
                state.suspicious_ip[ip]["windows"] +=1
                state.suspicious_ip[ip]["fin_scan_attempts"] += stats["fin_scan_attempts"]
                state.suspicious_ip[ip]["syn_scan_attempts"] += stats["syn_scan_attempts"]
                state.suspicious_ip[ip]["sensitive_port_count"] += stats["sensitive_port_count"] 
                state.suspicious_ip[ip]["unique_ports"].update(stats["unique_ports"])

                if state.suspicious_ip[ip]["windows"]>=3 :
                        state.scanner_ips.append(ip)


    state.current_logs = None
    state.ip_window_stats.clear()
    
    return state


def collect_evidence(state):
    """Collect evidence logs for the detected scanner IPs."""
    state.current_step = "collect_evidence"
    if state.incident_details is None:
        state.incident_details = Incident_Details(
            incident_type="Slow port scan detected",
            time_of_incident=datetime.now().isoformat()
        )


    for ip in state.scanner_ips:

        evidence_logs = [log for log in recent_logs if ip in log][:5]

        finding = Ip_Findings(
            severity_score=0,
            severity_level="Low",
            confidence_score=0.0,
            evidence_list=[
                {
                    "scan_type": "slow port scan",
                    "windows_detected": state.suspicious_ip[ip]["windows"],
                    "sensitive_ports_accessed": state.suspicious_ip[ip]["sensitive_port_count"],
                    "raw_logs": evidence_logs
                }
            ]
        )

        state.incident_details.ip_findings[ip] = finding

    return state


def set_severity(state):
    """Set severity level and score based on scanner IP behavior analysis."""
    state.current_step = "set_severity"

    if state.incident_details is None:
        state.incident_details = Incident_Details()

    max_severity_score = 0
    final_severity_level = "Low"

    for ip in state.scanner_ips:
        windows = state.suspicious_ip[ip]["windows"]
        syn = state.suspicious_ip[ip]["syn_scan_attempts"]
        fin = state.suspicious_ip[ip]["fin_scan_attempts"]
        sensitive = state.suspicious_ip[ip]["sensitive_port_count"]

        score = (syn + fin) * 10 * windows
        if sensitive > 0:
            score += 20

        score = min(score, 100)

        # Determine severity level
        if score >= 75:
            final_severity_level = "Critical"
        elif score >= 50:
            final_severity_level = "High"
        elif score >= 25:
            final_severity_level = "Medium"

        confidence_score = calculate_confidence(windows, syn, fin, sensitive)

        # Update individual IP findings
        if state.incident_details and ip in state.incident_details.ip_findings:
            state.incident_details.ip_findings[ip].severity_score = score
            state.incident_details.ip_findings[ip].severity_level = final_severity_level
            state.incident_details.ip_findings[ip].confidence_score = confidence_score
        
    return state



def calculate_confidence(windows, syn, fin, sensitive):
    """ Calculate confidence score for the incident classification based on evidence and severity."""

    confidence = min(
    (windows * 0.2) +
    ((syn + fin) * 0.05) +
    (0.1 if sensitive > 0 else 0),
    1.0)
    return float(f"{confidence:.2f}")
    


async def map_policy(state):
    state.current_step = "map_policy"

    incident = state.incident_details
    if incident is None:
        return state

    query = """
    SOC policies for handling slow port scanning incidents.
    Include response procedures for Low, Medium, High, and Critical severity levels.
    """

    related_policies = await retrieve_soc_policy(query)

    ip_data = []

    for ip, finding in incident.ip_findings.items():
        ip_data.append({
            "ip_address": ip,
            "severity_level": finding.severity_level,
            "severity_score": finding.severity_score,
            "confidence_score": finding.confidence_score
        })

    prompt = f"""
You are a senior SOC analyst.

POLICY EXCERPTS:
{related_policies}

Below are detected IP findings:

{ip_data}

TASK:
For EACH IP:
1. Identify which policy sections apply.
2. Briefly explain why they apply.
3. Do NOT invent policies.
4. Use only the provided excerpts.

Return output STRICTLY in JSON format as:

{{
  "ip_address": {{
      "policy_mapping": "text explanation here"
  }}
}}
"""

    response = await invoke_llm(prompt)

    try:
        response = response.strip().strip("```json").strip("```")
        parsed = json.loads(response)
    except Exception:
        return state

    for ip, content in parsed.items():
        state.incident_details.policy_mapping[ip] = content.get("policy_mapping")

    return state




async def summarize_incident(state):
    """Summarize the incident using LLM based on incident details."""
    prompt = f"""
            You are a senior SOC analyst.

            Based on the following incident details, provide a concise summary of the incident.

            INCIDENT DETAILS:
            - Type: {state.incident_details.incident_type}
            - IP Findings: {state.incident_details.ip_findings}
            - Time: {state.incident_details.time_of_incident}
            - Policy Mapping: {state.incident_details.policy_mapping}

            TASK:
            Provide a brief summary of the incident in 3-4 sentences.
            """
    summary = await invoke_llm(prompt)
    state.incident_details.summary = summary
    
    return state



async def recommend_actions(state):
    """Generate recommended action for the detected incident."""
    prompt = f"""
            You are a senior SOC analyst.

            Based on the following incident details and policy mappings, recommend actionable steps to mitigate the incident.

            INCIDENT DETAILS:
            - Type: {state.incident_details.incident_type}
            - IP Findings: {state.incident_details.ip_findings}
            - Time: {state.incident_details.time_of_incident}
            - Policy Mapping: {state.incident_details.policy_mapping}

            TASK:
            Provide a list of recommended actions to address the incident, ensuring alignment with the relevant SOC policies.
            use the "web_search" tool gather the recommended action mentioned in MITRE ATT&CK framework for similar incidents.

            Return the recommendations as a numbered list with each action on a new line.
            """

    recommendations = await invoke_llm(prompt)
    
    # Parse the LLM response into a list of action strings
    if isinstance(recommendations, str): 
        action_lines = [
            line.strip().lstrip('0123456789.-).] ').strip()
            for line in recommendations.split('\n')
            if line.strip() and not line.strip().startswith(('Based', 'Here', 'The', 'I recommend'))
        ]
        state.incident_details.recommended_actions = [a for a in action_lines if a]
    else:
        state.incident_details.recommended_actions = [recommendations] if recommendations else []
    
    return state



async def generate_report(state):
    """Generate a detailed incident report using LLM."""
    state.current_step = "generate_report"

    incident = state.incident_details

    system_prompt =( "You are an expert Incident Response and Reporting Assistant.\n\n"
    "Your task is to generate a clear, structured, objective, and professional incident report based on the information provided by the user."
    "The report must be suitable for both executive leadership and technical teams, following industry best practices in incident documentation."
    "Components of the Report Executive Summary: Brief overview of the incident, impact, and resolution for management. Incident Details: Date/Time: When it started, when detected, when resolved. Type/Severity: Categorization (e.g., data breach, malware) and impact level."
    "Affected Systems/Data: What was compromised or impacted. Reporter: Who found/reported it. Incident Timeline (Technical): Step-by-step sequence: compromise, lateral movement, data access, containment, eradication, recovery."
    " Detection & Analysis: How it was detected (human/tool), evidence (logs, screenshots), Indicators of Compromise (IoCs), and root cause analysis. Response Actions: Steps taken (containment, eradication, recovery), notifications made, and effectiveness. Impact Assessment: Details on actual or potential damages, injuries, or business disruption. Lessons Learned & Recommendations: Specific, actionable steps to improve future response and prevention (e.g., control gaps, process improvements). Appendices: Raw logs, screenshots, witness statements, network diagrams, etc.. Best Practices for Writing Be Objective: Stick to facts, avoid blame, use neutral language. Be Prompt & Detailed: Document immediately while fresh; capture all details. "
    "Use Clear Structure: Headings, lists, whitespace for readability. Tailor to Audience: Use jargon appropriately; provide high-level summaries for execs, deep dives for technical teams. "
    "Visuals: Timelines and attack maps (MITRE ATT&CK) enhance understanding. Example Incident Types Covered Cyberattacks (malware, phishing, DDoS) Workplace Accidents/Injuries Data Breaches System Outages/Failures"
    "details of incindent: "
    f"incident type: {incident.incident_type}\n"
    f"ip findings: {incident.ip_findings}\n"
    f"time of incident: {incident.time_of_incident}\n"
    f"summary: {incident.summary}\n"
    f"recommended actions: {incident.recommended_actions}\n"
    f"policy mapping: {incident.policy_mapping}\n"
    "Return the report as .md format with appropriate headings and subheadings.")


    report = await invoke_llm(system_prompt)

    with open(REPORT_FILE, 'w') as file:
        file.write(report)

    # attach report to state
    incident.report_text = report
    
    return state


async def draft_email(state):
    """Draft an email to notify stakeholders about the incident."""
    state.current_step = "draft_email"

    prompt = f"""
            You are a professional incident response coordinator.

            Based on the following incident report, draft a concise and clear email to notify stakeholders about the incident.

            Incident Details:
            - Type: {state.incident_details.incident_type}
            - Ip Findings: {state.incident_details.ip_findings}
            - Time: {state.incident_details.time_of_incident}
            - Summary: {state.incident_details.summary}
            - Recommended Actions: {state.incident_details.recommended_actions}
            - Mapped Policies: {state.incident_details.policy_mapping}
            

            TASK:
            1. Summarize the key points of the incident.
            2. Clearly state the impact and recommended actions.
            3. Use a professional and empathetic tone.
            4. Include a call to action for stakeholders to review the report.

            Return the email draft including subject line and body.
            """

    email_draft = await invoke_llm(prompt)
    
    return email_draft



   
def record_incident(state):
    """Record the incident details into the incident records file."""
    state.current_step = "record_incident"
    
    incident = state.incident_details

    # load existing incidents
    raw = INCIDENT_RECORD_FILE.read_text().strip()
    if not raw:
        incidents = []
    else:
        incidents = json.loads(raw)


    # create new incident record
    incident_id = len(incidents) + 1
    incident_record = {
        "id": incident_id,
        "type": incident.incident_type,
        "ip_findings": {
            ip: {
                "severity_level": finding.severity_level,   
                "severity_score": finding.severity_score,
                "confidence_score": finding.confidence_score,
                "evidence_list": finding.evidence_list
            } 
            for ip, finding in incident.ip_findings.items()
        },
        "time_of_incident": incident.time_of_incident,
        "summary": incident.summary,
        "recommended_actions": incident.recommended_actions,
        "report_text": incident.report_text
    
    }

    incidents.append(incident_record)

    # write incident back to file
    INCIDENT_RECORD_FILE.write_text(json.dumps(serialize_for_json(incidents), indent=2))

    return state



async def notify_stakeholders(state):
    """Notify stakeholders about the incident via email."""
    state.current_step = "notify_stakeholders"

    email_content = await draft_email(state)

    #-- parse email content --
    try:
        subject_line = email_content.split("Subject:")[1].split("\n")[0].strip()
        body = email_content.split("Body:")[1].strip()
    except IndexError:
        subject_line = "Incident Report Notification"
        body = email_content

    #-- send email using aiosmtplib --
    SMTP_SERVER = os.getenv("SMTP_SERVER", "smtp.gmail.com")
    SMTP_PORT = int(os.getenv("SMTP_PORT", 587))
    SENDER_EMAIL = os.getenv("SMTP_USER")
    SENDER_PASSWORD = os.getenv("SMTP_PASS")
    SECURITY_TEAM_EMAIL = os.getenv("SECURITY_TEAM_EMAIL")

    msg = EmailMessage()
    msg["From"] = SENDER_EMAIL
    msg["To"] = SECURITY_TEAM_EMAIL
    msg["Subject"] = subject_line
    msg.set_content(body)

    # Attach full incident report
    msg.add_attachment(
        state.incident_details.report_text.encode("utf-8"),
        maintype="text",
        subtype="markdown",
        filename="incident_report.md"
    )

    # Async email sending
    await send (
        msg,
        hostname = SMTP_SERVER,
        port = SMTP_PORT,
        start_tls= True,
        username = SENDER_EMAIL,
        password = SENDER_PASSWORD
    )

    state.current_step = "notification sent to stakeholders"   
    state.done = True
    
    return state



def no_log_end(state):
    """Check if all logs have been read and mark done."""
    state.current_step = "no more logs to read"
    state.done = True
    return state


def is_detected(state):
    """Check for any scanner ip in the current window."""
    return len(state.scanner_ips) > 0

def should_continue(state):
    """Check if there are more logs to read."""
    return not state.logs_read








#------Exports-----
__all__ = [
    "get_logs",
    "parse_logs",
    "collect_features",
    "classify_ip",
    "collect_scanner_ip",
    "collect_evidence",
    "is_detected",
    "set_severity",
    "map_policy",
    "summarize_incident",
    "recommend_actions",
    "generate_report",
    "record_incident",
    "notify_stakeholders",
    "no_log_end",
    "should_continue"
]