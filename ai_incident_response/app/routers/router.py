from fastapi import APIRouter, BackgroundTasks, HTTPException, Query
from src.agent.graph import run_graph
from typing import Literal
import json
from pathlib import Path
from datetime import datetime
from ..models.model import settings




app_router = APIRouter()

#incident_file to read from 
INCIDENT_FILE = Path(__file__).parent.parent.parent / "static" / "incident_records" / "incidents.json"




#---Endpoint to trigger the execution of the agent---

@app_router.post("/run")
async def run_agent(background_tasks: BackgroundTasks):
    """Endpoint to trigger the execution of the AI Incident Response Agent. This will run the agent's graph in the background."""
    background_tasks.add_task(run_graph)
    return {"message": "Agent execution started"}



#--- Endpoints to get the stats of incidents---

@app_router.get("/stats")
def get_stats():
    """Endpoint to retrieve statistics about the incidents handled by the agent."""
    if not INCIDENT_FILE.exists():
        raise HTTPException(status_code=404, detail="Incident records not found")
    
    incidents = json.loads(INCIDENT_FILE.read_text())
    total_incidents = len(incidents)
    severity_counts = {"low": 0, "medium": 0, "high": 0, "critical":0}
    type_counts = {}

    for incident in incidents:
        ip_findings = incident.get("ip_findings", {})

        for ip in ip_findings:
            severity = ip_findings[ip].get("severity_level", "").lower()
            if severity in severity_counts:
                severity_counts[severity] += 1 
            else: 
                severity_counts[severity] = 1
        
        inc_type = incident.get("type")
        if inc_type:
            type_counts[inc_type] = type_counts.get(inc_type, 0) + 1

    return {
        "total_incidents": total_incidents,
        "severity_counts": severity_counts,
        "type_counts": type_counts
    }




#---Endpoints to retrieve incident records and reports ---

@app_router.get("/incidents")

async def get_all_incidents(severity: Literal["low", "medium", "high"] = Query(None, description="Filter incidents by severity level"), type_of_incident = Query(None, description="Filter incidents by type"), from_date: str = Query(None, description="Filter incidents from a specific date (YYYY-MM-DD)"), to_date: str = Query(None, description="Filter incidents up to a specific date (YYYY-MM-DD)")):
    """Endpoint to retrieve the list of incidents."""

    if not INCIDENT_FILE.exists():
        raise HTTPException(status_code=404, detail="Incident records not found")
    
    incidents = json.loads(INCIDENT_FILE.read_text())

    # Apply filters
    if severity:
        incidents = [inc for inc in incidents 
                    if any(ip_data.get("severity_level", "").lower() == severity 
                          for ip_data in inc.get("ip_findings", {}).values())]
    
    if type_of_incident:
        incidents = [inc for inc in incidents 
                    if inc.get("type", "").lower() == type_of_incident.lower()]
    
    if from_date:
        from_dt = datetime.fromisoformat(from_date)
        incidents = [inc for inc in incidents 
                    if inc.get("time_of_incident") and 
                       datetime.fromisoformat(inc["time_of_incident"]) >= from_dt]
    
    if to_date:
        to_dt = datetime.fromisoformat(to_date)
        incidents = [inc for inc in incidents 
                    if inc.get("time_of_incident") and 
                       datetime.fromisoformat(inc["time_of_incident"]) <= to_dt]
    
    return {"incidents": incidents}



@app_router.get("/incidents/{incident_id}")
def get_incident(incident_id: int):
    """Endpoint to retrieve details of specific incident by ID."""
    if not INCIDENT_FILE.exists():
        raise HTTPException(status_code=404, detail="Incident records not found")
    
    incidents = json.loads(INCIDENT_FILE.read_text())
    for incident in incidents:
        if incident.get("id") == incident_id:
            return {"incident": incident}

    raise HTTPException(status_code=404, detail="Incident not found")
    

@app_router.get("/incidents/{incident_id}/report")
def get_incident_report(incident_id: int):
    """Endpoint to retrieve the incident report for a specific incident by ID."""

    if not INCIDENT_FILE.exists():
        raise HTTPException(status_code=404, detail="Incident records not found")
    
    incidents = json.loads(INCIDENT_FILE.read_text())
    for incident in incidents:
        if incident.get("id") == incident_id:
            report = incident.get("report_text")
            if report:
                return {"report": report}
            else:
                raise HTTPException(status_code=404, detail="Report not found for this incident")
    
    raise HTTPException(status_code=404, detail="Incident not found")
    

#---Endpoints to get and update the configs ---


@app_router.get("/config")
def get_config():
    """Endpoint to retrieve the current configuration settings of the agent."""

    config_data = {
        "time_window": settings.time_window,
        "port_threshold": settings.port_threshold,
        "security_team_email": settings.security_team_email,
        "sender_email": settings.sender_email
    }
    return {"config": config_data}


#--- health check endpoint --- 
@app_router.get("/health")
def health_check():
    """Endpoint to check the health status of the API.""" 
    return {"status": "healthy"}