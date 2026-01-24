# Incident Report
### Slow Port Scan Incident
#### Date/Time: 2026-01-24T12:40:31.734591
#### Type/Severity: Low Severity, Severity Score: 20
#### Affected Systems/Data: Network Service Scanning

## Executive Summary
A slow port scan was detected on 2026-01-24 at 12:40:31 originating from IP address 45.33.32.156. The scan targeted multiple ports, including port 21, 22, 23, 25, and 80, and was blocked by the firewall. This incident is classified as a low-severity event with a severity score of 20.

## Incident Details
### Date/Time
* Incident Start: 2026-01-24T12:40:31.734591
* Incident Detection: 2026-01-24T12:40:31.734591
* Incident Resolution: 2026-01-24T12:40:31.734591

### Type/Severity
* Incident Type: Slow Port Scan
* Severity Level: Low
* Severity Score: 20

### Affected Systems/Data
* Network Service Scanning

### Reporter
* Incident reported by: [Your Name]

## Incident Timeline (Technical)
### Compromise
* A slow port scan was detected originating from IP address 45.33.32.156.

### Lateral Movement
* The scan targeted multiple ports, including port 21, 22, 23, 25, and 80.

### Data Access
* The scan was blocked by the firewall.

### Containment
* The IP address 45.33.32.156 was blocked from accessing the network.

### Eradication
* The firewall rules were updated to block the IP address 45.33.32.156 and any other IP addresses that may be involved in the scanning activity.

### Recovery
* A network scan was conducted to identify any potential vulnerabilities that may have been exploited by the scanning activity.

## Detection & Analysis
### Detection Method
* The incident was detected by the firewall.

### Evidence
* Evidence logs:
```markdown
2026-01-05T10:00:10 FIREWALL src_ip=45.33.32.156 dest_port=21 protocol=TCP tcp_flags=SYN action=BLOCKED;
2026-01-05T10:00:35 FIREWALL src_ip=45.33.32.156 dest_port=22 protocol=TCP tcp_flags=FIN action=BLOCKED;
2026-01-05T10:01:00 FIREWALL src_ip=45.33.32.156 dest_port=23 protocol=TCP tcp_flags=SYN action=BLOCKED;
2026-01-05T10:01:25 FIREWALL src_ip=45.33.32.156 dest_port=25 protocol=TCP tcp_flags=FIN action=BLOCKED;
2026-01-05T10:01:50 FIREWALL src_ip=45.33.32.156 dest_port=80 protocol=TCP tcp_flags=SYN action=BLOCKED;
```

### Indicators of Compromise (IoCs)
* IP address 45.33.32.156

### Root Cause Analysis
* The root cause of the incident is unknown.

## Response Actions
### Containment
* The IP address 45.33.32.156 was blocked from accessing the network.

### Eradication
* The firewall rules were updated to block the IP address 45.33.32.156 and any other IP addresses that may be involved in the scanning activity.

### Recovery
* A network scan was conducted to identify any potential vulnerabilities that may have been exploited by the scanning activity.

### Notifications
* Relevant teams, such as the security operations team and the incident response team, were notified.

### Documentation
* The incident was documented in the incident response plan and updated in the security information and event management (SIEM) system.

## Impact Assessment
### Actual or Potential Damages
* The incident did not result in any actual or potential damages.

### Business Disruption
* The incident did not result in any business disruption.

## Lessons Learned & Recommendations
### Specific, Actionable Steps
* Verify the incident details to ensure that the slow port scan was indeed detected and that the evidence collected is accurate.
* Block the IP address 45.33.32.156 from accessing the network to prevent further scanning activity.
* Update the firewall rules to block the IP address 45.33.32.156 and any other IP addresses that may be involved in the scanning activity.
* Conduct a network scan to identify any potential vulnerabilities that may have been exploited by the scanning activity.
* Review system logs to identify any potential security incidents that may have occurred as a result of the scanning activity.
* Notify relevant teams, such as the security operations team and the incident response team, to ensure that they are aware of the incident and can take necessary actions.
* Document the incident in the incident response plan and update the security information and event management (SIEM) system to reflect the incident.
* Perform a risk assessment to determine the potential impact of the scanning activity and to identify any potential security risks.
* Implement additional security measures, such as intrusion detection and prevention systems (IDPS), to prevent similar incidents in the future.
* Review and update policies to ensure that they are aligned with the incident response plan and that they provide clear guidance on how to respond to similar incidents in the future.

### Additional Recommendations
* Implement a network segmentation strategy to limit the spread of malware and to prevent lateral movement.
* Use a host-based intrusion detection system (HIDS) to detect and prevent malicious activity on individual hosts.
* Implement a security information and event management (SIEM) system to collect and analyze security-related data from various sources.
* Conduct a vulnerability assessment to identify potential vulnerabilities that may have been exploited by the scanning activity.
* Implement an incident response plan to ensure that the organization is prepared to respond to similar incidents in the future.

## Appendices
### Raw Logs
* Evidence logs:
```markdown
2026-01-05T10:00:10 FIREWALL src_ip=45.33.32.156 dest_port=21 protocol=TCP tcp_flags=SYN action=BLOCKED;
2026-01-05T10:00:35 FIREWALL src_ip=45.33.32.156 dest_port=22 protocol=TCP tcp_flags=FIN action=BLOCKED;
2026-01-05T10:01:00 FIREWALL src_ip=45.33.32.156 dest_port=23 protocol=TCP tcp_flags=SYN action=BLOCKED;
2026-01-05T10:01:25 FIREWALL src_ip=45.33.32.156 dest_port=25 protocol=TCP tcp_flags=FIN action=BLOCKED;
2026-01-05T10:01:50 FIREWALL src_ip=45.33.32.156 dest_port=80 protocol=TCP tcp_flags=SYN action=BLOCKED;
```

### Screenshots
* None

### Witness Statements
* None

### Network Diagrams
* None