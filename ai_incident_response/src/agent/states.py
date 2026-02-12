"""This module contains the state definitions for the AI incident response agent."""
from typing import Dict, List, Literal

from pydantic import BaseModel, ConfigDict, Field



class Ip_Findings(BaseModel):
    """Data model for findings related to a specific IP address."""
    model_config = ConfigDict(extra='allow')

    severity_score: int = Field(default=0, ge=0, le=100)
    severity_level: Literal["Low", "Medium", "High", "Critical"] = "Low"
    confidence_score: float = Field(default=0.0, ge=0.0, le=1.0)
    evidence_list: List[Dict] = Field(default_factory=list)



class Incident_Details(BaseModel):
    """Incident details data model."""
    model_config = ConfigDict(extra='allow')
    
    incident_type: str = ""
    time_of_incident: str = ""

    ip_findings : Dict[str, Ip_Findings] = Field(default_factory=dict)

    summary: str = ""
    recommended_actions: List[str] = Field(default_factory=list)
    policy_mapping: Dict[str,Dict] = Field(default_factory=dict)
    report_text: str = ""
    

class State(BaseModel):
    """State data model for the AI incident response agent."""
    model_config = ConfigDict(extra='allow')
    
    current_logs: dict | None = None
    current_step: str = ""
    incident_details: Incident_Details | None = None
    ip_window_stats: Dict[str, Dict] = Field(default_factory=dict)
    suspicious_ip: Dict[str, Dict] = Field(default_factory=dict)
    scanner_ips: List[str] = Field(default_factory=list)
    logs_read: bool = False
    done: bool = False
