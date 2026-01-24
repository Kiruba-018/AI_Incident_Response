"""This module contains the state definitions for the AI incident response agent."""
from typing import Dict, List, Literal

from pydantic import BaseModel, ConfigDict, Field


class Incident_Details(BaseModel):
    """Incident details data model."""
    model_config = ConfigDict(extra='allow')
    
    incident_type: str = ""
    severity_score: int = Field(default=0, ge=0, le=100)
    severity_level: Literal["Low", "Medium", "High", "Critical"] = "Low"
    time_of_incident: str = ""
    evidence: List[Dict] = Field(default_factory=list)
    summary: str = ""
    recommended_actions: List[str] = Field(default_factory=list)
    report_text: str = ""
    policy_mapping: str = ""


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
