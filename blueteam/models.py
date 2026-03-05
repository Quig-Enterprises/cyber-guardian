"""Core data models."""
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


@dataclass
class SecurityEvent:
    """Normalized security event from any collector."""
    timestamp: datetime
    source: str          # 'audit_db', 'syslog', 'nginx', 'php_error', 'redteam'
    category: str        # auth, access, admin, data, ai, system, network
    severity: str        # critical, high, medium, low, info
    action: str
    user_id: Optional[str] = None
    ip_address: Optional[str] = None
    details: dict = field(default_factory=dict)
    nist_controls: list[str] = field(default_factory=list)
    cui_involved: bool = False
    event_id: Optional[str] = None


@dataclass
class SecurityIncident:
    """A correlated security incident."""
    title: str
    severity: str
    detected_by: str
    nist_controls: list[str]
    description: str = ""
    cui_involved: bool = False
    events: list[SecurityEvent] = field(default_factory=list)
    incident_id: Optional[str] = None


@dataclass
class ComplianceControl:
    """A NIST SP 800-171 control."""
    control_id: str
    family: str
    family_id: str
    requirement: str
    status: str = "not_assessed"
    implementation_notes: str = ""
    evidence_type: Optional[str] = None
