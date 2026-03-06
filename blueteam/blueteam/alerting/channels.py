"""Alert channels — deliver incident notifications."""
import json
import logging
import smtplib
import syslog
from abc import ABC, abstractmethod
from email.mime.text import MIMEText
from blueteam.models import SecurityIncident

logger = logging.getLogger(__name__)


class BaseChannel(ABC):
    """Base class for alert channels."""
    name: str = "base"

    @abstractmethod
    def send(self, incident: SecurityIncident) -> bool:
        ...


class SyslogChannel(BaseChannel):
    """Send alerts to syslog (NIST 3.3.1 compliance)."""
    name = "syslog"

    SEVERITY_MAP = {
        "critical": syslog.LOG_CRIT,
        "high": syslog.LOG_ERR,
        "medium": syslog.LOG_WARNING,
        "low": syslog.LOG_NOTICE,
        "info": syslog.LOG_INFO,
    }

    def __init__(self, config: dict):
        facility_name = config.get("alerting", {}).get("syslog", {}).get("facility", "local6")
        self._facility = getattr(syslog, f"LOG_{facility_name.upper()}", syslog.LOG_LOCAL6)
        syslog.openlog("eqmon-blueteam", syslog.LOG_PID, self._facility)

    def send(self, incident: SecurityIncident) -> bool:
        priority = self.SEVERITY_MAP.get(incident.severity, syslog.LOG_WARNING)
        cui_tag = " [CUI]" if incident.cui_involved else ""
        msg = (
            f"SECURITY_INCIDENT{cui_tag} severity={incident.severity} "
            f"rule={incident.detected_by} title=\"{incident.title}\" "
            f"nist={','.join(incident.nist_controls)}"
        )
        syslog.syslog(priority, msg)
        return True


class EmailChannel(BaseChannel):
    """Send alerts via email (for critical/high severity)."""
    name = "email"

    def __init__(self, config: dict):
        email_cfg = config.get("alerting", {}).get("email", {})
        self._smtp_host = email_cfg.get("smtp_host", "localhost")
        self._smtp_port = email_cfg.get("smtp_port", 587)
        self._from = email_cfg.get("from_address", "blueteam@eqmon.local")
        self._recipients = email_cfg.get("recipients", [])

    def send(self, incident: SecurityIncident) -> bool:
        if not self._recipients:
            return False

        cui_tag = "[CUI INCIDENT] " if incident.cui_involved else ""
        subject = f"{cui_tag}[{incident.severity.upper()}] {incident.title}"
        body = (
            f"Security Incident Detected\n"
            f"{'=' * 40}\n"
            f"Title: {incident.title}\n"
            f"Severity: {incident.severity}\n"
            f"Rule: {incident.detected_by}\n"
            f"NIST Controls: {', '.join(incident.nist_controls)}\n"
            f"CUI Involved: {incident.cui_involved}\n"
            f"\nDescription:\n{incident.description}\n"
        )

        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = self._from
        msg["To"] = ", ".join(self._recipients)

        try:
            with smtplib.SMTP(self._smtp_host, self._smtp_port, timeout=10) as smtp:
                smtp.sendmail(self._from, self._recipients, msg.as_string())
            return True
        except (smtplib.SMTPException, OSError) as e:
            logger.error("Email alert failed: %s", e)
            return False


class ConsoleChannel(BaseChannel):
    """Print alerts to console (for development/debugging)."""
    name = "console"

    def __init__(self, config: dict | None = None):
        pass

    def send(self, incident: SecurityIncident) -> bool:
        cui_tag = " [CUI]" if incident.cui_involved else ""
        print(
            f"[ALERT]{cui_tag} [{incident.severity.upper()}] "
            f"{incident.title} (rule={incident.detected_by})"
        )
        return True


ALL_CHANNELS: list[type[BaseChannel]] = [
    SyslogChannel,
    EmailChannel,
    ConsoleChannel,
]
