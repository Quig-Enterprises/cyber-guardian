# BT-08: Alert Engine

**Goal:** Implement multi-channel alerting with severity-based routing, audit failure detection, and alert persistence.

**Files:**
- Create: `/opt/security-blue-team/blueteam/alerting/engine.py`
- Create: `/opt/security-blue-team/blueteam/alerting/channels.py`
- Create: `/opt/security-blue-team/tests/test_alerting.py`

**Depends on:** BT-07

---

## Step 1: Write tests

```python
# tests/test_alerting.py
from blueteam.alerting.engine import AlertEngine
from blueteam.models import SecurityIncident

def test_alert_engine_routes_by_severity():
    engine = AlertEngine(config={"alerting": {"syslog": {"enabled": True}}})
    incident = SecurityIncident(
        title="Test incident",
        severity="critical",
        detected_by="test",
        nist_controls=["3.3.4"],
    )
    # Should not raise
    engine.alert(incident)

def test_alert_persisted_to_db():
    # Requires DB — integration test
    pass
```

---

## Step 2: Implement alert channels

```python
# blueteam/alerting/channels.py
"""Alert delivery channels."""
import syslog
import smtplib
from email.mime.text import MIMEText
from abc import ABC, abstractmethod
from blueteam.models import SecurityIncident

class AlertChannel(ABC):
    @abstractmethod
    def send(self, incident: SecurityIncident) -> bool: ...

class SyslogChannel(AlertChannel):
    SEVERITY_MAP = {
        "critical": syslog.LOG_CRIT,
        "high": syslog.LOG_ERR,
        "medium": syslog.LOG_WARNING,
        "low": syslog.LOG_NOTICE,
        "info": syslog.LOG_INFO,
    }

    def send(self, incident: SecurityIncident) -> bool:
        priority = self.SEVERITY_MAP.get(incident.severity, syslog.LOG_WARNING)
        syslog.openlog("eqmon-blueteam", syslog.LOG_PID, syslog.LOG_LOCAL6)
        syslog.syslog(priority,
            f"SECURITY_INCIDENT [{incident.severity.upper()}] "
            f"{incident.title} | detected_by={incident.detected_by} "
            f"nist={','.join(incident.nist_controls)} "
            f"cui={incident.cui_involved}")
        syslog.closelog()
        return True

class EmailChannel(AlertChannel):
    def __init__(self, config: dict):
        self.smtp_host = config.get("smtp_host", "localhost")
        self.smtp_port = config.get("smtp_port", 587)
        self.from_addr = config.get("from_address", "blueteam@eqmon.local")
        self.recipients = config.get("recipients", [])

    def send(self, incident: SecurityIncident) -> bool:
        if not self.recipients:
            return False
        subject = f"[{incident.severity.upper()}] {incident.title}"
        body = (
            f"Security Incident Detected\n"
            f"{'=' * 40}\n"
            f"Title: {incident.title}\n"
            f"Severity: {incident.severity}\n"
            f"Detected by: {incident.detected_by}\n"
            f"NIST Controls: {', '.join(incident.nist_controls)}\n"
            f"CUI Involved: {incident.cui_involved}\n\n"
            f"Description:\n{incident.description}\n"
        )
        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = self.from_addr
        msg["To"] = ", ".join(self.recipients)
        try:
            with smtplib.SMTP(self.smtp_host, self.smtp_port) as smtp:
                smtp.send_message(msg)
            return True
        except Exception:
            return False

class ConsoleChannel(AlertChannel):
    def send(self, incident: SecurityIncident) -> bool:
        from rich.console import Console
        from rich.panel import Panel
        console = Console(stderr=True)
        style = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "blue"}.get(incident.severity, "white")
        console.print(Panel(
            f"[bold]{incident.title}[/bold]\n"
            f"Severity: {incident.severity} | Rule: {incident.detected_by}\n"
            f"NIST: {', '.join(incident.nist_controls)}\n"
            f"{incident.description}",
            title=f"SECURITY ALERT",
            style=style,
        ))
        return True
```

---

## Step 3: Implement alert engine with severity routing

```python
# blueteam/alerting/engine.py
"""Alert routing engine with severity-based channel selection."""
from blueteam.models import SecurityIncident
from blueteam.alerting.channels import SyslogChannel, EmailChannel, ConsoleChannel
from blueteam import db as db_module

# Severity → channels
ROUTING = {
    "critical": ["email", "syslog", "console"],
    "high":     ["email", "syslog"],
    "medium":   ["syslog"],
    "low":      ["syslog"],
    "info":     [],
}

class AlertEngine:
    def __init__(self, config: dict):
        self.config = config
        self.channels = {}
        alert_cfg = config.get("alerting", {})
        if alert_cfg.get("syslog", {}).get("enabled"):
            self.channels["syslog"] = SyslogChannel()
        if alert_cfg.get("email", {}).get("enabled"):
            self.channels["email"] = EmailChannel(alert_cfg["email"])
        self.channels["console"] = ConsoleChannel()

    def alert(self, incident: SecurityIncident):
        """Route alert to appropriate channels based on severity."""
        channels = ROUTING.get(incident.severity, [])
        for ch_name in channels:
            if ch_name in self.channels:
                try:
                    self.channels[ch_name].send(incident)
                except Exception as e:
                    import sys
                    print(f"Alert channel {ch_name} failed: {e}", file=sys.stderr)
        self._persist(incident)

    def _persist(self, incident: SecurityIncident):
        """Save alert to blueteam.alert_history."""
        try:
            conn = db_module.get_connection(self.config)
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO blueteam.alert_history
                        (rule_id, severity, title, description)
                    VALUES (%s, %s, %s, %s)
                """, (incident.detected_by, incident.severity,
                      incident.title, incident.description))
        except Exception:
            pass  # Don't crash monitoring over DB write failure
```

---

## Step 4: Run tests, commit

```bash
python -m pytest tests/test_alerting.py -v
git add -A
git commit -m "feat: alert engine with syslog, email, console channels (NIST 3.3.4)"
```
