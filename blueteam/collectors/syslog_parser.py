"""Syslog collector — parses auth events from /var/log/syslog or auth.log."""
import re
from datetime import datetime, timezone
from pathlib import Path
from blueteam.collectors.base import BaseCollector
from blueteam.models import SecurityEvent

AUTH_PATTERNS = [
    (r"eqmon-auth.*Forgot password rate limited.*email=(\S+)\s+ip=(\S+)",
     "auth", "password_reset_rate_limited", "high", ["3.1.8", "3.3.1"]),
    (r"eqmon-auth.*Password reset email sent.*email=(\S+)\s+user_id=(\S+)",
     "auth", "password_reset_sent", "info", ["3.3.1", "3.5.9"]),
    (r"eqmon-auth.*Password reset email FAILED.*email=(\S+)",
     "system", "email_failure", "medium", ["3.3.4"]),
    (r"eqmon-auth.*Password reset by (\S+) for user (\S+)",
     "admin", "admin_password_reset", "high", ["3.3.1", "3.1.7"]),
    (r"EQMON.*User deleted.*email=(\S+).*by=(\S+)",
     "admin", "user_delete", "high", ["3.3.1", "3.1.7"]),
    (r"eqmon-audit.*AUDIT_FAILURE",
     "system", "audit_failure", "critical", ["3.3.4"]),
]


class SyslogCollector(BaseCollector):
    name = "syslog"

    def __init__(self, config: dict):
        super().__init__(config)
        self._file_pos = 0
        self._path = Path(config.get("collectors", {}).get("syslog", {}).get("path", "/var/log/syslog"))

    def collect(self) -> list[SecurityEvent]:
        if not self._path.exists():
            return []

        events = []
        try:
            with open(self._path) as f:
                f.seek(self._file_pos)
                for line in f:
                    event = self._parse_line(line.strip())
                    if event:
                        events.append(event)
                self._file_pos = f.tell()
        except PermissionError:
            pass
        return events

    def _parse_line(self, line: str):
        for pattern, category, action, severity, nist in AUTH_PATTERNS:
            match = re.search(pattern, line)
            if match:
                return SecurityEvent(
                    timestamp=datetime.now(timezone.utc),
                    source="syslog",
                    category=category,
                    severity=severity,
                    action=action,
                    details={"raw": line[:500], "groups": list(match.groups())},
                    nist_controls=nist,
                )
        return None
