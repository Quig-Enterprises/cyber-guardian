"""Nginx access log collector — detects 4xx/5xx responses and unusual patterns."""
import re
from datetime import datetime, timezone
from pathlib import Path
from blueteam.collectors.base import BaseCollector
from blueteam.models import SecurityEvent

# Combined nginx log format regex
NGINX_PATTERN = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) \S+" (?P<status>\d+) (?P<bytes>\d+)'
)


class NginxLogCollector(BaseCollector):
    name = "nginx"

    def __init__(self, config: dict):
        super().__init__(config)
        self._file_pos = 0
        self._path = Path(config.get("collectors", {}).get("nginx", {}).get("path", "/var/log/nginx/access.log"))

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
        match = NGINX_PATTERN.match(line)
        if not match:
            return None

        status = int(match.group("status"))
        path = match.group("path")
        ip = match.group("ip")

        # Only capture security-relevant events
        if status < 400:
            return None

        if status == 401:
            severity, action = "medium", "unauthorized_request"
        elif status == 403:
            severity, action = "medium", "forbidden_request"
        elif status == 404 and any(p in path for p in [".env", ".git", "wp-", "admin", "phpmyadmin"]):
            severity, action = "high", "recon_probe"
        elif status >= 500:
            severity, action = "medium", "server_error"
        else:
            severity, action = "low", f"http_{status}"

        return SecurityEvent(
            timestamp=datetime.now(timezone.utc),
            source="nginx",
            category="access" if status < 500 else "system",
            severity=severity,
            action=action,
            ip_address=ip,
            details={
                "method": match.group("method"),
                "path": path,
                "status": status,
                "bytes": int(match.group("bytes")),
            },
            nist_controls=["3.3.1", "3.14.6"],
        )
