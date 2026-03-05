"""PHP error log collector — parses structured JSON error logs."""
import json
from datetime import datetime, timezone
from pathlib import Path
from blueteam.collectors.base import BaseCollector
from blueteam.models import SecurityEvent


class PHPErrorCollector(BaseCollector):
    name = "php_errors"

    def __init__(self, config: dict):
        super().__init__(config)
        self._file_positions = {}
        self._paths = [
            Path(p) for p in
            config.get("collectors", {}).get("php_errors", {}).get("paths", [])
        ]

    def collect(self) -> list[SecurityEvent]:
        events = []
        for path in self._paths:
            if not path.exists():
                continue
            pos = self._file_positions.get(str(path), 0)
            try:
                with open(path) as f:
                    f.seek(pos)
                    for line in f:
                        event = self._parse_line(line.strip())
                        if event:
                            events.append(event)
                    self._file_positions[str(path)] = f.tell()
            except PermissionError:
                pass
        return events

    def _parse_line(self, line: str):
        # Try JSON format first (from error-handler.php)
        try:
            data = json.loads(line)
            severity = "medium"
            if data.get("level") in ("FATAL", "ERROR"):
                severity = "high"
            return SecurityEvent(
                timestamp=datetime.now(timezone.utc),
                source="php_error",
                category="system",
                severity=severity,
                action="php_error",
                details={
                    "message": data.get("message", "")[:500],
                    "file": data.get("file"),
                    "level": data.get("level"),
                },
                nist_controls=["3.14.1"],
            )
        except (json.JSONDecodeError, KeyError):
            pass

        # Plain text PHP error
        if "Fatal error" in line or "CRITICAL" in line:
            return SecurityEvent(
                timestamp=datetime.now(timezone.utc),
                source="php_error",
                category="system",
                severity="high",
                action="php_fatal_error",
                details={"raw": line[:500]},
                nist_controls=["3.14.1"],
            )
        return None
