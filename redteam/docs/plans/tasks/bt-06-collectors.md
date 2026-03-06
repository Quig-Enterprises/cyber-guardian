# BT-06: Event Collectors

**Goal:** Implement the collector subsystem that reads security events from multiple sources and normalizes them into `SecurityEvent` objects.

**Files:**
- Create: `/opt/security-blue-team/blueteam/collectors/base.py`
- Create: `/opt/security-blue-team/blueteam/collectors/db_audit.py`
- Create: `/opt/security-blue-team/blueteam/collectors/syslog_parser.py`
- Create: `/opt/security-blue-team/blueteam/collectors/nginx_log.py`
- Create: `/opt/security-blue-team/blueteam/collectors/php_error.py`
- Create: `/opt/security-blue-team/blueteam/collectors/redteam_report.py`
- Create: `/opt/security-blue-team/tests/test_collectors.py`

**Depends on:** BT-05

---

## Step 1: Write tests for collector base and DB collector

```python
# tests/test_collectors.py
import pytest
from datetime import datetime
from blueteam.models import SecurityEvent
from blueteam.collectors.base import BaseCollector

def test_security_event_creation():
    event = SecurityEvent(
        timestamp=datetime.utcnow(),
        source="test",
        category="auth",
        severity="high",
        action="login_failed",
        user_id="abc-123",
        ip_address="192.168.1.1",
        details={"reason": "invalid_password"},
        nist_controls=["3.3.1", "3.5.2"],
    )
    assert event.source == "test"
    assert event.severity == "high"
    assert not event.cui_involved

def test_base_collector_is_abstract():
    with pytest.raises(TypeError):
        BaseCollector({})
```

Run: `cd /opt/security-blue-team && python -m pytest tests/test_collectors.py -v`
Expected: FAIL (classes don't exist yet)

---

## Step 2: Implement base collector

```python
# blueteam/collectors/base.py
"""Base collector interface."""
from abc import ABC, abstractmethod
from blueteam.models import SecurityEvent

class BaseCollector(ABC):
    """Abstract base for all event collectors."""

    def __init__(self, config: dict):
        self.config = config
        self._last_position = None

    @property
    @abstractmethod
    def name(self) -> str:
        """Collector identifier."""
        ...

    @abstractmethod
    def collect(self) -> list[SecurityEvent]:
        """Collect new events since last poll. Returns list of SecurityEvent."""
        ...

    def is_enabled(self) -> bool:
        """Check if this collector is enabled in config."""
        collectors = self.config.get("collectors", {})
        return collectors.get(self.name, {}).get("enabled", False)
```

---

## Step 3: Implement DB audit collector

This is the primary collector — reads from the `audit_events` table written by PHP AuditLogger.

```python
# blueteam/collectors/db_audit.py
"""Database audit event collector — reads from audit_events table."""
from datetime import datetime, timezone
from blueteam.collectors.base import BaseCollector
from blueteam.models import SecurityEvent
from blueteam.db import get_connection

# Map audit categories to severity defaults
SEVERITY_MAP = {
    ("auth", "login", "failure"): "medium",
    ("auth", "login", "denied"): "high",
    ("auth", "login", "success"): "info",
    ("auth", "password_reset", "success"): "medium",
    ("auth", "impersonation_start", "success"): "high",
    ("access", "api_request", "denied"): "medium",
    ("admin", "user_delete", "success"): "high",
    ("admin", "role_change", "success"): "high",
    ("admin", "settings_change", "success"): "high",
    ("ai", "guardrail_triggered", "denied"): "high",
    ("system", "rate_limit_hit", "denied"): "medium",
    ("system", "error_500", "failure"): "medium",
}

# Map categories to NIST controls
NIST_MAP = {
    "auth": ["3.3.1", "3.5.2"],
    "access": ["3.3.1", "3.3.2", "3.1.1"],
    "admin": ["3.3.1", "3.3.2", "3.1.7"],
    "data": ["3.3.1", "3.1.3"],
    "ai": ["3.3.1", "3.14.6"],
    "system": ["3.3.1", "3.14.1"],
}

class DBAuditCollector(BaseCollector):
    name = "db_audit"

    def __init__(self, config: dict):
        super().__init__(config)
        self._last_event_id = None
        self._last_timestamp = datetime.now(timezone.utc)

    def collect(self) -> list[SecurityEvent]:
        conn = get_connection(self.config)
        with conn.cursor() as cur:
            cur.execute("""
                SELECT event_id, timestamp, category, action, result,
                       user_id, session_id, ip_address, user_agent,
                       resource_type, resource_id, instance_id,
                       cui_accessed, metadata
                FROM audit_events
                WHERE timestamp > %s
                ORDER BY timestamp ASC
                LIMIT 1000
            """, (self._last_timestamp,))
            rows = cur.fetchall()

        events = []
        for row in rows:
            severity = SEVERITY_MAP.get(
                (row["category"], row["action"], row["result"]),
                "info" if row["result"] == "success" else "medium"
            )
            nist = NIST_MAP.get(row["category"], ["3.3.1"])

            event = SecurityEvent(
                timestamp=row["timestamp"],
                source="audit_db",
                category=row["category"],
                severity=severity,
                action=row["action"],
                user_id=str(row["user_id"]) if row["user_id"] else None,
                ip_address=str(row["ip_address"]) if row["ip_address"] else None,
                details={
                    "result": row["result"],
                    "session_id": row["session_id"],
                    "user_agent": row["user_agent"],
                    "resource_type": row["resource_type"],
                    "resource_id": row["resource_id"],
                    "instance_id": str(row["instance_id"]) if row["instance_id"] else None,
                    **(row["metadata"] or {}),
                },
                nist_controls=nist,
                cui_involved=row["cui_accessed"] or False,
                event_id=str(row["event_id"]),
            )
            events.append(event)
            self._last_timestamp = row["timestamp"]

        return events
```

---

## Step 4: Implement syslog parser

```python
# blueteam/collectors/syslog_parser.py
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
                    details={"raw": line[:500], "groups": match.groups()},
                    nist_controls=nist,
                )
        return None
```

---

## Step 5: Implement nginx log and PHP error collectors (similar pattern)

**nginx_log.py** — parse access log for 4xx/5xx responses, unusual request patterns.
**php_error.py** — parse structured JSON error logs from error-handler.php.

Both follow the same BaseCollector pattern with file position tracking and regex parsing.

---

## Step 6: Implement red team report collector

```python
# blueteam/collectors/redteam_report.py
"""Red team report collector — imports attack results for posture scoring."""
import json
from datetime import datetime, timezone
from pathlib import Path
from blueteam.collectors.base import BaseCollector
from blueteam.models import SecurityEvent

class RedTeamCollector(BaseCollector):
    name = "redteam"

    def __init__(self, config: dict):
        super().__init__(config)
        reports_dir = config.get("collectors", {}).get("redteam", {}).get(
            "reports_dir", "/opt/security-red-team/reports"
        )
        self._reports_dir = Path(reports_dir)
        self._imported_files = set()

    def collect(self) -> list[SecurityEvent]:
        if not self._reports_dir.exists():
            return []

        events = []
        for report_file in sorted(self._reports_dir.glob("*.json")):
            if report_file.name in self._imported_files:
                continue
            self._imported_files.add(report_file.name)

            try:
                with open(report_file) as f:
                    report = json.load(f)

                for attack in report.get("attacks", []):
                    for variant in attack.get("variants", []):
                        if variant.get("result") in ("vulnerable", "partial"):
                            events.append(SecurityEvent(
                                timestamp=datetime.now(timezone.utc),
                                source="redteam",
                                category="system",
                                severity=variant.get("severity", "medium").lower(),
                                action=f"redteam_{variant.get('result', 'unknown')}",
                                details={
                                    "attack": attack.get("name"),
                                    "variant": variant.get("name"),
                                    "category": attack.get("category"),
                                    "confidence": variant.get("confidence"),
                                    "report_file": report_file.name,
                                },
                                nist_controls=variant.get("nist_controls", []),
                            ))
            except (json.JSONDecodeError, KeyError):
                pass

        return events
```

---

## Step 7: Update collectors/__init__.py with registry

```python
# blueteam/collectors/__init__.py
"""Collector registry."""
from blueteam.collectors.db_audit import DBAuditCollector
from blueteam.collectors.syslog_parser import SyslogCollector
from blueteam.collectors.nginx_log import NginxLogCollector
from blueteam.collectors.php_error import PHPErrorCollector
from blueteam.collectors.redteam_report import RedTeamCollector

ALL_COLLECTORS = [
    DBAuditCollector,
    SyslogCollector,
    NginxLogCollector,
    PHPErrorCollector,
    RedTeamCollector,
]

def get_enabled_collectors(config: dict):
    """Return instances of all enabled collectors."""
    collectors = []
    for cls in ALL_COLLECTORS:
        instance = cls(config)
        if instance.is_enabled():
            collectors.append(instance)
    return collectors
```

---

## Step 8: Run tests, commit

```bash
cd /opt/security-blue-team
python -m pytest tests/ -v
git add -A
git commit -m "feat: event collectors for audit DB, syslog, nginx, PHP errors, red team"
```
