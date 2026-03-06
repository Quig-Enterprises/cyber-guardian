"""Database audit event collector — reads from audit_events table."""
from datetime import datetime, timezone
from blueteam.collectors.base import BaseCollector
from blueteam.models import SecurityEvent
from shared import get_connection

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
