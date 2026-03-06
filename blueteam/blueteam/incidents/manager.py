"""Incident lifecycle management — PICERL workflow."""
import hashlib
from shared import get_connection
from blueteam.models import SecurityIncident


class IncidentManager:
    """Manages security incidents through PICERL lifecycle."""

    def __init__(self, config: dict):
        self.config = config

    def create(self, incident: SecurityIncident) -> str:
        """Create a new incident, return incident_id."""
        conn = get_connection(self.config)
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO blueteam.security_incidents
                    (title, description, severity, detected_by, correlation_rule,
                     nist_controls, cui_involved, dfars_reportable)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING incident_id
            """, (incident.title, incident.description, incident.severity,
                  incident.detected_by, incident.detected_by,
                  incident.nist_controls, incident.cui_involved,
                  incident.cui_involved and incident.severity in ("critical", "high")))
            row = cur.fetchone()
            return str(row["incident_id"])

    def update_status(self, incident_id: str, new_status: str, notes: str = ""):
        """Advance incident through PICERL lifecycle."""
        conn = get_connection(self.config)
        ts_column = {
            "contained": "contained_at",
            "eradicated": "eradicated_at",
            "recovered": "recovered_at",
            "closed": "closed_at",
        }.get(new_status)

        with conn.cursor() as cur:
            sets = ["status = %s", "updated_at = NOW()"]
            values = [new_status]
            if ts_column:
                sets.append(f"{ts_column} = NOW()")
            if notes and new_status == "closed":
                sets.append("lessons_learned = %s")
                values.append(notes)
            values.append(incident_id)
            cur.execute(
                f"UPDATE blueteam.security_incidents SET {', '.join(sets)} WHERE incident_id = %s",
                values
            )

    def list_active(self) -> list:
        """List all non-closed incidents."""
        conn = get_connection(self.config)
        with conn.cursor() as cur:
            cur.execute("""
                SELECT incident_id, title, severity, status, detected_at, assigned_to,
                       cui_involved, dfars_reportable, dfars_reported_at
                FROM blueteam.security_incidents
                WHERE status != 'closed'
                ORDER BY
                    CASE severity
                        WHEN 'critical' THEN 1
                        WHEN 'high' THEN 2
                        WHEN 'medium' THEN 3
                        WHEN 'low' THEN 4
                    END,
                    detected_at DESC
            """)
            return cur.fetchall()

    def get(self, incident_id: str) -> dict:
        """Get full incident details."""
        conn = get_connection(self.config)
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM blueteam.security_incidents WHERE incident_id = %s",
                        (incident_id,))
            return cur.fetchone()

    def add_evidence(self, incident_id: str, evidence_type: str,
                     description: str, content: str, collected_by: str) -> str:
        """Add evidence with SHA-256 integrity hash."""
        content_hash = hashlib.sha256(content.encode()).hexdigest()
        conn = get_connection(self.config)
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO blueteam.incident_evidence
                    (incident_id, evidence_type, description, content,
                     collected_by, hash_sha256)
                VALUES (%s, %s, %s, %s, %s, %s)
                RETURNING evidence_id
            """, (incident_id, evidence_type, description, content,
                  collected_by, content_hash))
            row = cur.fetchone()
            return str(row["evidence_id"])
