"""DFARS 252.204-7012 reporting workflow — 72-hour CUI breach notification."""
from blueteam.db import get_connection


def is_dfars_reportable(cui_involved: bool, severity: str) -> bool:
    """Determine if an incident requires DFARS 72-hour reporting."""
    return cui_involved and severity in ("critical", "high")


def get_overdue_reports(config: dict) -> list:
    """Find DFARS-reportable incidents past 72-hour deadline."""
    conn = get_connection(config)
    with conn.cursor() as cur:
        cur.execute("""
            SELECT incident_id, title, severity, detected_at,
                   NOW() - detected_at as time_elapsed
            FROM blueteam.security_incidents
            WHERE dfars_reportable = TRUE
              AND dfars_reported_at IS NULL
              AND detected_at < NOW() - INTERVAL '72 hours'
              AND status != 'closed'
        """)
        return cur.fetchall()


def mark_reported(config: dict, incident_id: str):
    """Mark incident as reported to DC3."""
    conn = get_connection(config)
    with conn.cursor() as cur:
        cur.execute("""
            UPDATE blueteam.security_incidents
            SET dfars_reported_at = NOW(), updated_at = NOW()
            WHERE incident_id = %s
        """, (incident_id,))


def get_reporting_status(config: dict) -> dict:
    """Get summary of DFARS reporting obligations."""
    conn = get_connection(config)
    with conn.cursor() as cur:
        cur.execute("""
            SELECT
                COUNT(*) FILTER (WHERE dfars_reportable AND dfars_reported_at IS NULL
                    AND status != 'closed') as pending,
                COUNT(*) FILTER (WHERE dfars_reportable AND dfars_reported_at IS NOT NULL) as reported,
                COUNT(*) FILTER (WHERE dfars_reportable AND dfars_reported_at IS NULL
                    AND detected_at < NOW() - INTERVAL '72 hours'
                    AND status != 'closed') as overdue
            FROM blueteam.security_incidents
        """)
        return cur.fetchone()
