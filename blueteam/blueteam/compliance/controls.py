"""Compliance control management — load, query, update."""
from shared import get_connection
from blueteam.compliance.nist_800_171 import CONTROLS


def load_controls(config: dict):
    """Load all 110 NIST SP 800-171r2 controls into the database."""
    conn = get_connection(config)
    with conn.cursor() as cur:
        for ctrl in CONTROLS:
            cur.execute("""
                INSERT INTO blueteam.compliance_controls
                    (control_id, family, family_id, requirement)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT (control_id) DO NOTHING
            """, (ctrl["control_id"], ctrl["family"],
                  ctrl["family_id"], ctrl["requirement"]))


def get_status_summary(config: dict) -> dict:
    """Get compliance status summary by family."""
    conn = get_connection(config)
    with conn.cursor() as cur:
        cur.execute("""
            SELECT family, status, COUNT(*) as count
            FROM blueteam.compliance_controls
            GROUP BY family, status
            ORDER BY family, status
        """)
        rows = cur.fetchall()
    summary = {}
    for row in rows:
        family = row["family"]
        if family not in summary:
            summary[family] = {}
        summary[family][row["status"]] = row["count"]
    return summary


def get_gaps(config: dict) -> list:
    """Get all controls not fully implemented."""
    conn = get_connection(config)
    with conn.cursor() as cur:
        cur.execute("""
            SELECT control_id, family, requirement, status
            FROM blueteam.compliance_controls
            WHERE status NOT IN ('implemented', 'not_applicable')
            ORDER BY control_id
        """)
        return cur.fetchall()


def update_control(config: dict, control_id: str, **kwargs):
    """Update a control's status and notes."""
    conn = get_connection(config)
    sets = []
    values = []
    for key in ("status", "implementation_notes", "evidence_type", "assessor_notes"):
        if key in kwargs:
            sets.append(f"{key} = %s")
            values.append(kwargs[key])
    if not sets:
        return
    sets.append("updated_at = NOW()")
    sets.append("last_assessed = NOW()")
    values.append(control_id)
    with conn.cursor() as cur:
        cur.execute(
            f"UPDATE blueteam.compliance_controls SET {', '.join(sets)} WHERE control_id = %s",
            values
        )
