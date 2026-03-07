"""Compliance control management — load, query, update."""
from shared import get_connection
from blueteam.compliance.nist_800_171 import CONTROLS
from blueteam.compliance.pci_dss_v4 import CONTROLS as PCI_CONTROLS
from blueteam.compliance.hipaa_security import CONTROLS as HIPAA_CONTROLS
from blueteam.compliance.cross_map import MAPPINGS as CROSS_MAPPINGS


def load_controls(config: dict, framework: str = "nist_800_171"):
    """Load compliance controls for the specified framework into the database."""
    catalog_map = {
        "nist_800_171": CONTROLS,
        "pci_dss_v4": PCI_CONTROLS,
        "hipaa": HIPAA_CONTROLS,
    }
    controls = catalog_map.get(framework)
    if controls is None:
        raise ValueError(f"Unknown framework: {framework}")
    conn = get_connection(config)
    with conn.cursor() as cur:
        for ctrl in controls:
            cur.execute("""
                INSERT INTO blueteam.compliance_controls
                    (framework, control_id, family, family_id, requirement)
                VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT (framework, control_id) DO NOTHING
            """, (framework, ctrl["control_id"], ctrl["family"],
                  ctrl["family_id"], ctrl["requirement"]))


def load_pci_controls(config: dict):
    """Load PCI DSS 4.0 controls."""
    load_controls(config, framework="pci_dss_v4")


def load_hipaa_controls(config: dict):
    """Load HIPAA Security Rule controls."""
    load_controls(config, framework="hipaa")


def load_cross_map(config: dict):
    """Load cross-framework compliance mappings."""
    conn = get_connection(config)
    with conn.cursor() as cur:
        for m in CROSS_MAPPINGS:
            cur.execute("""
                INSERT INTO blueteam.compliance_cross_map
                    (source_framework, source_control, target_framework,
                     target_control, relationship, notes)
                VALUES (%s, %s, %s, %s, %s, %s)
                ON CONFLICT (source_framework, source_control,
                             target_framework, target_control) DO NOTHING
            """, (m["source_framework"], m["source_control"],
                  m["target_framework"], m["target_control"],
                  m["relationship"], m.get("notes", "")))


def get_status_summary(config: dict, framework: str | None = None) -> dict:
    """Get compliance status summary by family, optionally filtered by framework."""
    conn = get_connection(config)
    with conn.cursor() as cur:
        if framework:
            cur.execute("""
                SELECT family, status, COUNT(*) as count
                FROM blueteam.compliance_controls
                WHERE framework = %s
                GROUP BY family, status
                ORDER BY family, status
            """, (framework,))
        else:
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


def get_gaps(config: dict, framework: str | None = None) -> list:
    """Get all controls not fully implemented, optionally filtered by framework."""
    conn = get_connection(config)
    with conn.cursor() as cur:
        if framework:
            cur.execute("""
                SELECT framework, control_id, family, requirement, status
                FROM blueteam.compliance_controls
                WHERE status NOT IN ('implemented', 'not_applicable')
                  AND framework = %s
                ORDER BY control_id
            """, (framework,))
        else:
            cur.execute("""
                SELECT framework, control_id, family, requirement, status
                FROM blueteam.compliance_controls
                WHERE status NOT IN ('implemented', 'not_applicable')
                ORDER BY framework, control_id
            """)
        return cur.fetchall()


def update_control(config: dict, control_id: str, framework: str = "nist_800_171", **kwargs):
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
    values.extend([framework, control_id])
    with conn.cursor() as cur:
        cur.execute(
            f"UPDATE blueteam.compliance_controls SET {', '.join(sets)} WHERE framework = %s AND control_id = %s",
            values
        )


def get_cross_mappings(config: dict, framework: str, control_id: str) -> list:
    """Get cross-framework mappings for a specific control."""
    conn = get_connection(config)
    with conn.cursor() as cur:
        cur.execute("""
            SELECT target_framework, target_control, relationship, notes
            FROM blueteam.compliance_cross_map
            WHERE source_framework = %s AND source_control = %s
            UNION
            SELECT source_framework, source_control, relationship, notes
            FROM blueteam.compliance_cross_map
            WHERE target_framework = %s AND target_control = %s
            ORDER BY 1, 2
        """, (framework, control_id, framework, control_id))
        return cur.fetchall()


def get_framework_summary(config: dict) -> list:
    """Get summary of all loaded frameworks."""
    conn = get_connection(config)
    with conn.cursor() as cur:
        cur.execute("""
            SELECT framework, COUNT(*) as total_controls,
                   COUNT(*) FILTER (WHERE status = 'implemented') as implemented,
                   COUNT(*) FILTER (WHERE status = 'not_assessed') as not_assessed
            FROM blueteam.compliance_controls
            GROUP BY framework
            ORDER BY framework
        """)
        return cur.fetchall()
