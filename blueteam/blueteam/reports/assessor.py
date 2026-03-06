"""Generate CMMC assessor-ready compliance reports."""
from pathlib import Path
from jinja2 import Environment, FileSystemLoader
from blueteam.db import get_connection
from blueteam.reports.posture import calculate_posture

TEMPLATE_DIR = Path(__file__).parent.parent.parent / "templates"


def generate_assessor_report(config: dict, output_path: str) -> str:
    """Generate a comprehensive assessor-ready report."""
    env = Environment(loader=FileSystemLoader(str(TEMPLATE_DIR)))
    template = env.get_template("assessor_report.md.j2")

    conn = get_connection(config)
    posture = calculate_posture(config)

    # Get all controls
    with conn.cursor() as cur:
        cur.execute("""
            SELECT control_id, family, family_id, requirement, status,
                   implementation_notes, evidence_type
            FROM blueteam.compliance_controls
            ORDER BY control_id
        """)
        controls = cur.fetchall()

    # Get POA&M items
    with conn.cursor() as cur:
        cur.execute(
            "SELECT * FROM blueteam.poam_items WHERE status != 'completed' ORDER BY risk_level DESC"
        )
        poam_items = cur.fetchall()

    # Get incident summary
    with conn.cursor() as cur:
        cur.execute("""
            SELECT severity, COUNT(*) as count
            FROM blueteam.security_incidents
            GROUP BY severity
        """)
        incident_summary = cur.fetchall()

    report = template.render(
        posture=posture,
        controls=controls,
        poam_items=poam_items,
        incident_summary=incident_summary,
        framework="NIST SP 800-171 Rev 2",
        target_level="CMMC Level 2",
    )

    Path(output_path).write_text(report)
    return output_path
