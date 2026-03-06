"""Combined security posture scoring."""
from shared import get_connection


def calculate_posture(config: dict) -> dict:
    """Calculate overall security posture from all data sources."""
    conn = get_connection(config)

    # Compliance score: % of controls implemented
    with conn.cursor() as cur:
        cur.execute("""
            SELECT
                COUNT(*) as total,
                COUNT(*) FILTER (WHERE status = 'implemented') as implemented,
                COUNT(*) FILTER (WHERE status = 'partial') as partial,
                COUNT(*) FILTER (WHERE status = 'not_applicable') as na
            FROM blueteam.compliance_controls
        """)
        comp = cur.fetchone()

    assessable = comp["total"] - (comp["na"] or 0)
    compliance_score = (
        ((comp["implemented"] + (comp["partial"] or 0) * 0.5) / assessable * 100)
        if assessable > 0 else 0
    )

    # Latest red team score
    with conn.cursor() as cur:
        cur.execute(
            "SELECT redteam_score FROM blueteam.posture_scores ORDER BY scored_at DESC LIMIT 1"
        )
        rt = cur.fetchone()
    redteam_score = float(rt["redteam_score"]) if rt else 0

    # Incident score: inverse of open critical/high incidents
    with conn.cursor() as cur:
        cur.execute("""
            SELECT COUNT(*) as open_incidents
            FROM blueteam.security_incidents
            WHERE status NOT IN ('closed', 'recovered')
              AND severity IN ('critical', 'high')
        """)
        inc = cur.fetchone()
    incident_score = max(0, 100 - (inc["open_incidents"] * 20))

    # Monitoring score: based on collector health
    monitoring_score = 80  # Placeholder — check collector last-seen timestamps

    # Overall weighted score
    overall = (
        compliance_score * 0.35 +
        redteam_score * 0.30 +
        incident_score * 0.20 +
        monitoring_score * 0.15
    )

    return {
        "overall": round(overall, 1),
        "compliance": round(compliance_score, 1),
        "redteam": round(redteam_score, 1),
        "incident": round(incident_score, 1),
        "monitoring": round(monitoring_score, 1),
        "controls_implemented": comp["implemented"],
        "controls_total": assessable,
    }
