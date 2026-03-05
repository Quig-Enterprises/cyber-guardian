# BT-12: Reports & Red Team Integration

**Goal:** Implement report generation (assessor, executive, posture) and red team results integration for combined security posture scoring.

**Files:**
- Create: `/opt/security-blue-team/blueteam/reports/assessor.py`
- Create: `/opt/security-blue-team/blueteam/reports/posture.py`
- Create: `/opt/security-blue-team/blueteam/reports/redteam_import.py`
- Create: `/opt/security-blue-team/templates/assessor_report.md.j2`
- Create: `/opt/security-blue-team/templates/posture_report.md.j2`
- Create: `/opt/security-blue-team/tests/test_reports.py`
- Modify: `/opt/security-blue-team/blueteam/cli.py` — report and redteam commands

**Depends on:** BT-09, BT-10, BT-11

---

## Step 1: Implement red team import

```python
# blueteam/reports/redteam_import.py
"""Import red team attack results for posture scoring."""
import json
from pathlib import Path
from datetime import datetime, timezone
from blueteam.db import get_connection

def import_report(config: dict, report_path: str) -> dict:
    """Import a red team JSON report into posture scoring."""
    path = Path(report_path)
    with open(path) as f:
        report = json.load(f)

    summary = report.get("summary", {})
    attacks = report.get("attacks", [])

    total = summary.get("total_variants", 0)
    defended = summary.get("defended", 0)
    partial = summary.get("partial", 0)
    vulnerable = summary.get("vulnerable", 0)

    # Calculate red team score (0-100, higher = better defended)
    if total > 0:
        score = ((defended * 1.0 + partial * 0.5) / total) * 100
    else:
        score = 0

    # Store posture score
    conn = get_connection(config)
    with conn.cursor() as cur:
        cur.execute("""
            INSERT INTO blueteam.posture_scores
                (redteam_score, details, redteam_report_id)
            VALUES (%s, %s, %s)
            RETURNING score_id
        """, (round(score, 2), json.dumps({
            "total_variants": total,
            "defended": defended,
            "partial": partial,
            "vulnerable": vulnerable,
            "report_file": path.name,
            "imported_at": datetime.now(timezone.utc).isoformat(),
        }), path.stem))
        row = cur.fetchone()

    return {
        "score_id": str(row["score_id"]),
        "redteam_score": round(score, 2),
        "total": total,
        "defended": defended,
        "partial": partial,
        "vulnerable": vulnerable,
    }
```

---

## Step 2: Implement posture scoring

```python
# blueteam/reports/posture.py
"""Combined security posture scoring."""
from blueteam.db import get_connection

def calculate_posture(config: dict) -> dict:
    """Calculate overall security posture from all data sources."""
    conn = get_connection(config)

    # Compliance score: % of controls implemented
    with conn.cursor() as cur:
        cur.execute("""
            SELECT
                COUNT(*) as total,
                COUNT(*) FILTER (WHERE status = 'implemented') as implemented,
                COUNT(*) FILTER (WHERE status = 'partially_implemented') as partial,
                COUNT(*) FILTER (WHERE status = 'not_applicable') as na
            FROM blueteam.compliance_controls
        """)
        comp = cur.fetchone()

    assessable = comp["total"] - (comp["na"] or 0)
    compliance_score = ((comp["implemented"] + (comp["partial"] or 0) * 0.5) / assessable * 100) if assessable > 0 else 0

    # Latest red team score
    with conn.cursor() as cur:
        cur.execute("SELECT redteam_score FROM blueteam.posture_scores ORDER BY scored_at DESC LIMIT 1")
        rt = cur.fetchone()
    redteam_score = rt["redteam_score"] if rt else 0

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
```

---

## Step 3: Implement assessor report generation

```python
# blueteam/reports/assessor.py
"""Generate CMMC assessor-ready compliance reports."""
from pathlib import Path
from jinja2 import Environment, FileSystemLoader
from blueteam.db import get_connection
from blueteam.reports.posture import calculate_posture

TEMPLATE_DIR = Path(__file__).parent.parent.parent / "templates"

def generate_assessor_report(config: dict, output_path: str):
    """Generate a comprehensive assessor-ready report."""
    env = Environment(loader=FileSystemLoader(str(TEMPLATE_DIR)))
    template = env.get_template("assessor_report.md.j2")

    conn = get_connection(config)
    posture = calculate_posture(config)

    # Get all controls with evidence
    with conn.cursor() as cur:
        cur.execute("""
            SELECT c.*, array_agg(e.description) as evidence_list
            FROM blueteam.compliance_controls c
            LEFT JOIN blueteam.compliance_evidence e ON c.control_id = e.control_id
            GROUP BY c.control_id
            ORDER BY c.control_id
        """)
        controls = cur.fetchall()

    # Get POA&M items
    with conn.cursor() as cur:
        cur.execute("SELECT * FROM blueteam.poam_items WHERE status != 'completed' ORDER BY risk_level DESC")
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
```

---

## Step 4: Wire CLI commands

```python
@report.command(name="posture")
@click.pass_context
def report_posture(ctx):
    """Show overall security posture score."""
    from blueteam.reports.posture import calculate_posture
    posture = calculate_posture(ctx.obj["config"])
    # Rich formatted output with color-coded scores...

@report.command(name="assessor")
@click.option("--output", "-o", default="/tmp/cmmc-assessor-report.md")
@click.pass_context
def report_assessor(ctx, output):
    """Generate CMMC assessor-ready compliance report."""
    from blueteam.reports.assessor import generate_assessor_report
    path = generate_assessor_report(ctx.obj["config"], output)
    console.print(f"[green]Assessor report written to {path}[/green]")

@main.group()
def redteam():
    """Red team integration commands."""
    pass

@redteam.command(name="import")
@click.argument("report_path")
@click.pass_context
def redteam_import(ctx, report_path):
    """Import a red team report for posture scoring."""
    from blueteam.reports.redteam_import import import_report
    result = import_report(ctx.obj["config"], report_path)
    console.print(f"[green]Imported: score={result['redteam_score']}/100[/green]")
    console.print(f"  Defended: {result['defended']}/{result['total']}")
    console.print(f"  Vulnerable: {result['vulnerable']}/{result['total']}")
```

---

## Step 5: Create report templates

**templates/assessor_report.md.j2** — Full CMMC assessor report with:
- System description and boundary
- Overall posture scores
- Control-by-control status with evidence references
- POA&M items
- Incident history summary
- Red team results summary

---

## Step 6: Run tests, commit

```bash
python -m pytest tests/test_reports.py -v
git add -A
git commit -m "feat: assessor reports, posture scoring, red team integration (NIST 3.12.1)"
```
