# BT-11: Incident Manager

**Goal:** Implement PICERL incident lifecycle management with DFARS 252.204-7012 72-hour reporting workflow and forensic evidence chain.

**Files:**
- Create: `/opt/security-blue-team/blueteam/incidents/manager.py`
- Create: `/opt/security-blue-team/blueteam/incidents/dfars.py`
- Create: `/opt/security-blue-team/blueteam/incidents/evidence.py`
- Create: `/opt/security-blue-team/templates/dfars_report.md.j2`
- Create: `/opt/security-blue-team/templates/incident_report.md.j2`
- Create: `/opt/security-blue-team/tests/test_incidents.py`
- Modify: `/opt/security-blue-team/blueteam/cli.py` — incidents subcommands

**Depends on:** BT-05

---

## Step 1: Write tests

```python
# tests/test_incidents.py
from blueteam.incidents.manager import IncidentManager
from blueteam.models import SecurityIncident

def test_create_incident():
    manager = IncidentManager.__new__(IncidentManager)
    incident = SecurityIncident(
        title="Brute force from 1.2.3.4",
        severity="high",
        detected_by="brute_force",
        nist_controls=["3.1.8"],
    )
    assert incident.severity == "high"
    assert incident.cui_involved is False

def test_dfars_classification():
    from blueteam.incidents.dfars import is_dfars_reportable
    # CUI breach = reportable
    assert is_dfars_reportable(cui_involved=True, severity="critical")
    # Non-CUI low severity = not reportable
    assert not is_dfars_reportable(cui_involved=False, severity="low")
```

---

## Step 2: Implement incident manager

```python
# blueteam/incidents/manager.py
"""Incident lifecycle management — PICERL workflow."""
import hashlib
from datetime import datetime, timezone
from blueteam.db import get_connection
from blueteam.models import SecurityIncident

class IncidentManager:
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
        conn = get_connection(self.config)
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM blueteam.security_incidents WHERE incident_id = %s", (incident_id,))
            return cur.fetchone()

    def add_evidence(self, incident_id: str, evidence_type: str,
                     description: str, content: str, collected_by: str) -> str:
        """Add evidence with SHA-256 integrity hash."""
        content_hash = hashlib.sha256(content.encode()).hexdigest()
        conn = get_connection(self.config)
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO blueteam.incident_evidence
                    (incident_id, evidence_type, description, content, collected_by, hash_sha256)
                VALUES (%s, %s, %s, %s, %s, %s)
                RETURNING evidence_id
            """, (incident_id, evidence_type, description, content, collected_by, content_hash))
            row = cur.fetchone()
            return str(row["evidence_id"])
```

---

## Step 3: Implement DFARS reporting

```python
# blueteam/incidents/dfars.py
"""DFARS 252.204-7012 reporting workflow — 72-hour CUI breach notification."""
from datetime import datetime, timedelta, timezone
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
                COUNT(*) FILTER (WHERE dfars_reportable AND dfars_reported_at IS NULL AND status != 'closed') as pending,
                COUNT(*) FILTER (WHERE dfars_reportable AND dfars_reported_at IS NOT NULL) as reported,
                COUNT(*) FILTER (WHERE dfars_reportable AND dfars_reported_at IS NULL
                    AND detected_at < NOW() - INTERVAL '72 hours' AND status != 'closed') as overdue
            FROM blueteam.security_incidents
        """)
        return cur.fetchone()
```

---

## Step 4: Wire CLI commands

```python
@incidents.command(name="list")
@click.pass_context
def incidents_list(ctx):
    """List active incidents."""
    from blueteam.incidents.manager import IncidentManager
    mgr = IncidentManager(ctx.obj["config"])
    active = mgr.list_active()
    # Rich table output with severity coloring...

@incidents.command(name="create")
@click.option("--title", required=True)
@click.option("--severity", type=click.Choice(["critical", "high", "medium", "low"]), required=True)
@click.option("--cui", is_flag=True, help="CUI involved")
@click.pass_context
def incidents_create(ctx, title, severity, cui):
    """Create a new security incident."""
    from blueteam.incidents.manager import IncidentManager
    from blueteam.models import SecurityIncident
    mgr = IncidentManager(ctx.obj["config"])
    incident = SecurityIncident(title=title, severity=severity, detected_by="manual", nist_controls=[], cui_involved=cui)
    iid = mgr.create(incident)
    console.print(f"[green]Incident created: {iid}[/green]")

@incidents.command(name="dfars")
@click.pass_context
def incidents_dfars(ctx):
    """Check DFARS 72-hour reporting status."""
    from blueteam.incidents.dfars import get_reporting_status, get_overdue_reports
    status = get_reporting_status(ctx.obj["config"])
    overdue = get_overdue_reports(ctx.obj["config"])
    # Display status and any overdue reports...
```

---

## Step 5: Run tests, commit

```bash
python -m pytest tests/test_incidents.py -v
git add -A
git commit -m "feat: incident manager with PICERL lifecycle and DFARS reporting (NIST 3.6.1-3.6.3)"
```
