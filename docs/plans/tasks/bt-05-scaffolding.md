# BT-05: Blue Team Python Project Scaffolding

**Goal:** Set up the Python project structure for the blue team analysis engine at `/opt/security-blue-team/`.

**Files:**
- Create: `/opt/security-blue-team/pyproject.toml`
- Create: `/opt/security-blue-team/blueteam/__init__.py`
- Create: `/opt/security-blue-team/blueteam/config.py`
- Create: `/opt/security-blue-team/blueteam/db.py`
- Create: `/opt/security-blue-team/blueteam/models.py`
- Create: `/opt/security-blue-team/blueteam/cli.py`
- Create: `/opt/security-blue-team/blueteam/collectors/__init__.py`
- Create: `/opt/security-blue-team/blueteam/correlator/__init__.py`
- Create: `/opt/security-blue-team/blueteam/alerting/__init__.py`
- Create: `/opt/security-blue-team/blueteam/compliance/__init__.py`
- Create: `/opt/security-blue-team/blueteam/incidents/__init__.py`
- Create: `/opt/security-blue-team/blueteam/reports/__init__.py`
- Create: `/opt/security-blue-team/tests/__init__.py`
- Create: `/opt/security-blue-team/config.yaml`
- Create: `/opt/security-blue-team/.gitignore`
- Create: `/opt/security-blue-team/README.md`

**Depends on:** None (can start parallel with Phase 1)

---

## Step 1: Create directory structure

```bash
sudo mkdir -p /opt/security-blue-team/{blueteam/{collectors,correlator,alerting,compliance,incidents,reports},tests,templates}
sudo chown -R $USER:$USER /opt/security-blue-team
cd /opt/security-blue-team
git init
```

---

## Step 2: Create pyproject.toml

```toml
[build-system]
requires = ["setuptools>=68.0"]
build-backend = "setuptools.build_meta"

[project]
name = "eqmon-blue-team"
version = "0.1.0"
description = "EQMON Blue Team - Defensive Security Monitoring & CMMC Compliance"
requires-python = ">=3.11"
dependencies = [
    "psycopg2-binary>=2.9",
    "click>=8.1",
    "rich>=13.0",
    "pyyaml>=6.0",
    "jinja2>=3.1",
]

[project.optional-dependencies]
dev = ["pytest>=8.0", "pytest-asyncio>=0.23"]

[project.scripts]
blueteam = "blueteam.cli:main"

[tool.setuptools.packages.find]
include = ["blueteam*"]
```

---

## Step 3: Create config.yaml

```yaml
# Blue Team Configuration
database:
  host: localhost
  port: 5432
  name: eqmon
  user: eqmon
  # password loaded from EQMON_AUTH_DB_PASS env var

monitoring:
  poll_interval_sec: 5
  log_retention_days: 90

alerting:
  email:
    enabled: false
    smtp_host: localhost
    smtp_port: 587
    from_address: blueteam@eqmon.local
    recipients: []
  syslog:
    enabled: true
    facility: local6

collectors:
  db_audit:
    enabled: true
  syslog:
    enabled: true
    path: /var/log/syslog
  nginx:
    enabled: true
    path: /var/log/nginx/access.log
  php_errors:
    enabled: true
    paths:
      - /var/www/html/eqmon/logs/server_errors.log
      - /opt/eqmon/logs/server_errors.log
  redteam:
    enabled: true
    reports_dir: /opt/security-red-team/reports

correlation:
  window_seconds: 300
  rules:
    brute_force:
      threshold: 5
      window_seconds: 300
    credential_stuffing:
      threshold: 10
      window_seconds: 300
    data_exfiltration:
      threshold: 20
      window_seconds: 3600

compliance:
  framework: "NIST SP 800-171r2"
  target_level: "CMMC Level 2"
  controls_count: 110
```

---

## Step 4: Create core modules

**blueteam/__init__.py:**
```python
"""EQMON Blue Team - Defensive Security Monitoring & CMMC Compliance"""
__version__ = "0.1.0"
```

**blueteam/config.py:**
```python
"""Configuration loader."""
import os
from pathlib import Path
import yaml

DEFAULT_CONFIG = Path(__file__).parent.parent / "config.yaml"

def load_config(path: str | Path | None = None) -> dict:
    config_path = Path(path) if path else DEFAULT_CONFIG
    if not config_path.exists():
        raise FileNotFoundError(f"Config not found: {config_path}")
    with open(config_path) as f:
        config = yaml.safe_load(f)
    # Override DB password from env
    config["database"]["password"] = os.environ.get(
        "EQMON_AUTH_DB_PASS", os.environ.get("DB_PASS", "")
    )
    return config
```

**blueteam/db.py:**
```python
"""Database connection management."""
import psycopg2
from psycopg2.extras import RealDictCursor

_conn = None

def get_connection(config: dict) -> psycopg2.extensions.connection:
    global _conn
    if _conn is None or _conn.closed:
        db = config["database"]
        _conn = psycopg2.connect(
            host=db["host"],
            port=db.get("port", 5432),
            dbname=db["name"],
            user=db["user"],
            password=db.get("password", ""),
            cursor_factory=RealDictCursor,
        )
        _conn.autocommit = True
    return _conn

def close():
    global _conn
    if _conn and not _conn.closed:
        _conn.close()
        _conn = None
```

**blueteam/models.py:**
```python
"""Core data models."""
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

@dataclass
class SecurityEvent:
    """Normalized security event from any collector."""
    timestamp: datetime
    source: str          # 'audit_db', 'syslog', 'nginx', 'php_error', 'redteam'
    category: str        # auth, access, admin, data, ai, system, network
    severity: str        # critical, high, medium, low, info
    action: str
    user_id: Optional[str] = None
    ip_address: Optional[str] = None
    details: dict = field(default_factory=dict)
    nist_controls: list[str] = field(default_factory=list)
    cui_involved: bool = False
    event_id: Optional[str] = None

@dataclass
class SecurityIncident:
    """A correlated security incident."""
    title: str
    severity: str
    detected_by: str
    nist_controls: list[str]
    description: str = ""
    cui_involved: bool = False
    events: list[SecurityEvent] = field(default_factory=list)
    incident_id: Optional[str] = None

@dataclass
class ComplianceControl:
    """A NIST SP 800-171 control."""
    control_id: str
    family: str
    family_id: str
    requirement: str
    status: str = "not_assessed"
    implementation_notes: str = ""
    evidence_type: Optional[str] = None
```

**blueteam/cli.py:**
```python
"""Blue Team CLI interface."""
import click
from rich.console import Console

from blueteam.config import load_config

console = Console()

@click.group()
@click.option("--config", "-c", default=None, help="Config file path")
@click.pass_context
def main(ctx, config):
    """EQMON Blue Team - Defensive Security Monitoring & CMMC Compliance"""
    ctx.ensure_object(dict)
    ctx.obj["config"] = load_config(config)

@main.command()
@click.pass_context
def status(ctx):
    """Show current security posture summary."""
    console.print("[bold]EQMON Blue Team[/bold] - Security Posture", style="blue")
    console.print("Status: [yellow]Not yet monitoring[/yellow]")
    console.print("Run 'blueteam monitor' to start real-time monitoring.")

@main.group()
def compliance():
    """Compliance tracking commands."""
    pass

@compliance.command(name="status")
@click.pass_context
def compliance_status(ctx):
    """Show all 110 NIST controls with status."""
    console.print("[bold]Compliance Status[/bold]", style="blue")
    console.print("[yellow]Not yet loaded. Run bt-10 to populate controls.[/yellow]")

@main.group()
def incidents():
    """Incident management commands."""
    pass

@incidents.command(name="list")
@click.pass_context
def incidents_list(ctx):
    """List active incidents."""
    console.print("[bold]Active Incidents[/bold]", style="blue")
    console.print("[green]No active incidents.[/green]")

@main.group()
def alerts():
    """Alert management commands."""
    pass

@main.group()
def report():
    """Generate reports."""
    pass

if __name__ == "__main__":
    main()
```

---

## Step 5: Create .gitignore

```
__pycache__/
*.pyc
*.egg-info/
venv/
dist/
build/
.env
*.log
```

---

## Step 6: Set up venv and install

```bash
cd /opt/security-blue-team
python3 -m venv venv
source venv/bin/activate
pip install -e ".[dev]"
```

---

## Step 7: Verify CLI works

```bash
blueteam --help
blueteam status
```

Expected: Help text showing monitor, compliance, incidents, alerts, report command groups.

---

## Step 8: Commit

```bash
cd /opt/security-blue-team
git add -A
git commit -m "feat: blue team project scaffolding with CLI framework"
```
