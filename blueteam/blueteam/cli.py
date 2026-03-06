"""Blue Team CLI interface."""
import click
from rich.console import Console
from rich.table import Table

from shared import load_config

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
    console.print("Run 'blueteam monitor' to start real-time monitoring.")
    console.print("Run 'blueteam compliance status' for NIST control status.")
    console.print("Run 'blueteam incidents list' for active incidents.")


@main.command()
@click.pass_context
def monitor(ctx):
    """Start real-time security monitoring daemon."""
    from blueteam.monitor import MonitorDaemon
    daemon = MonitorDaemon(ctx.obj["config"])
    daemon.start()


# --- Compliance commands ---

@main.group()
def compliance():
    """Compliance tracking commands."""
    pass


@compliance.command(name="load")
@click.pass_context
def compliance_load(ctx):
    """Load all 110 NIST SP 800-171r2 controls into database."""
    from blueteam.compliance.controls import load_controls
    load_controls(ctx.obj["config"])
    console.print("[green]Loaded 110 NIST SP 800-171r2 controls.[/green]")


@compliance.command(name="status")
@click.pass_context
def compliance_status(ctx):
    """Show compliance status by family."""
    from blueteam.compliance.controls import get_status_summary
    summary = get_status_summary(ctx.obj["config"])
    if not summary:
        console.print("[yellow]No controls loaded. Run 'blueteam compliance load' first.[/yellow]")
        return

    table = Table(title="NIST SP 800-171r2 Compliance Status")
    table.add_column("Family", style="cyan")
    table.add_column("Implemented", style="green", justify="right")
    table.add_column("Partial", style="yellow", justify="right")
    table.add_column("Not Assessed", style="red", justify="right")
    table.add_column("N/A", style="dim", justify="right")

    for family, statuses in sorted(summary.items()):
        table.add_row(
            family,
            str(statuses.get("implemented", 0)),
            str(statuses.get("partial", 0)),
            str(statuses.get("not_assessed", 0)),
            str(statuses.get("not_applicable", 0)),
        )
    console.print(table)


@compliance.command(name="gaps")
@click.pass_context
def compliance_gaps(ctx):
    """Show all unimplemented/partial controls."""
    from blueteam.compliance.controls import get_gaps
    gaps = get_gaps(ctx.obj["config"])
    if not gaps:
        console.print("[green]All controls implemented or N/A.[/green]")
        return

    table = Table(title=f"Compliance Gaps ({len(gaps)} controls)")
    table.add_column("Control", style="cyan", width=8)
    table.add_column("Family", style="blue")
    table.add_column("Status", style="yellow")
    table.add_column("Requirement")

    for gap in gaps:
        table.add_row(
            gap["control_id"], gap["family"],
            gap["status"], gap["requirement"][:80] + "..."
            if len(gap["requirement"]) > 80 else gap["requirement"],
        )
    console.print(table)


# --- Incident commands ---

@main.group()
def incidents():
    """Incident management commands."""
    pass


@incidents.command(name="list")
@click.pass_context
def incidents_list(ctx):
    """List active incidents."""
    from blueteam.incidents.manager import IncidentManager
    mgr = IncidentManager(ctx.obj["config"])
    active = mgr.list_active()
    if not active:
        console.print("[green]No active incidents.[/green]")
        return

    table = Table(title=f"Active Incidents ({len(active)})")
    table.add_column("ID", style="dim", width=8)
    table.add_column("Severity", width=10)
    table.add_column("Status", style="cyan")
    table.add_column("Title")
    table.add_column("CUI", width=4)
    table.add_column("DFARS", width=6)

    sev_colors = {"critical": "red bold", "high": "red", "medium": "yellow", "low": "green"}
    for inc in active:
        sev = inc["severity"]
        table.add_row(
            str(inc["incident_id"])[:8],
            f"[{sev_colors.get(sev, '')}]{sev}[/]",
            inc["status"],
            inc["title"],
            "Yes" if inc["cui_involved"] else "",
            "Yes" if inc["dfars_reportable"] else "",
        )
    console.print(table)


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
    incident = SecurityIncident(
        title=title, severity=severity, detected_by="manual",
        nist_controls=[], cui_involved=cui,
    )
    iid = mgr.create(incident)
    console.print(f"[green]Incident created: {iid}[/green]")
    if cui and severity in ("critical", "high"):
        console.print("[red bold]DFARS 72-hour reporting required![/red bold]")


@incidents.command(name="dfars")
@click.pass_context
def incidents_dfars(ctx):
    """Check DFARS 72-hour reporting status."""
    from blueteam.incidents.dfars import get_reporting_status, get_overdue_reports
    status = get_reporting_status(ctx.obj["config"])
    console.print("[bold]DFARS 252.204-7012 Reporting Status[/bold]")
    console.print(f"  Pending reports: {status['pending']}")
    console.print(f"  Reported to DC3: {status['reported']}")
    if status["overdue"] > 0:
        console.print(f"  [red bold]OVERDUE: {status['overdue']} incidents past 72-hour deadline![/red bold]")
        overdue = get_overdue_reports(ctx.obj["config"])
        for inc in overdue:
            console.print(f"    - [{inc['severity'].upper()}] {inc['title']} (elapsed: {inc['time_elapsed']})")
    else:
        console.print("  [green]No overdue reports.[/green]")


# --- Alert commands ---

@main.group()
def alerts():
    """Alert management commands."""
    pass


# --- Report commands ---

@main.group()
def report():
    """Generate reports."""
    pass


@report.command(name="posture")
@click.pass_context
def report_posture(ctx):
    """Show overall security posture score."""
    from blueteam.reports.posture import calculate_posture
    posture = calculate_posture(ctx.obj["config"])

    def score_color(score):
        if score >= 80:
            return "green"
        elif score >= 50:
            return "yellow"
        return "red"

    console.print("\n[bold]Security Posture Score[/bold]")
    c = score_color(posture["overall"])
    console.print(f"  Overall: [{c} bold]{posture['overall']}/100[/{c} bold]")
    for key in ("compliance", "redteam", "incident", "monitoring"):
        c = score_color(posture[key])
        label = key.replace("_", " ").title()
        console.print(f"  {label}: [{c}]{posture[key]}/100[/{c}]")
    console.print(f"\n  Controls: {posture['controls_implemented']}/{posture['controls_total']} implemented")


@report.command(name="assessor")
@click.option("--output", "-o", default="/tmp/cmmc-assessor-report.md")
@click.pass_context
def report_assessor(ctx, output):
    """Generate CMMC assessor-ready compliance report."""
    from blueteam.reports.assessor import generate_assessor_report
    path = generate_assessor_report(ctx.obj["config"], output)
    console.print(f"[green]Assessor report written to {path}[/green]")


# --- Red team integration ---

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


if __name__ == "__main__":
    main()
