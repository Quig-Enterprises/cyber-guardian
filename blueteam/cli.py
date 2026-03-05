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


@main.command()
@click.pass_context
def monitor(ctx):
    """Start real-time security monitoring daemon."""
    from blueteam.monitor import MonitorDaemon
    daemon = MonitorDaemon(ctx.obj["config"])
    daemon.start()


@main.group()
def compliance():
    """Compliance tracking commands."""
    pass


@compliance.command(name="status")
@click.pass_context
def compliance_status(ctx):
    """Show all 110 NIST controls with status."""
    console.print("[bold]Compliance Status[/bold]", style="blue")
    console.print("[yellow]Not yet loaded. Run 'blueteam compliance load' to populate controls.[/yellow]")


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
