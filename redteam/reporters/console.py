"""Console reporter for human-readable terminal output."""

import logging
from typing import Any

from ..base import Severity, Status
from ..scoring import severity_color, status_color

logger = logging.getLogger(__name__)

try:
    from rich.console import Console
    from rich.table import Table
    from rich.text import Text
    _RICH_AVAILABLE = True
except ImportError:
    _RICH_AVAILABLE = False


class ConsoleReporter:
    """Renders attack results and summaries to the console."""

    def __init__(self):
        if _RICH_AVAILABLE:
            self.console = Console()
        else:
            self.console = None

    def print_attack_list(self, attacks: list[dict]) -> None:
        """Print a formatted list of available attacks."""
        if not attacks:
            print("No attacks registered.")
            return

        if _RICH_AVAILABLE and self.console is not None:
            table = Table(title="Available Attacks", show_lines=False)
            table.add_column("Key", style="cyan", no_wrap=True)
            table.add_column("Name")
            table.add_column("Category", style="blue")
            table.add_column("Severity")
            table.add_column("Description")

            for attack in attacks:
                sev = attack.get("severity", "info")
                sev_enum = Severity(sev) if sev in [s.value for s in Severity] else Severity.INFO
                color = severity_color(sev_enum)
                table.add_row(
                    attack["key"],
                    attack["name"],
                    attack["category"],
                    Text(sev.upper(), style=color),
                    attack.get("description", ""),
                )
            self.console.print(table)
        else:
            print(f"{'KEY':<25} {'NAME':<30} {'CAT':<6} {'SEV':<10} DESCRIPTION")
            print("-" * 90)
            for attack in attacks:
                print(
                    f"{attack['key']:<25} {attack['name']:<30} "
                    f"{attack['category']:<6} {attack.get('severity','info'):<10} "
                    f"{attack.get('description','')}"
                )

    def print_report(self, summary: dict) -> None:
        """Print a summary report of all attack results."""
        total = summary.get("total_variants", 0)
        vulnerable = summary.get("total_vulnerable", 0)
        partial = summary.get("total_partial", 0)
        defended = summary.get("total_defended", 0)
        errors = summary.get("total_errors", 0)
        worst = summary.get("worst_severity", Severity.INFO)

        if _RICH_AVAILABLE and self.console is not None:
            console = self.console

            console.print("\n[bold]Security Red Team Report[/bold]")
            console.print(f"Attacks run:  {summary.get('total_attacks', 0)}")
            console.print(f"Variants:     {total}")
            console.print(f"[red bold]Vulnerable:   {vulnerable}[/red bold]")
            console.print(f"[yellow]Partial:      {partial}[/yellow]")
            console.print(f"[green]Defended:     {defended}[/green]")
            console.print(f"[magenta]Errors:       {errors}[/magenta]")

            if isinstance(worst, Severity):
                color = severity_color(worst)
                console.print(f"Worst severity: [{color}]{worst.value.upper()}[/{color}]")

            timing = summary.get("timing", {})
            if timing:
                console.print(f"Started:      {timing.get('start', 'N/A')}")
                console.print(f"Finished:     {timing.get('end', 'N/A')}")
                duration = timing.get('duration_ms', 0)
                console.print(f"Duration:     {duration/1000:.1f}s")

            by_cat = summary.get("by_category", {})
            if by_cat:
                table = Table(title="Results by Category")
                table.add_column("Category", style="blue")
                table.add_column("Attacks", justify="right")
                table.add_column("Vulnerable", justify="right", style="red")
                table.add_column("Partial", justify="right", style="yellow")
                table.add_column("Defended", justify="right", style="green")
                table.add_column("Errors", justify="right", style="magenta")
                table.add_column("Duration", justify="right", style="cyan")

                for cat, data in sorted(by_cat.items()):
                    table.add_row(
                        cat,
                        str(data["attacks"]),
                        str(data["vulnerable"]),
                        str(data["partial"]),
                        str(data["defended"]),
                        str(data["errors"]),
                        f"{data.get('duration_ms', 0)/1000:.1f}s",
                    )
                console.print(table)

            # Per-attack detail
            scores = summary.get("scores", [])
            if scores:
                detail = Table(title="Per-Attack Detail", show_lines=True)
                detail.add_column("Attack")
                detail.add_column("Category")
                detail.add_column("Vuln", justify="right")
                detail.add_column("Part", justify="right")
                detail.add_column("Def", justify="right")
                detail.add_column("Err", justify="right")
                detail.add_column("Severity")
                detail.add_column("Duration", justify="right", style="cyan")

                for score in scores:
                    sev_color = severity_color(score.worst_severity)
                    detail.add_row(
                        score.attack_name,
                        score.category,
                        str(score.vulnerable),
                        str(score.partial),
                        str(score.defended),
                        str(score.errors),
                        Text(score.worst_severity.value.upper(), style=sev_color),
                        f"{score.duration_ms/1000:.1f}s",
                    )
                console.print(detail)

            # Verdict
            if vulnerable == 0 and partial == 0:
                console.print("\n[green bold]All attacks defended![/green bold]")
        else:
            print("\n=== Security Red Team Report ===")
            print(f"Attacks run:  {summary.get('total_attacks', 0)}")
            print(f"Variants:     {total}")
            print(f"Vulnerable:   {vulnerable}")
            print(f"Partial:      {partial}")
            print(f"Defended:     {defended}")
            print(f"Errors:       {errors}")
            worst_val = worst.value if isinstance(worst, Severity) else str(worst)
            print(f"Worst severity: {worst_val.upper()}")
