# Task 06: Reporters

## Overview

Create the reporting modules that format and output red team results. Three formats are supported: Rich terminal output for interactive use, JSON for machine consumption and CI integration, and HTML for shareable standalone reports.

## Files

- `redteam/reporters/console.py` - Rich terminal output with tables, panels, and color-coded severity
- `redteam/reporters/json_report.py` - JSON output for programmatic consumption
- `redteam/reporters/html.py` - Jinja2-based standalone HTML report with dark theme
- `tests/test_reporters.py` - Unit tests

---

## Step 1: Write tests/test_reporters.py

Create `/opt/security-red-team/tests/test_reporters.py`:

```python
"""Tests for the reporter modules: console, json_report, html."""

import json
import os
import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime
from pathlib import Path

from redteam.base import AttackResult, Score, Severity, Status
from redteam.scoring import aggregate_scores
from redteam.reporters.console import ConsoleReporter
from redteam.reporters.json_report import JsonReporter
from redteam.reporters.html import HtmlReporter


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_result(attack_name="Test Attack", variant="v1", status=Status.VULNERABLE,
                 severity=Severity.HIGH, evidence="leaked data", details="Found issue",
                 duration_ms=150.0) -> AttackResult:
    return AttackResult(
        attack_name=attack_name,
        variant=variant,
        status=status,
        severity=severity,
        evidence=evidence,
        details=details,
        request={"prompt": "test prompt"},
        response={"text": "test response"},
        duration_ms=duration_ms,
    )


def _make_score(name="Test Attack", category="ai", vulnerable=1, partial=0,
                defended=1, errors=0, worst_severity=Severity.HIGH,
                results=None) -> Score:
    if results is None:
        results = []
        if vulnerable > 0:
            results.append(_make_result(attack_name=name, status=Status.VULNERABLE,
                                        severity=worst_severity))
        if defended > 0:
            results.append(_make_result(attack_name=name, variant="v2",
                                        status=Status.DEFENDED, severity=Severity.INFO,
                                        evidence="", details=""))
    total = vulnerable + partial + defended + errors
    return Score(
        attack_name=name,
        category=category,
        total_variants=total,
        vulnerable=vulnerable,
        partial=partial,
        defended=defended,
        errors=errors,
        worst_severity=worst_severity,
        results=results,
    )


def _make_summary(scores=None) -> dict:
    if scores is None:
        scores = [
            _make_score("Jailbreak", "ai", vulnerable=2, defended=1,
                        worst_severity=Severity.HIGH),
            _make_score("Auth Bypass", "api", vulnerable=0, defended=3,
                        worst_severity=Severity.INFO),
            _make_score("Prompt Leak", "ai", vulnerable=1, partial=1, defended=0,
                        worst_severity=Severity.CRITICAL),
        ]
    return aggregate_scores(scores)


# ---------------------------------------------------------------------------
# ConsoleReporter
# ---------------------------------------------------------------------------

class TestConsoleReporter:
    def setup_method(self):
        self.reporter = ConsoleReporter()

    def test_print_report_does_not_raise(self):
        """Smoke test: printing a full report should not crash."""
        summary = _make_summary()
        # Redirect console to suppress output during test
        from io import StringIO
        from rich.console import Console
        self.reporter.console = Console(file=StringIO())
        self.reporter.print_report(summary)

    def test_print_report_with_no_findings(self):
        """Report with all defended should show success message."""
        scores = [_make_score("Safe Attack", "ai", vulnerable=0, partial=0,
                              defended=3, worst_severity=Severity.INFO,
                              results=[
                                  _make_result(status=Status.DEFENDED, severity=Severity.INFO,
                                               evidence="", details=""),
                                  _make_result(variant="v2", status=Status.DEFENDED,
                                               severity=Severity.INFO, evidence="", details=""),
                                  _make_result(variant="v3", status=Status.DEFENDED,
                                               severity=Severity.INFO, evidence="", details=""),
                              ])]
        summary = aggregate_scores(scores)
        from io import StringIO
        from rich.console import Console
        buf = StringIO()
        self.reporter.console = Console(file=buf)
        self.reporter.print_report(summary)
        output = buf.getvalue()
        assert "defended" in output.lower() or "All attacks" in output

    def test_print_report_with_vulnerabilities(self):
        """Report with findings should include severity and evidence."""
        summary = _make_summary()
        from io import StringIO
        from rich.console import Console
        buf = StringIO()
        self.reporter.console = Console(file=buf, width=200)
        self.reporter.print_report(summary)
        output = buf.getvalue()
        assert "Security Red Team Report" in output

    def test_print_attack_list_does_not_raise(self):
        """Smoke test: listing attacks should not crash."""
        attacks = [
            {"key": "ai.jailbreak", "name": "Jailbreak", "category": "ai",
             "severity": "high", "description": "Test jailbreak resistance"},
            {"key": "api.auth", "name": "Auth Bypass", "category": "api",
             "severity": "critical", "description": "Test auth controls"},
        ]
        from io import StringIO
        from rich.console import Console
        self.reporter.console = Console(file=StringIO())
        self.reporter.print_attack_list(attacks)

    def test_print_attack_list_output_contains_keys(self):
        """Attack list should show attack keys."""
        attacks = [
            {"key": "ai.jailbreak", "name": "Jailbreak", "category": "ai",
             "severity": "high", "description": "Test jailbreak resistance"},
        ]
        from io import StringIO
        from rich.console import Console
        buf = StringIO()
        self.reporter.console = Console(file=buf, width=200)
        self.reporter.print_attack_list(attacks)
        output = buf.getvalue()
        assert "ai.jailbreak" in output
        assert "Jailbreak" in output

    def test_print_report_empty_scores(self):
        """Edge case: empty score list should not crash."""
        summary = aggregate_scores([])
        from io import StringIO
        from rich.console import Console
        self.reporter.console = Console(file=StringIO())
        self.reporter.print_report(summary)


# ---------------------------------------------------------------------------
# JsonReporter
# ---------------------------------------------------------------------------

class TestJsonReporter:
    def setup_method(self):
        self.reporter = JsonReporter()

    def test_write_report_creates_file(self, tmp_path):
        summary = _make_summary()
        path = self.reporter.write_report(summary, str(tmp_path))
        assert os.path.exists(path)
        assert path.endswith(".json")

    def test_write_report_valid_json(self, tmp_path):
        summary = _make_summary()
        path = self.reporter.write_report(summary, str(tmp_path))
        with open(path) as f:
            data = json.load(f)
        assert isinstance(data, dict)

    def test_report_contains_totals(self, tmp_path):
        summary = _make_summary()
        path = self.reporter.write_report(summary, str(tmp_path))
        with open(path) as f:
            data = json.load(f)
        assert "total_attacks" in data
        assert "total_variants" in data
        assert "total_vulnerable" in data
        assert "total_partial" in data
        assert "total_defended" in data
        assert "total_errors" in data
        assert data["total_attacks"] == 3

    def test_report_contains_severity(self, tmp_path):
        summary = _make_summary()
        path = self.reporter.write_report(summary, str(tmp_path))
        with open(path) as f:
            data = json.load(f)
        assert "worst_severity" in data
        assert data["worst_severity"] in ["critical", "high", "medium", "low", "info"]

    def test_report_contains_findings(self, tmp_path):
        summary = _make_summary()
        path = self.reporter.write_report(summary, str(tmp_path))
        with open(path) as f:
            data = json.load(f)
        assert "findings" in data
        assert isinstance(data["findings"], list)
        assert len(data["findings"]) > 0

    def test_finding_has_required_fields(self, tmp_path):
        summary = _make_summary()
        path = self.reporter.write_report(summary, str(tmp_path))
        with open(path) as f:
            data = json.load(f)
        finding = data["findings"][0]
        assert "attack" in finding
        assert "variant" in finding
        assert "status" in finding
        assert "severity" in finding
        assert "duration_ms" in finding

    def test_report_contains_by_category(self, tmp_path):
        summary = _make_summary()
        path = self.reporter.write_report(summary, str(tmp_path))
        with open(path) as f:
            data = json.load(f)
        assert "by_category" in data
        assert "ai" in data["by_category"]

    def test_report_contains_generated_timestamp(self, tmp_path):
        summary = _make_summary()
        path = self.reporter.write_report(summary, str(tmp_path))
        with open(path) as f:
            data = json.load(f)
        assert "generated" in data

    def test_filename_contains_timestamp(self, tmp_path):
        summary = _make_summary()
        path = self.reporter.write_report(summary, str(tmp_path))
        filename = os.path.basename(path)
        assert filename.startswith("redteam-report-")
        assert filename.endswith(".json")

    def test_empty_summary(self, tmp_path):
        summary = aggregate_scores([])
        path = self.reporter.write_report(summary, str(tmp_path))
        with open(path) as f:
            data = json.load(f)
        assert data["total_attacks"] == 0
        assert data["findings"] == []


# ---------------------------------------------------------------------------
# HtmlReporter
# ---------------------------------------------------------------------------

class TestHtmlReporter:
    def setup_method(self):
        self.reporter = HtmlReporter()

    def test_write_report_creates_file(self, tmp_path):
        summary = _make_summary()
        path = self.reporter.write_report(summary, str(tmp_path))
        assert os.path.exists(path)
        assert path.endswith(".html")

    def test_report_is_valid_html(self, tmp_path):
        summary = _make_summary()
        path = self.reporter.write_report(summary, str(tmp_path))
        with open(path) as f:
            content = f.read()
        assert content.startswith("<!DOCTYPE html>")
        assert "</html>" in content

    def test_report_contains_title(self, tmp_path):
        summary = _make_summary()
        path = self.reporter.write_report(summary, str(tmp_path))
        with open(path) as f:
            content = f.read()
        assert "Security Red Team Report" in content

    def test_report_contains_summary_stats(self, tmp_path):
        summary = _make_summary()
        path = self.reporter.write_report(summary, str(tmp_path))
        with open(path) as f:
            content = f.read()
        assert "Attacks" in content
        assert "Variants" in content
        assert "Vulnerable" in content
        assert "Defended" in content

    def test_report_contains_category_table(self, tmp_path):
        summary = _make_summary()
        path = self.reporter.write_report(summary, str(tmp_path))
        with open(path) as f:
            content = f.read()
        assert "Results by Category" in content
        assert "AI" in content

    def test_report_contains_findings_section(self, tmp_path):
        summary = _make_summary()
        path = self.reporter.write_report(summary, str(tmp_path))
        with open(path) as f:
            content = f.read()
        assert "Findings" in content

    def test_report_contains_css(self, tmp_path):
        summary = _make_summary()
        path = self.reporter.write_report(summary, str(tmp_path))
        with open(path) as f:
            content = f.read()
        assert "<style>" in content
        assert "background:" in content

    def test_filename_contains_timestamp(self, tmp_path):
        summary = _make_summary()
        path = self.reporter.write_report(summary, str(tmp_path))
        filename = os.path.basename(path)
        assert filename.startswith("redteam-report-")
        assert filename.endswith(".html")

    def test_evidence_truncated_in_html(self, tmp_path):
        """Long evidence should be truncated to 500 chars in HTML."""
        long_evidence = "A" * 1000
        results = [_make_result(evidence=long_evidence)]
        scores = [_make_score("Long Evidence", "ai", vulnerable=1, defended=0,
                              worst_severity=Severity.HIGH, results=results)]
        summary = aggregate_scores(scores)
        path = self.reporter.write_report(summary, str(tmp_path))
        with open(path) as f:
            content = f.read()
        # Evidence in template is truncated to 500 chars
        assert "A" * 501 not in content

    def test_empty_summary(self, tmp_path):
        summary = aggregate_scores([])
        path = self.reporter.write_report(summary, str(tmp_path))
        assert os.path.exists(path)
        with open(path) as f:
            content = f.read()
        assert "<!DOCTYPE html>" in content
```

---

## Step 2: Run tests to verify failures

```bash
cd /opt/security-red-team
source venv/bin/activate
python -m pytest tests/test_reporters.py -v 2>&1 | head -60
```

Expected: All tests fail because the reporter modules do not yet exist.

---

## Step 3: Write redteam/reporters/console.py

Create `/opt/security-red-team/redteam/reporters/console.py`:

```python
"""Rich-based console reporter."""

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from datetime import datetime

from ..base import Severity, Status
from ..scoring import severity_color, status_color


class ConsoleReporter:
    def __init__(self):
        self.console = Console()

    def print_report(self, summary: dict):
        """Print full report to terminal."""
        self.console.print()
        self.console.print(Panel.fit(
            f"[bold]Security Red Team Report[/bold]\n"
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"Attacks: {summary['total_attacks']} | Variants: {summary['total_variants']}",
            border_style="blue"
        ))

        # Summary table
        table = Table(title="Results by Category")
        table.add_column("Category", style="bold")
        table.add_column("Attacks", justify="right")
        table.add_column("Vulnerable", justify="right", style="red")
        table.add_column("Partial", justify="right", style="yellow")
        table.add_column("Defended", justify="right", style="green")
        table.add_column("Errors", justify="right", style="magenta")

        for cat, data in summary["by_category"].items():
            table.add_row(
                cat.upper(),
                str(data["attacks"]),
                str(data["vulnerable"]),
                str(data["partial"]),
                str(data["defended"]),
                str(data["errors"]),
            )
        self.console.print(table)

        # Severity breakdown
        sev_table = Table(title="Findings by Severity")
        sev_table.add_column("Severity")
        sev_table.add_column("Count", justify="right")
        for sev, count in summary["by_severity"].items():
            if count > 0:
                color = severity_color(Severity(sev))
                sev_table.add_row(f"[{color}]{sev.upper()}[/]", str(count))
        if any(v > 0 for v in summary["by_severity"].values()):
            self.console.print(sev_table)

        # Detailed findings
        for score in summary["scores"]:
            if not score.has_findings:
                continue
            self.console.print(f"\n[bold]{score.attack_name}[/bold] ({score.category})")
            for r in score.results:
                if r.is_vulnerable:
                    color = status_color(r.status)
                    sev_c = severity_color(r.severity)
                    self.console.print(f"  [{color}]{r.status.value.upper()}[/] [{sev_c}][{r.severity.value}][/] {r.variant}")
                    if r.details:
                        self.console.print(f"    {r.details[:200]}")
                    if r.evidence:
                        self.console.print(f"    Evidence: {r.evidence[:200]}")

        # Verdict
        worst = summary["worst_severity"]
        color = severity_color(worst)
        self.console.print(f"\n[{color}]Overall: {worst.value.upper()} severity findings detected[/]"
                          if summary["total_vulnerable"] > 0
                          else "\n[green bold]All attacks defended![/]")

    def print_attack_list(self, attacks: list[dict]):
        """Print available attacks."""
        table = Table(title="Available Attacks")
        table.add_column("Key", style="bold")
        table.add_column("Name")
        table.add_column("Category")
        table.add_column("Severity")
        table.add_column("Description")
        for a in attacks:
            color = severity_color(Severity(a["severity"]))
            table.add_row(a["key"], a["name"], a["category"], f"[{color}]{a['severity']}[/]", a["description"])
        self.console.print(table)
```

---

## Step 4: Write redteam/reporters/json_report.py

Create `/opt/security-red-team/redteam/reporters/json_report.py`:

```python
"""JSON report generator."""

import json
from datetime import datetime
from pathlib import Path
from ..base import AttackResult, Score


class JsonReporter:
    def write_report(self, summary: dict, output_dir: str) -> str:
        """Write JSON report. Returns file path."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = Path(output_dir) / f"redteam-report-{timestamp}.json"

        report = {
            "generated": datetime.now().isoformat(),
            "total_attacks": summary["total_attacks"],
            "total_variants": summary["total_variants"],
            "total_vulnerable": summary["total_vulnerable"],
            "total_partial": summary["total_partial"],
            "total_defended": summary["total_defended"],
            "total_errors": summary["total_errors"],
            "worst_severity": summary["worst_severity"].value,
            "by_category": summary["by_category"],
            "by_severity": summary["by_severity"],
            "findings": [],
        }

        for score in summary["scores"]:
            for r in score.results:
                report["findings"].append({
                    "attack": r.attack_name,
                    "variant": r.variant,
                    "status": r.status.value,
                    "severity": r.severity.value,
                    "evidence": r.evidence,
                    "details": r.details,
                    "request": r.request,
                    "duration_ms": r.duration_ms,
                })

        path.write_text(json.dumps(report, indent=2, default=str))
        return str(path)
```

---

## Step 5: Write redteam/reporters/html.py

Create `/opt/security-red-team/redteam/reporters/html.py`:

```python
"""HTML report generator using Jinja2."""

from datetime import datetime
from pathlib import Path
from jinja2 import Template

from ..base import Severity


HTML_TEMPLATE = """<!DOCTYPE html>
<html><head>
<meta charset="utf-8">
<title>Security Red Team Report</title>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; max-width: 1200px; margin: 0 auto; padding: 20px; background: #0d1117; color: #c9d1d9; }
  h1 { color: #58a6ff; border-bottom: 1px solid #30363d; padding-bottom: 10px; }
  h2 { color: #8b949e; margin-top: 30px; }
  .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin: 20px 0; }
  .stat { background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 15px; text-align: center; }
  .stat .number { font-size: 2em; font-weight: bold; }
  .stat .label { color: #8b949e; font-size: 0.9em; }
  .critical { color: #f85149; } .high { color: #f0883e; } .medium { color: #d29922; } .low { color: #58a6ff; } .info { color: #8b949e; }
  .vulnerable { color: #f85149; } .partial { color: #d29922; } .defended { color: #3fb950; }
  table { width: 100%; border-collapse: collapse; margin: 15px 0; }
  th, td { padding: 8px 12px; text-align: left; border-bottom: 1px solid #30363d; }
  th { background: #161b22; color: #8b949e; }
  .finding { background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 15px; margin: 10px 0; }
  .finding-header { display: flex; justify-content: space-between; align-items: center; }
  .evidence { background: #0d1117; border: 1px solid #30363d; border-radius: 4px; padding: 10px; margin-top: 10px; font-family: monospace; font-size: 0.85em; white-space: pre-wrap; max-height: 200px; overflow-y: auto; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 0.8em; font-weight: bold; }
  .badge.critical { background: #f8514922; border: 1px solid #f85149; }
  .badge.high { background: #f0883e22; border: 1px solid #f0883e; }
  .badge.medium { background: #d2992222; border: 1px solid #d29922; }
  .badge.low { background: #58a6ff22; border: 1px solid #58a6ff; }
</style>
</head><body>
<h1>Security Red Team Report</h1>
<p>Generated: {{ generated }}</p>

<div class="summary">
  <div class="stat"><div class="number">{{ total_attacks }}</div><div class="label">Attacks</div></div>
  <div class="stat"><div class="number">{{ total_variants }}</div><div class="label">Variants</div></div>
  <div class="stat"><div class="number vulnerable">{{ total_vulnerable }}</div><div class="label">Vulnerable</div></div>
  <div class="stat"><div class="number partial">{{ total_partial }}</div><div class="label">Partial</div></div>
  <div class="stat"><div class="number defended">{{ total_defended }}</div><div class="label">Defended</div></div>
  <div class="stat"><div class="number {{ worst_severity }}">{{ worst_severity | upper }}</div><div class="label">Worst Severity</div></div>
</div>

<h2>Results by Category</h2>
<table>
<tr><th>Category</th><th>Attacks</th><th>Vulnerable</th><th>Partial</th><th>Defended</th><th>Errors</th></tr>
{% for cat, data in by_category.items() %}
<tr><td>{{ cat | upper }}</td><td>{{ data.attacks }}</td><td class="vulnerable">{{ data.vulnerable }}</td><td class="partial">{{ data.partial }}</td><td class="defended">{{ data.defended }}</td><td>{{ data.errors }}</td></tr>
{% endfor %}
</table>

<h2>Findings</h2>
{% for finding in findings %}
{% if finding.status in ['vulnerable', 'partial'] %}
<div class="finding">
  <div class="finding-header">
    <strong>{{ finding.attack }} / {{ finding.variant }}</strong>
    <span class="badge {{ finding.severity }}">{{ finding.severity | upper }}</span>
  </div>
  <p class="{{ finding.status }}">{{ finding.status | upper }}</p>
  {% if finding.details %}<p>{{ finding.details }}</p>{% endif %}
  {% if finding.evidence %}<div class="evidence">{{ finding.evidence[:500] }}</div>{% endif %}
</div>
{% endif %}
{% endfor %}

</body></html>"""


class HtmlReporter:
    def write_report(self, summary: dict, output_dir: str) -> str:
        """Write HTML report. Returns file path."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = Path(output_dir) / f"redteam-report-{timestamp}.html"

        template = Template(HTML_TEMPLATE)

        findings = []
        for score in summary["scores"]:
            for r in score.results:
                findings.append({
                    "attack": r.attack_name,
                    "variant": r.variant,
                    "status": r.status.value,
                    "severity": r.severity.value,
                    "evidence": r.evidence,
                    "details": r.details,
                    "duration_ms": r.duration_ms,
                })

        html = template.render(
            generated=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            total_attacks=summary["total_attacks"],
            total_variants=summary["total_variants"],
            total_vulnerable=summary["total_vulnerable"],
            total_partial=summary["total_partial"],
            total_defended=summary["total_defended"],
            total_errors=summary["total_errors"],
            worst_severity=summary["worst_severity"].value,
            by_category=summary["by_category"],
            by_severity=summary["by_severity"],
            findings=findings,
        )

        path.write_text(html)
        return str(path)
```

---

## Step 6: Run tests to verify passes

```bash
cd /opt/security-red-team
source venv/bin/activate
python -m pytest tests/test_reporters.py -v
```

Expected: All tests pass.

---

## Step 7: Commit

```bash
cd /opt/security-red-team
git add redteam/reporters/console.py redteam/reporters/json_report.py redteam/reporters/html.py tests/test_reporters.py
git commit -m "feat: add reporter modules for console, JSON, and HTML output

- ConsoleReporter: Rich-based terminal output with severity tables and findings
- JsonReporter: machine-readable JSON with all findings and metadata
- HtmlReporter: standalone dark-themed HTML report via Jinja2 templates
- Comprehensive test suite for all three reporters"
```

---

## Acceptance Criteria

- [ ] `tests/test_reporters.py` exists and covers all three reporter classes
- [ ] Tests fail before implementation (TDD red phase)
- [ ] `redteam/reporters/console.py` implements `ConsoleReporter` with `print_report()` and `print_attack_list()`
- [ ] Console report includes summary table, severity breakdown, detailed findings, and overall verdict
- [ ] Console report color-codes severity and status using Rich markup
- [ ] `redteam/reporters/json_report.py` implements `JsonReporter` with `write_report()` returning file path
- [ ] JSON report contains `total_attacks`, `total_variants`, `total_vulnerable`, `worst_severity`, `by_category`, `findings`
- [ ] JSON report filename includes timestamp: `redteam-report-{YYYYMMDD_HHMMSS}.json`
- [ ] `redteam/reporters/html.py` implements `HtmlReporter` with `write_report()` returning file path
- [ ] HTML report is a standalone file with embedded CSS (dark theme, GitHub-inspired)
- [ ] HTML report truncates evidence to 500 characters
- [ ] HTML report filename includes timestamp: `redteam-report-{YYYYMMDD_HHMMSS}.html`
- [ ] All reporters handle empty summaries (zero scores) without crashing
- [ ] All tests pass after implementation
- [ ] Changes committed with descriptive message
