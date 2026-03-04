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
