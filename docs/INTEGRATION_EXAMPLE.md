# HierarchicalJsonReporter Integration Example

This document shows how to integrate the HierarchicalJsonReporter into the existing redteam scanner workflow.

## Adding to config.yaml

Add "hierarchical" to the reporting formats:

```yaml
reporting:
  formats: ["console", "json", "hierarchical", "html"]
  output_dir: "reports/"
```

## Updating runner.py

Modify the reporter initialization section in `runner.py`:

```python
# Import the new reporter
from redteam.reporters.hierarchical_json import HierarchicalJsonReporter
from redteam.reporters.json_report import JsonReporter
from redteam.reporters.html import HtmlReporter
from redteam.reporters.console import ConsoleReporter

# ... existing code ...

async def run_scan(config: dict):
    """Run security scan with configured reporters."""

    # Add start_time to execution metadata
    config["execution"]["start_time"] = datetime.now().isoformat()

    # ... run attacks and collect scores ...

    # Aggregate results
    summary = aggregate_scores(scores)

    # Generate reports
    output_dir = config.get("reporting", {}).get("output_dir", "reports/")
    formats = config.get("reporting", {}).get("formats", ["console"])

    for format_name in formats:
        if format_name == "console":
            reporter = ConsoleReporter()
            reporter.write_report(summary, output_dir)

        elif format_name == "json":
            reporter = JsonReporter()
            path = reporter.write_report(summary, output_dir)
            print(f"JSON report: {path}")

        elif format_name == "hierarchical":
            reporter = HierarchicalJsonReporter(config)
            path = reporter.write_report(summary, output_dir)
            print(f"Hierarchical report: {path}")

        elif format_name == "html":
            reporter = HtmlReporter()
            path = reporter.write_report(summary, output_dir)
            print(f"HTML report: {path}")

    return summary
```

## Standalone Usage

You can also use the reporter standalone after a scan:

```python
#!/usr/bin/env python3
"""Generate hierarchical report from existing scan data."""

import yaml
from redteam.reporters.hierarchical_json import HierarchicalJsonReporter
from redteam.scoring import aggregate_scores

# Load configuration
with open("config.yaml") as f:
    config = yaml.safe_load(f)

# Assume scores are already collected from a scan
# scores = [score1, score2, ...]

summary = aggregate_scores(scores)

# Generate hierarchical report
reporter = HierarchicalJsonReporter(config)
report_path = reporter.write_report(summary, "reports/")

print(f"Hierarchical report generated: {report_path}")
```

## Database Import

The hierarchical report can be imported into the blueteam schema (future enhancement):

```python
#!/usr/bin/env python3
"""Import hierarchical report into database."""

import json
import psycopg2
from datetime import datetime

def import_hierarchical_report(report_path: str, db_config: dict):
    """Import hierarchical report into blueteam.scans table."""

    with open(report_path) as f:
        report = json.load(f)

    conn = psycopg2.connect(**db_config)
    cursor = conn.cursor()

    # Insert scan record
    scan_metadata = report["scan_metadata"]
    cursor.execute("""
        INSERT INTO blueteam.scans (
            scan_id, target_url, target_name, target_type, environment,
            scanner_version, config_hash, execution_mode, scan_date,
            duration_ms, report_path, status
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        RETURNING id
    """, (
        scan_metadata["scan_id"],
        scan_metadata["target"]["url"],
        scan_metadata["target"]["name"],
        scan_metadata["target"]["type"],
        scan_metadata["target"]["environment"],
        scan_metadata["scanner_version"],
        scan_metadata["config_hash"],
        scan_metadata["execution"]["mode"],
        scan_metadata["generated"],
        scan_metadata["execution"]["duration_ms"],
        report_path,
        "completed"
    ))

    scan_id = cursor.fetchone()[0]

    # Insert attack results
    for attack in report["attacks"]:
        cursor.execute("""
            INSERT INTO blueteam.scan_attacks (
                scan_id, attack_id, duration_ms, variants_tested,
                vulnerable_count, partial_count, defended_count, error_count
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id
        """, (
            scan_id,
            attack["attack_id"],
            attack["duration_ms"],
            attack["results_summary"]["variants_tested"],
            attack["results_summary"]["vulnerable"],
            attack["results_summary"]["partial"],
            attack["results_summary"]["defended"],
            attack["results_summary"]["errors"]
        ))

        scan_attack_id = cursor.fetchone()[0]

        # Insert variant findings
        for variant in attack["variants"]:
            cursor.execute("""
                INSERT INTO blueteam.findings (
                    scan_id, scan_attack_id, attack_id, variant_id, variant_name,
                    status, severity, duration_ms,
                    evidence_summary, evidence_details, evidence_proof,
                    request_data, response_data,
                    recommendation, priority, references
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                scan_id,
                scan_attack_id,
                attack["attack_id"],
                variant["variant_id"],
                variant["name"],
                variant["status"],
                variant["severity"],
                variant["duration_ms"],
                variant["evidence"]["summary"],
                variant["evidence"]["technical_details"],
                json.dumps(variant["evidence"]["proof"]),
                json.dumps(variant["request"]),
                json.dumps(variant["response"]),
                variant["recommendation"]["remediation"],
                variant["recommendation"]["priority"],
                variant["recommendation"]["references"]
            ))

    conn.commit()
    cursor.close()
    conn.close()

    print(f"Imported scan {scan_metadata['scan_id']} to database")

# Usage
if __name__ == "__main__":
    db_config = {
        "host": "localhost",
        "database": "eqmon",
        "user": "eqmon",
        "password": "..."
    }

    import_hierarchical_report(
        "reports/hierarchical-20260308_214053.json",
        db_config
    )
```

## Comparison with Legacy Format

### Legacy JsonReporter Output

```json
{
  "generated": "2026-03-08T18:45:40.017192",
  "total_attacks": 83,
  "findings": [
    {"attack": "api.account_lockout_bypass", "variant": "rapid_attempts", ...},
    {"attack": "api.account_lockout_bypass", "variant": "ip_rotation", ...}
  ]
}
```

**Issues:**
- No scan identification
- No target metadata
- Flat findings array requires string matching to group variants
- No execution context

### HierarchicalJsonReporter Output

```json
{
  "scan_metadata": {
    "scan_id": "scan-20260308-214053-cd9ff1",
    "target": {"url": "...", "name": "...", "environment": "..."},
    "execution": {"mode": "...", "duration_ms": 127456.2, ...}
  },
  "attacks": [
    {
      "attack_id": "api.account_lockout_bypass",
      "category": "api",
      "results_summary": {"variants_tested": 3, "vulnerable": 1, ...},
      "variants": [
        {"variant_id": "rapid_attempts", ...},
        {"variant_id": "ip_rotation", ...}
      ]
    }
  ],
  "findings": [...]  // Backward compatible
}
```

**Benefits:**
- Unique scan identification
- Complete target and execution context
- Hierarchical structure preserves relationships
- Easier to query and analyze
- Database-ready format
- Backward compatible with legacy systems
