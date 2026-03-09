# Hierarchical JSON Reporter Usage Guide

**Version:** 1.0
**Created:** 2026-03-08
**Module:** `redteam/reporters/hierarchical_json.py`

---

## Overview

The `HierarchicalJsonReporter` generates comprehensive security scan reports in a hierarchical format that preserves the attack → variant relationship and includes complete scan context. This format is designed to replace the flat findings array with a more structured, maintainable report format.

## Key Features

1. **Unique Scan ID**: Each report gets a unique identifier (format: `scan-{timestamp}-{uuid6}`)
2. **Complete Target Metadata**: URL, name, environment, and type information
3. **Execution Context**: Mode, duration, start/end timestamps, operator
4. **Hierarchical Structure**: Attacks contain nested variant arrays
5. **Structured Evidence**: Separate summary, technical details, and machine-readable proof
6. **Compliance Ready**: Placeholder for framework mappings (future enhancement)
7. **Backward Compatible**: Includes flat findings array for legacy systems

---

## Report Structure

```json
{
  "scan_metadata": {
    "scan_id": "scan-20260308-214053-cd9ff1",
    "generated": "2026-03-08T21:40:53.166419",
    "scanner_version": "1.0.0",
    "target": {
      "url": "https://keystone.quigs.com",
      "name": "Project Keystone",
      "environment": "production",
      "type": "app"
    },
    "execution": {
      "mode": "full",
      "duration_ms": 127456.2,
      "start_time": "2026-03-08T18:43:15.000000",
      "end_time": "2026-03-08T21:40:53.166419",
      "operator": "automated"
    }
  },
  "summary": {
    "attacks_executed": 83,
    "variants_tested": 323,
    "findings": {
      "vulnerable": 44,
      "partial": 74,
      "defended": 154,
      "errors": 20,
      "skipped": 31,
      "not_assessed": 0
    },
    "severity": {
      "critical": 9,
      "high": 17,
      "medium": 16,
      "low": 2,
      "info": 0
    },
    "by_category": {
      "api": {
        "attacks": 22,
        "vulnerable": 17,
        "partial": 29,
        "defended": 42,
        "errors": 3,
        "skipped": 0,
        "not_assessed": 0,
        "duration_ms": 2534.5
      }
    }
  },
  "attacks": [
    {
      "attack_id": "api.account_lockout_bypass",
      "name": "Account Lockout Bypass",
      "category": "api",
      "description": "Account Lockout Bypass security test",
      "compliance": [],
      "target_types": ["app"],
      "default_severity": "medium",
      "duration_ms": 60.0,
      "results_summary": {
        "variants_tested": 3,
        "vulnerable": 1,
        "partial": 1,
        "defended": 1,
        "errors": 0,
        "skipped": 0,
        "not_assessed": 0
      },
      "variants": [
        {
          "variant_id": "rapid_attempts",
          "name": "Rapid Attempts",
          "status": "vulnerable",
          "severity": "medium",
          "duration_ms": 20.0,
          "evidence": {
            "summary": "All 10 rapid login failures completed in 0.0s without lockout",
            "technical_details": "No rate limiting detected. Brute-force attacks possible.",
            "proof": {
              "requests_sent": 10,
              "method": "POST",
              "status_codes": [404, 404, 404, 404, 404, 404, 404, 404, 404, 404],
              "lockout_triggered": false
            }
          },
          "request": {
            "endpoint": "/api/auth/login.php",
            "method": "POST",
            "attempts": 10,
            "target_email": "redteam-sysadmin@example.com"
          },
          "response": {
            "status_codes": [404, 404, 404, 404, 404, 404, 404, 404, 404, 404],
            "lockout_headers": null,
            "lockout_triggered": false
          },
          "recommendation": {
            "priority": "medium",
            "remediation": "Address api.account_lockout_bypass vulnerability: All 10 rapid login failures completed in 0.0s without lockout",
            "references": []
          }
        }
      ]
    }
  ],
  "scan_config": {
    "execution_mode": "full",
    "rate_limit_testing": true,
    "rate_limit_test_ip": "203.0.113.99",
    "cleanup_enabled": true,
    "ai_attacker_enabled": true,
    "models": {
      "attacker": "claude-sonnet-4-6",
      "judge": "claude-haiku-4-5-20251001"
    },
    "throttles": {},
    "skip_attacks": []
  },
  "findings": [
    {
      "attack": "api.account_lockout_bypass",
      "variant": "rapid_attempts",
      "status": "vulnerable",
      "severity": "medium",
      "evidence": "All 10 rapid login failures completed in 0.0s without lockout",
      "details": "No rate limiting detected. Brute-force attacks possible.",
      "request": {},
      "response": {},
      "duration_ms": 20.0
    }
  ]
}
```

---

## Usage

### Basic Usage

```python
from redteam.reporters.hierarchical_json import HierarchicalJsonReporter
from redteam.scoring import aggregate_scores

# After running attacks and collecting scores
summary = aggregate_scores(scores)

# Create reporter with configuration
config = {
    "target": {
        "base_url": "https://keystone.quigs.com",
        "name": "Project Keystone",
        "environment": "production",
        "type": "app",
    },
    "execution": {
        "mode": "full",
        "start_time": "2026-03-08T18:43:15.000000",
        "scanner_version": "1.0.0",
    },
}

reporter = HierarchicalJsonReporter(config)
report_path = reporter.write_report(summary, "reports/")
print(f"Report written to: {report_path}")
```

### Integration with Runner

The reporter can be integrated into the existing runner workflow:

```python
from redteam.reporters.hierarchical_json import HierarchicalJsonReporter
from redteam.reporters.json_report import JsonReporter
from redteam.reporters.html import HtmlReporter
from redteam.reporters.console import ConsoleReporter

# In runner.py after collecting scores:
summary = aggregate_scores(scores)

# Generate multiple report formats
reporters = []
if "console" in config.get("reporting", {}).get("formats", []):
    reporters.append(ConsoleReporter())
if "json" in config.get("reporting", {}).get("formats", []):
    reporters.append(JsonReporter())
if "hierarchical" in config.get("reporting", {}).get("formats", []):
    reporters.append(HierarchicalJsonReporter(config))
if "html" in config.get("reporting", {}).get("formats", []):
    reporters.append(HtmlReporter())

output_dir = config.get("reporting", {}).get("output_dir", "reports/")
for reporter in reporters:
    path = reporter.write_report(summary, output_dir)
    print(f"Report: {path}")
```

---

## Configuration Requirements

### Required Config Keys

The reporter expects the following structure in the config dict:

```yaml
target:
  base_url: "https://keystone.quigs.com"  # Required: Target URL
  name: "Project Keystone"                # Optional: Human-readable name
  environment: "production"                # Optional: Environment identifier
  type: "app"                              # Optional: Target type (app/wordpress/generic/cloud)

execution:
  mode: "full"                             # Optional: Execution mode
  start_time: "2026-03-08T18:43:15.000000" # Optional: Scan start time (ISO format)
  scanner_version: "1.0.0"                 # Optional: Scanner version
  rate_limit_testing: true                 # Optional: Rate limit test mode
  rate_limit_test_ip: "203.0.113.99"       # Optional: Test IP for rate limiting

cleanup:
  enabled: true                            # Optional: Cleanup enabled flag

ai_attacker:
  enabled: true                            # Optional: AI attacker enabled
  attacker_model: "claude-sonnet-4-6"      # Optional: Attacker model name
  judge_model: "claude-haiku-4-5"          # Optional: Judge model name
```

### Default Values

If configuration keys are missing, the reporter uses these defaults:

- `target.name`: Falls back to `target.base_url`
- `target.environment`: "unknown"
- `target.type`: "app"
- `execution.mode`: "full"
- `execution.operator`: "automated"
- `scanner_version`: "1.0.0"

---

## Output Location

Reports are written to: `{output_dir}/hierarchical-{timestamp}.json`

Example: `reports/hierarchical-20260308_214053.json`

---

## Data Flow

```
Attack Modules
    ↓
AttackResult objects
    ↓
Score objects (via attack.score())
    ↓
Summary dict (via aggregate_scores())
    ↓
HierarchicalJsonReporter
    ↓
JSON report file
```

---

## Evidence Structure

Each variant includes a structured `evidence` object:

```json
{
  "summary": "Human-readable summary of the finding",
  "technical_details": "Technical explanation for security teams",
  "proof": {
    "requests_sent": 10,
    "method": "POST",
    "status_codes": [404, 404, 404],
    "lockout_triggered": false
  }
}
```

The `proof` field is automatically populated from `request` and `response` data where available.

---

## Recommendation Structure

Each variant includes a `recommendation` object:

```json
{
  "priority": "high",
  "remediation": "Implement account lockout after 5 failed attempts within 15 minutes",
  "references": [
    "https://pages.nist.gov/800-63-3/sp800-63b.html#memsecretver",
    "https://owasp.org/www-community/controls/Blocking_Brute_Force_Attacks"
  ]
}
```

Currently, `references` is a placeholder. Future enhancements will populate this from attack metadata.

---

## Future Enhancements

### Phase 1: Attack Catalog Integration
- Query attack descriptions from attack_catalog table
- Populate compliance mappings from attack_compliance table
- Extract target_types from attack metadata
- Add attack references/documentation links

### Phase 2: Enhanced Recommendations
- Populate remediation references from NIST/OWASP documentation
- Add CVE references for known vulnerabilities
- Include fix verification steps
- Link to internal remediation runbooks

### Phase 3: Scan History & Comparison
- Add baseline_scan_id for comparison tracking
- Include regression detection (fixed → vulnerable again)
- Add improvement tracking (vulnerable → defended)
- Generate trend data for dashboards

### Phase 4: Database Integration
- Import reports into blueteam.scans table
- Link findings to mitigation_projects
- Enable historical tracking and comparison queries
- Support re-scan verification workflows

---

## Testing

Run the test suite to verify the reporter:

```bash
cd /opt/claude-workspace/projects/cyber-guardian
python3 redteam/tests/test_hierarchical_reporter.py
```

Expected output:
```
Testing HierarchicalJsonReporter...
✓ Report generated: .../hierarchical-20260308_214053.json
✓ Found required key: scan_metadata
✓ Found required key: summary
✓ Found required key: attacks
✓ Found required key: scan_config
✓ Found required key: findings
✓ Scan ID: scan-20260308-214053-cd9ff1
✓ Target and execution metadata correct
✓ Summary statistics correct
✓ Found 2 attacks
✓ Attack 1 has 3 variants
✓ Variant structure complete
✓ Evidence structure correct
✓ Recommendation structure correct
✓ Scan config captured
✓ Backward-compatible findings array present

✓ All tests passed!
```

---

## Backward Compatibility

The reporter maintains backward compatibility by including a flat `findings` array identical to the legacy JsonReporter format. This ensures existing import scripts and dashboards continue to work while new systems can leverage the hierarchical structure.

Legacy systems can ignore the hierarchical `attacks` array and continue using `findings[]`.

New systems should use the `attacks[]` array for better data organization and querying capabilities.

---

## Related Documentation

- **IDEAL_REPORT_STRUCTURE.md**: Architectural rationale and database schema
- **redteam/reporters/json_report.py**: Legacy flat reporter (backward compatible)
- **redteam/scoring.py**: Summary aggregation logic
- **redteam/base.py**: AttackResult and Score data structures
