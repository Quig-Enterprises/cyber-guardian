# Import Scan to Database

## Overview

`import-scan-to-db.py` imports hierarchical JSON scan reports into the PostgreSQL `blueteam` schema for trend analysis, compliance tracking, and historical comparison.

**Script:** `/opt/claude-workspace/projects/cyber-guardian/scripts/import-scan-to-db.py`
**Version:** 1.0.0
**Created:** 2026-03-08

---

## Features

- Imports hierarchical JSON reports from `redteam/reports/hierarchical-*.json`
- Populates 3 database tables: `scans`, `scan_attacks`, `findings`
- Supports dry-run validation (no database connection required)
- Handles duplicate detection (skip or force re-import)
- Supports glob patterns for batch import
- Comprehensive error handling and statistics reporting
- Environment variable and CLI argument configuration

---

## Database Schema

### Tables Populated

**1. blueteam.scans**
- Scan metadata and execution context
- Fields: `scan_id`, `target_url`, `target_name`, `target_type`, `environment`, `execution_mode`, `duration_ms`, `report_path`, `status`

**2. blueteam.scan_attacks**
- Attack-level rollup statistics
- Fields: `scan_id`, `attack_id`, `duration_ms`, `variants_tested`, `vulnerable_count`, `partial_count`, `defended_count`, `error_count`

**3. blueteam.findings**
- Individual variant-level findings
- Fields: `scan_id`, `scan_attack_id`, `attack_id`, `variant_id`, `status`, `severity`, `evidence_summary`, `evidence_details`, `evidence_proof` (JSONB), `request_data` (JSONB), `response_data` (JSONB), `recommendation`, `references`

### Foreign Keys

- `scan_attacks.scan_id` → `scans.id`
- `scan_attacks.attack_id` → `attack_catalog.attack_id`
- `findings.scan_id` → `scans.id`
- `findings.scan_attack_id` → `scan_attacks.id`

---

## Usage

### Basic Usage

```bash
# Import single report
python3 scripts/import-scan-to-db.py redteam/reports/hierarchical-20260308_214053.json

# Import most recent report
python3 scripts/import-scan-to-db.py --latest

# Import multiple reports (glob pattern)
python3 scripts/import-scan-to-db.py redteam/reports/hierarchical-*.json
```

### Dry-Run (Validation Only)

```bash
# Validate without database connection
python3 scripts/import-scan-to-db.py --dry-run --latest

# Validate multiple reports
python3 scripts/import-scan-to-db.py --dry-run redteam/reports/*.json

# Verbose dry-run
python3 scripts/import-scan-to-db.py --dry-run --verbose --latest
```

### Force Re-Import

```bash
# Re-import existing scan (deletes and re-inserts)
python3 scripts/import-scan-to-db.py --force --latest

# Re-import all reports
python3 scripts/import-scan-to-db.py --force redteam/reports/hierarchical-*.json
```

### Database Connection Options

```bash
# Using command-line arguments
python3 scripts/import-scan-to-db.py \
  --host localhost \
  --database alfred_admin \
  --user alfred_admin \
  --password 'your-password' \
  --latest

# Using environment variables
export PGHOST=localhost
export PGDATABASE=alfred_admin
export PGUSER=alfred_admin
export PGPASSWORD='your-password'
python3 scripts/import-scan-to-db.py --latest
```

---

## Command-Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `files` | Report files to import (supports globs) | (positional) |
| `--latest` | Import most recent report | false |
| `--host HOST` | Database host | `localhost` or `$PGHOST` |
| `--database DATABASE` | Database name | `alfred_admin` or `$PGDATABASE` |
| `--user USER` | Database user | `alfred_admin` or `$PGUSER` |
| `--password PASSWORD` | Database password | `$PGPASSWORD` |
| `--dry-run` | Validate without inserting | false |
| `--verbose`, `-v` | Enable detailed logging | false |
| `--force` | Re-import existing scans | false |

---

## Output

### Dry-Run Output

```
*** DRY RUN MODE - No data will be inserted ***

Loaded report: redteam/reports/hierarchical-20260308_214053.json
[DRY RUN] Would insert scan: scan-20260308-214053-cd9ff1
  [DRY RUN] Would insert attack: api.account_lockout_bypass
    [DRY RUN] Would insert finding: rapid_attempts (vulnerable)
    [DRY RUN] Would insert finding: ip_rotation (partial)
    [DRY RUN] Would insert finding: rate_limit_header_check (defended)
  [DRY RUN] Would insert attack: api.auth_bypass
    [DRY RUN] Would insert finding: jwt_none_alg (vulnerable)
    [DRY RUN] Would insert finding: weak_secret (defended)

============================================================
Import Statistics
============================================================
Scans imported:     0
Scans skipped:      0
Attacks inserted:   0
Findings inserted:  0
Errors:             0
============================================================
```

### Actual Import Output

```
Connected to PostgreSQL: alfred_admin@localhost/alfred_admin
Loaded report: redteam/reports/hierarchical-20260308_214053.json
Inserted scan: scan-20260308-214053-cd9ff1 (DB ID: 42)
  Inserted attack: api.account_lockout_bypass (DB ID: 123)
    Inserted finding: rapid_attempts (vulnerable)
    Inserted finding: ip_rotation (partial)
    Inserted finding: rate_limit_header_check (defended)
  Inserted attack: api.auth_bypass (DB ID: 124)
    Inserted finding: jwt_none_alg (vulnerable)
    Inserted finding: weak_secret (defended)
Successfully imported: redteam/reports/hierarchical-20260308_214053.json

============================================================
Import Statistics
============================================================
Scans imported:     1
Scans skipped:      0
Attacks inserted:   2
Findings inserted:  5
Errors:             0
============================================================
```

### Duplicate Detection Output

```
SKIPPED: Scan scan-20260308-214053-cd9ff1 already exists (use --force to re-import)

============================================================
Import Statistics
============================================================
Scans imported:     0
Scans skipped:      1
Attacks inserted:   0
Findings inserted:  0
Errors:             0
============================================================
```

---

## Error Handling

### Return Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Import error (partial failure) |
| 2 | Database connection error |
| 3 | File not found |

### Common Errors

**Database Connection Failed**
```
ERROR: Failed to connect to database: connection to server at "localhost" (127.0.0.1), port 5432 failed: fe_sendauth: no password supplied
```
**Solution:** Set `PGPASSWORD` environment variable or use `--password` argument

**File Not Found**
```
ERROR: Files not found: redteam/reports/hierarchical-20260308_999999.json
```
**Solution:** Verify file path or use `--latest` flag

**Invalid JSON Structure**
```
ERROR: Invalid report structure in redteam/reports/hierarchical-broken.json
```
**Solution:** Verify report was generated correctly

**Foreign Key Violation (attack_id not in catalog)**
```
ERROR: Failed to insert attack api.new_attack: insert or update on table "scan_attacks" violates foreign key constraint
```
**Solution:** Ensure `blueteam.attack_catalog` is populated with all attack definitions

---

## Prerequisites

### 1. Database Schema

Ensure the scan registry schema is deployed:

```bash
cd /opt/claude-workspace/projects/cyber-guardian/sql
psql -U alfred_admin -d alfred_admin -f 05-scan-registry-schema.sql
```

### 2. Attack Catalog

Populate the attack catalog from attack module metadata:

```bash
# (Script to populate attack_catalog - to be created)
python3 scripts/build-attack-catalog.py
```

### 3. Python Dependencies

Install required packages:

```bash
cd /opt/claude-workspace/projects/cyber-guardian
source venv/bin/activate
pip install psycopg2-binary
```

---

## Testing

### Run Test Suite

```bash
bash scripts/test-import-scan.sh
```

### Manual Testing

```bash
# 1. Dry-run validation
python3 scripts/import-scan-to-db.py --dry-run --verbose --latest

# 2. Import to database
python3 scripts/import-scan-to-db.py --latest

# 3. Verify import
psql -U alfred_admin -d alfred_admin -c "
SELECT
    s.scan_id,
    s.target_url,
    COUNT(DISTINCT sa.id) as attacks,
    COUNT(f.id) as findings
FROM blueteam.scans s
LEFT JOIN blueteam.scan_attacks sa ON sa.scan_id = s.id
LEFT JOIN blueteam.findings f ON f.scan_id = s.id
WHERE s.scan_id = 'scan-20260308-214053-cd9ff1'
GROUP BY s.scan_id, s.target_url;
"
```

---

## Integration

### Cron Job (Nightly Import)

```bash
# Add to crontab
30 2 * * * cd /opt/claude-workspace/projects/cyber-guardian && \
    /opt/claude-workspace/projects/cyber-guardian/venv/bin/python3 \
    scripts/import-scan-to-db.py --latest >> logs/db-import.log 2>&1
```

### Post-Scan Hook

```bash
# In scripts/run-nightly-scan.sh, after report generation:
echo "Importing scan to database..."
python3 scripts/import-scan-to-db.py "$REPORT_FILE"
```

---

## Data Flow

```
┌─────────────────────────────────────────────────────────────┐
│ 1. Red Team Scanner                                          │
│    └─> redteam/reports/hierarchical-*.json                   │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│ 2. import-scan-to-db.py                                      │
│    ├─> Parse JSON report                                     │
│    ├─> Extract scan metadata                                 │
│    ├─> Extract attack rollups                                │
│    └─> Extract variant findings                              │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│ 3. PostgreSQL blueteam Schema                                │
│    ├─> blueteam.scans (scan metadata)                        │
│    ├─> blueteam.scan_attacks (attack rollups)                │
│    └─> blueteam.findings (variant findings)                  │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│ 4. Blue Team Dashboard                                       │
│    ├─> Trend analysis                                        │
│    ├─> Compliance reporting                                  │
│    ├─> Historical comparison                                 │
│    └─> Regression detection                                  │
└─────────────────────────────────────────────────────────────┘
```

---

## Examples

### Example 1: First-Time Setup and Import

```bash
# 1. Navigate to project
cd /opt/claude-workspace/projects/cyber-guardian

# 2. Activate virtual environment
source venv/bin/activate

# 3. Verify schema is deployed
psql -U alfred_admin -d alfred_admin -c "\dt blueteam.*"

# 4. Test with dry-run
python3 scripts/import-scan-to-db.py --dry-run --verbose --latest

# 5. Import to database
export PGPASSWORD='your-password'
python3 scripts/import-scan-to-db.py --latest

# 6. Verify import
psql -U alfred_admin -d alfred_admin -c "
SELECT scan_id, target_url, scan_date
FROM blueteam.scans
ORDER BY scan_date DESC
LIMIT 5;
"
```

### Example 2: Batch Import Historical Reports

```bash
# Import all reports from last week
python3 scripts/import-scan-to-db.py \
  redteam/reports/hierarchical-202603*.json \
  --verbose

# Review statistics
psql -U alfred_admin -d alfred_admin -c "
SELECT
    DATE(scan_date) as date,
    COUNT(*) as scans,
    SUM((SELECT COUNT(*) FROM blueteam.findings WHERE scan_id = s.id)) as total_findings
FROM blueteam.scans s
GROUP BY DATE(scan_date)
ORDER BY date DESC;
"
```

### Example 3: Re-Import After Schema Change

```bash
# Re-import all scans (use with caution)
python3 scripts/import-scan-to-db.py \
  --force \
  redteam/reports/hierarchical-*.json \
  --verbose
```

---

## Troubleshooting

### Issue: "psycopg2 not installed"

**Solution:**
```bash
cd /opt/claude-workspace/projects/cyber-guardian
source venv/bin/activate
pip install psycopg2-binary
```

### Issue: "Table blueteam.scans does not exist"

**Solution:**
```bash
psql -U alfred_admin -d alfred_admin -f sql/05-scan-registry-schema.sql
```

### Issue: "Foreign key constraint violation (attack_id)"

**Solution:**
```bash
# Populate attack catalog first
python3 scripts/build-attack-catalog.py
```

### Issue: Import succeeds but findings count is wrong

**Check for duplicate variants:**
```sql
SELECT
    attack_id,
    variant_id,
    COUNT(*)
FROM blueteam.findings
WHERE scan_id = (SELECT id FROM blueteam.scans ORDER BY scan_date DESC LIMIT 1)
GROUP BY attack_id, variant_id
HAVING COUNT(*) > 1;
```

---

## Related Documentation

- **Schema:** `/opt/claude-workspace/projects/cyber-guardian/sql/05-scan-registry-schema.sql`
- **Ideal Report Structure:** `/opt/claude-workspace/projects/cyber-guardian/docs/IDEAL_REPORT_STRUCTURE.md`
- **Attack Catalog Builder:** `/opt/claude-workspace/projects/cyber-guardian/scripts/README-build-attack-catalog.md`

---

## Future Enhancements

- [ ] Auto-populate attack_catalog if missing entries detected
- [ ] Support for scan comparison generation (regression detection)
- [ ] Email notifications on import failures
- [ ] Prometheus metrics export
- [ ] Support for incremental imports (only new findings)
- [ ] Archive old scans (retention policy enforcement)

---

**Created:** 2026-03-08
**Version:** 1.0.0
**Maintained by:** CxQ Development Team
