# Malware Scanner Database Schema

**Phase:** 1 - Database Setup
**Status:** Ready for Deployment
**Database:** PostgreSQL blueteam schema

---

## Files

| File | Purpose |
|------|---------|
| `01-malware-schema.sql` | Main schema creation script |
| `01-malware-schema-rollback.sql` | Rollback/cleanup script |
| `deploy-phase1.sh` | Deployment automation script |
| `README.md` | This file |

---

## Schema Overview

### Tables

**1. blueteam.malware_scans**
- Stores metadata about each malware scan execution
- Primary key: `scan_id`
- Tracks: scan type, date, status, files scanned, infections found, duration

**2. blueteam.malware_detections**
- Stores individual malware findings
- Primary key: `detection_id`
- Foreign key: `scan_id` → malware_scans
- Tracks: file path, signature, severity, action taken, resolution status

**3. blueteam.posture_scores** (updated)
- Added column: `malware_score` (NUMERIC 0-100)
- Contributes 10% to overall security posture

### Views

**1. v_latest_scans**
- Latest scan result for each scanner type
- Includes days since last scan

**2. v_active_detections**
- All unresolved malware detections
- Ordered by severity and date

**3. v_detection_summary**
- Count of active detections by severity level

### Functions

**1. calculate_malware_score()**
- Calculates malware defense score (0-100)
- Formula: `100 - (critical×30 + high×20 + medium×10 + low×5)`

**2. get_scan_stats(start_date, end_date)**
- Returns scan statistics for date range
- Default: last 30 days

---

## Deployment

### Prerequisites

- PostgreSQL database with `blueteam` schema
- Database user with CREATE TABLE permissions
- Existing `blueteam.posture_scores` table

### Quick Start

```bash
# Deploy schema
cd /opt/claude-workspace/projects/cyber-guardian/sql
bash deploy-phase1.sh

# Or manual deployment
psql -U blueteam_app -d blueteam -f 01-malware-schema.sql
```

### Environment Variables

Set these if your database is not localhost:

```bash
export DB_HOST=localhost
export DB_PORT=5432
export DB_NAME=blueteam
export DB_USER=blueteam_app
```

### Deployment Output

```
==========================================
Phase 1: Database Schema Deployment
==========================================

Database: blueteam
Host: localhost:5432
User: blueteam_app

Checking database connection...
✓ Database connection successful

Deploying schema...

✓ Malware scanner database schema created successfully
✓ Tables: malware_scans, malware_detections
✓ Views: v_latest_scans, v_active_detections, v_detection_summary
✓ Functions: calculate_malware_score(), get_scan_stats()
✓ Sample data inserted for testing

==========================================
Deployment Successful!
==========================================

Verification:
  Tables created: 2/2
  Views created: 3/3
  Functions created: 2/2
  Sample records: 4

Quick Tests:
  ✓ Malware score: 100.00/100
  ✓ Latest scans: 4 scanner types

Phase 1 Complete!
```

---

## Verification Queries

### Check Tables

```sql
SELECT
    table_name,
    (SELECT COUNT(*) FROM information_schema.columns
     WHERE table_schema = 'blueteam' AND table_name = t.table_name) as columns
FROM information_schema.tables t
WHERE table_schema = 'blueteam'
    AND table_name IN ('malware_scans', 'malware_detections');
```

### Check Indexes

```sql
SELECT indexname, tablename
FROM pg_indexes
WHERE schemaname = 'blueteam'
    AND tablename IN ('malware_scans', 'malware_detections')
ORDER BY tablename, indexname;
```

### View Sample Data

```sql
-- Latest scans
SELECT * FROM blueteam.v_latest_scans;

-- Active detections
SELECT * FROM blueteam.v_active_detections;

-- Malware score
SELECT blueteam.calculate_malware_score();

-- Scan statistics (last 30 days)
SELECT * FROM blueteam.get_scan_stats();
```

---

## Sample Data

The schema includes sample test data:

| Scanner | Status | Files Scanned | Infections |
|---------|--------|---------------|------------|
| clamav | clean | 156,789 | 0 |
| maldet | clean | 1,234 | 0 |
| rkhunter | clean | 0 | 0 |
| chkrootkit | clean | 0 | 0 |

**Note:** This is test data. Real scans will populate via log parser (Phase 2).

---

## Testing

### Insert Test Detection

```sql
-- Create a test detection
INSERT INTO blueteam.malware_detections
(scan_id, file_path, malware_signature, severity, action_taken)
SELECT
    scan_id,
    '/var/www/html/test/malware.php',
    'Php.Webshell.Generic',
    'critical',
    'quarantined'
FROM blueteam.malware_scans
WHERE scan_type = 'clamav'
ORDER BY scan_date DESC
LIMIT 1;

-- Check malware score (should drop from 100)
SELECT blueteam.calculate_malware_score();
-- Result: 70.00 (100 - 30 for critical)

-- View active detections
SELECT * FROM blueteam.v_active_detections;
```

### Resolve Detection

```sql
-- Mark detection as resolved
UPDATE blueteam.malware_detections
SET resolved_at = NOW(),
    resolution_notes = 'False positive - legitimate plugin file'
WHERE detection_id = 1;

-- Check score again (should return to 100)
SELECT blueteam.calculate_malware_score();
```

### Clean Up Test Data

```sql
-- Remove test detection
DELETE FROM blueteam.malware_detections WHERE detection_id = 1;
```

---

## Rollback

### Quick Rollback

```bash
cd /opt/claude-workspace/projects/cyber-guardian/sql
bash deploy-phase1.sh --rollback
```

### Manual Rollback

```bash
psql -U blueteam_app -d blueteam -f 01-malware-schema-rollback.sql
```

**WARNING:** Rollback will DELETE all malware scan data!

---

## Database Schema Diagram

```
┌─────────────────────────────┐
│   malware_scans             │
├─────────────────────────────┤
│ • scan_id (PK)              │
│   scan_type                 │
│   scan_date                 │
│   status                    │
│   files_scanned             │
│   infections_found          │
│   scan_duration_seconds     │
│   log_file_path             │
│   summary (JSONB)           │
│   created_at                │
└──────────┬──────────────────┘
           │
           │ 1:N
           ▼
┌─────────────────────────────┐
│  malware_detections         │
├─────────────────────────────┤
│ • detection_id (PK)         │
│ • scan_id (FK)              │
│   file_path                 │
│   malware_signature         │
│   severity                  │
│   action_taken              │
│   detected_at               │
│   resolved_at               │
│   resolution_notes          │
│   resolver_user_id          │
└─────────────────────────────┘

┌─────────────────────────────┐
│  posture_scores (updated)   │
├─────────────────────────────┤
│   ... (existing columns)    │
│   malware_score (NEW)       │
└─────────────────────────────┘
```

---

## Permissions

Schema grants permissions to `blueteam_app` user:
- SELECT, INSERT, UPDATE, DELETE on tables
- USAGE on sequences
- SELECT on views
- EXECUTE on functions

---

## Next Steps

After successful Phase 1 deployment:

1. ✅ Verify schema with test queries
2. ✅ Review sample data
3. ✅ Test malware score calculation
4. **Proceed to Phase 2:** Log Parser Development

---

## Troubleshooting

### Connection Failed

```bash
# Check PostgreSQL is running
sudo systemctl status postgresql

# Test connection
psql -U blueteam_app -d blueteam -c "SELECT 1"

# Check pg_hba.conf authentication
sudo cat /etc/postgresql/*/main/pg_hba.conf | grep blueteam
```

### Permission Denied

```sql
-- Grant schema usage
GRANT USAGE ON SCHEMA blueteam TO blueteam_app;

-- Grant table permissions
GRANT ALL ON ALL TABLES IN SCHEMA blueteam TO blueteam_app;
GRANT ALL ON ALL SEQUENCES IN SCHEMA blueteam TO blueteam_app;
```

### Table Already Exists

If tables exist from previous deployment:

```bash
# Rollback first
bash deploy-phase1.sh --rollback

# Then deploy again
bash deploy-phase1.sh
```

---

## Support

**Documentation:**
- Main Plan: `/opt/claude-workspace/projects/cyber-guardian/MALWARE_DASHBOARD_INTEGRATION_PLAN.md`
- Schema: `/opt/claude-workspace/projects/cyber-guardian/sql/01-malware-schema.sql`

**Database Schema Documentation:**
```sql
-- View table comments
SELECT
    obj_description((table_schema||'.'||table_name)::regclass::oid, 'pg_class') as description
FROM information_schema.tables
WHERE table_schema = 'blueteam'
    AND table_name IN ('malware_scans', 'malware_detections');

-- View column comments
SELECT
    column_name,
    col_description((table_schema||'.'||table_name)::regclass::oid, ordinal_position) as description
FROM information_schema.columns
WHERE table_schema = 'blueteam'
    AND table_name = 'malware_scans';
```
