# Lynis CIS Audit Integration

**Version:** 1.0.0
**Date:** 2026-03-10
**Status:** Ready for Deployment

---

## Overview

Lynis integration provides comprehensive CIS (Center for Internet Security) benchmark compliance auditing using the industry-standard Lynis security tool. Results are stored in the blueteam PostgreSQL database alongside compliance scanner and malware scanner data.

**Key Features:**
- Automated CIS benchmark compliance auditing
- Database integration for historical tracking
- Hardening index scoring (0-100)
- Warning and suggestion tracking
- Combined security posture view (compliance + Lynis)
- Trend analysis over time

---

## Architecture

```
┌─────────────┐
│   Lynis     │  (System security auditor)
│   v3.0.9    │
└──────┬──────┘
       │
       ├─ Runs 200+ security tests
       ├─ Generates hardening index
       ├─ Outputs warnings/suggestions
       │
┌──────▼──────────────┐
│  lynis-auditor.py   │  (Python wrapper)
└──────┬──────────────┘
       │
       ├─ Parses Lynis output
       ├─ Extracts findings
       ├─ Calculates metrics
       │
┌──────▼──────────────┐
│  blueteam schema    │  (PostgreSQL)
│  - lynis_audits     │
│  - lynis_findings   │
└─────────────────────┘
```

---

## Database Schema

### Tables

**blueteam.lynis_audits**
- `audit_id` (PK) - Unique audit identifier
- `server_name` - Server being audited
- `audit_date` - When audit was performed
- `hardening_index` - Lynis hardening score (0-100)
- `tests_performed` - Number of security tests run
- `warnings_count` - Total warnings found
- `suggestions_count` - Total suggestions provided

**blueteam.lynis_findings**
- `finding_id` (PK) - Unique finding identifier
- `audit_id` (FK) - References lynis_audits
- `test_id` - Lynis test identifier
- `finding_type` - 'warning' or 'suggestion'
- `severity` - 'high', 'medium', or 'low'
- `description` - Finding description
- `resolved` - Whether addressed (boolean)
- `resolution_notes` - Notes on resolution

### Views

1. **v_latest_lynis_audits** - Most recent audit per server
2. **v_unresolved_lynis_findings** - All unresolved findings
3. **v_lynis_hardening_trend** - Hardening index changes over time
4. **v_security_posture** - Combined compliance + Lynis scores

### Functions

- `get_lynis_stats(server_name)` - Comprehensive statistics
- `resolve_lynis_finding(finding_id, notes)` - Mark finding as resolved

---

## Installation

### Prerequisites

1. **Lynis installed** (already present on alfred)
   ```bash
   lynis show version  # Should show 3.0.9
   ```

2. **Python dependencies** (already satisfied)
   ```bash
   pip3 install psycopg2-binary
   ```

3. **Database schema deployed**
   ```bash
   psql postgresql://eqmon:password@localhost/eqmon -f sql/06-lynis-schema.sql
   ```

### Verification

```bash
# Check tables exist
psql postgresql://eqmon:password@localhost/eqmon -c "
  SELECT tablename FROM pg_tables
  WHERE schemaname = 'blueteam'
  AND tablename LIKE 'lynis%';
"

# Check views exist
psql postgresql://eqmon:password@localhost/eqmon -c "
  SELECT viewname FROM pg_views
  WHERE schemaname = 'blueteam'
  AND viewname LIKE '%lynis%';
"
```

---

## Usage

### Running an Audit

**Method 1: Via wrapper script (recommended)**
```bash
cd /opt/claude-workspace/projects/cyber-guardian
sudo bash scripts/run-lynis-audit.sh alfred
```

**Method 2: Direct Python script**
```bash
cd /opt/claude-workspace/projects/cyber-guardian
sudo python3 scripts/lynis-auditor.py alfred
```

### Multi-Server Audits

```bash
# Audit all three servers
for server in alfred willie peter; do
    echo "Auditing $server..."
    sudo bash scripts/run-lynis-audit.sh $server
    echo ""
done
```

### Output Example

```
================================================================================
LYNIS AUDIT SUMMARY
================================================================================
Server: alfred
Hardening Index: 78/100
Tests Performed: 219
Warnings: 12
Suggestions: 34
================================================================================

View results: SELECT * FROM blueteam.v_latest_lynis_audits WHERE server_name = 'alfred';
================================================================================
```

---

## Database Queries

### View Latest Audits

```sql
-- All servers
SELECT * FROM blueteam.v_latest_lynis_audits;

-- Specific server
SELECT * FROM blueteam.v_latest_lynis_audits
WHERE server_name = 'alfred';
```

### View Unresolved Findings

```sql
-- All findings
SELECT * FROM blueteam.v_unresolved_lynis_findings;

-- High severity only
SELECT * FROM blueteam.v_unresolved_lynis_findings
WHERE severity = 'high';

-- Specific server
SELECT * FROM blueteam.v_unresolved_lynis_findings
WHERE server_name = 'alfred'
ORDER BY severity;
```

### View Security Posture

```sql
-- Combined compliance + Lynis scores
SELECT
    server_name,
    compliance_score,
    lynis_hardening,
    combined_score,
    compliance_issues + lynis_issues as total_issues
FROM blueteam.v_security_posture
ORDER BY combined_score DESC;
```

### View Hardening Trend

```sql
-- Track improvements over time
SELECT
    server_name,
    audit_date,
    hardening_index,
    hardening_change,
    warnings_count,
    suggestions_count
FROM blueteam.v_lynis_hardening_trend
WHERE server_name = 'alfred'
ORDER BY audit_date DESC
LIMIT 10;
```

### Get Comprehensive Statistics

```sql
-- Detailed stats for a server
SELECT * FROM blueteam.get_lynis_stats('alfred');
```

### Resolve Findings

```sql
-- Mark a finding as resolved
SELECT blueteam.resolve_lynis_finding(
    123,  -- finding_id
    'Updated SSH configuration per recommendation. Disabled password auth.'
);

-- Verify resolution
SELECT * FROM blueteam.lynis_findings
WHERE finding_id = 123;
```

---

## Understanding Results

### Hardening Index

The Lynis hardening index is a score from 0-100 indicating overall security posture:

- **90-100:** Excellent - Very few improvements needed
- **80-89:** Good - Minor hardening recommended
- **70-79:** Fair - Several improvements recommended
- **60-69:** Poor - Significant hardening needed
- **0-59:** Critical - Major security concerns

**Industry Benchmarks:**
- Production servers: Target 80+
- Development servers: Target 70+
- Personal systems: Target 60+

### Finding Types

**Warnings:**
- Higher priority security issues
- Should be addressed promptly
- May indicate active vulnerabilities
- Severity: medium to high

**Suggestions:**
- Security improvements and best practices
- Lower priority enhancements
- Hardening recommendations
- Severity: low to medium

### Severity Levels

- **High:** Critical security issues requiring immediate attention
- **Medium:** Important security improvements
- **Low:** Minor enhancements and best practices

---

## Integration with Compliance Scanner

The Lynis integration works alongside the compliance scanner to provide comprehensive security assessment:

**Compliance Scanner:**
- Focused checks (SSH, firewall, Docker, AWS)
- Pass/fail binary results
- Automated daily/weekly scans
- Specific configuration validation

**Lynis Auditor:**
- Comprehensive CIS benchmarks
- Hardening recommendations
- 200+ security tests
- System-wide security posture
- Manual/scheduled execution

**Combined View:**
```sql
SELECT * FROM blueteam.v_security_posture;
```

This view shows:
- Compliance score (0-100)
- Lynis hardening index (0-100)
- Combined score (average)
- Total unresolved issues

---

## Automation

### Cron Schedule (Recommended)

```bash
# Weekly Lynis audits on Sunday at 2 AM
0 2 * * 0 /opt/claude-workspace/projects/cyber-guardian/scripts/run-lynis-audit.sh alfred >> /var/log/lynis-cron.log 2>&1
```

### Multi-Server Cron

```bash
# Audit all servers weekly
0 2 * * 0 for server in alfred willie peter; do /opt/claude-workspace/projects/cyber-guardian/scripts/run-lynis-audit.sh $server; done >> /var/log/lynis-cron.log 2>&1
```

---

## Remote Server Auditing

For remote servers (willie, peter), you have two options:

### Option 1: Run Locally on Each Server

SSH to the server and run audit locally:
```bash
ssh willie
cd /opt/claude-workspace/projects/cyber-guardian
sudo bash scripts/run-lynis-audit.sh willie
```

### Option 2: Remote Execution via SSH

Install Lynis and deploy scripts to remote server:
```bash
# Install on remote server
ssh willie "sudo apt-get install -y lynis"

# Copy scripts
scp scripts/lynis-auditor.py willie:/opt/claude-workspace/projects/cyber-guardian/scripts/
scp scripts/run-lynis-audit.sh willie:/opt/claude-workspace/projects/cyber-guardian/scripts/

# Run remotely
ssh willie "cd /opt/claude-workspace/projects/cyber-guardian && sudo bash scripts/run-lynis-audit.sh willie"
```

---

## Troubleshooting

### Permission Denied

**Problem:** Script fails with permission denied
**Solution:** Run with sudo
```bash
sudo bash scripts/run-lynis-audit.sh alfred
```

### Database Connection Failed

**Problem:** Cannot connect to PostgreSQL
**Solution:** Verify ~/.pgpass file exists and contains eqmon credentials
```bash
cat ~/.pgpass | grep eqmon
# Should show: localhost:5432:eqmon:eqmon:password
```

### Lynis Not Found

**Problem:** `lynis: command not found`
**Solution:** Install Lynis
```bash
sudo apt-get install lynis
```

### Report File Not Found

**Problem:** Warning about /var/log/lynis-report.dat not found
**Solution:** This is expected on first run. Lynis creates it during the audit.

### No Findings Recorded

**Problem:** Audit completes but no findings in database
**Solution:** Check Lynis report permissions and verify database schema
```bash
sudo ls -la /var/log/lynis-report.dat
psql postgresql://eqmon:password@localhost/eqmon -c "\dt blueteam.lynis*"
```

---

## Security Considerations

1. **Sudo Required:** Lynis requires root privileges to perform comprehensive system audits
2. **Report Storage:** Lynis report stored in /var/log/lynis-report.dat (root readable only)
3. **Database Security:** Findings stored in PostgreSQL with standard access controls
4. **Sensitive Data:** Lynis may identify sensitive configuration issues; limit database access appropriately

---

## Performance

- **Audit Duration:** 30-60 seconds per server (depends on system size)
- **Database Impact:** Minimal (small inserts)
- **System Load:** Low (read-only system inspection)
- **Disk Usage:** ~100KB per audit in database

---

## Future Enhancements

1. **Web Dashboard:** Add Lynis results to security dashboard UI
2. **Automated Remediation:** Scripts to fix common findings
3. **Email Alerts:** Notify on hardening index drops or new warnings
4. **Compliance Mapping:** Map Lynis findings to CIS benchmark sections
5. **Comparison Reports:** Side-by-side hardening comparisons between servers
6. **API Endpoint:** RESTful API for Lynis data retrieval

---

## Related Documentation

- Compliance Scanner: `README.md` (Compliance Scanning section)
- Database Schema: `sql/06-lynis-schema.sql`
- Cyber-Guardian README: `README.md`
- Server Scripts: `/opt/claude-workspace/shared-resources/SERVER_SCRIPTS.md`

---

## Support

For issues or questions:
1. Check this documentation
2. Review troubleshooting section
3. Check Lynis logs: `/var/log/lynis.log`
4. Check audit script logs
5. Verify database connectivity

---

**Last Updated:** 2026-03-10
**Version:** 1.0.0
**Status:** Production Ready
