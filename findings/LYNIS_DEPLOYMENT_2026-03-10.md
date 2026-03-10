# Lynis CIS Audit Deployment

**Date:** 2026-03-10
**Component:** Lynis CIS Auditing System
**Status:** ✅ DEPLOYED - Ready for Execution
**Version:** 1.0.0

---

## Executive Summary

Successfully deployed comprehensive CIS benchmark compliance auditing system using Lynis security tool. Integrates with existing blueteam database schema and complements the compliance scanner with 200+ security tests and hardening index scoring.

**Status:** Infrastructure deployed and ready for first audit runs
**Next Step:** Execute audits on all three servers (alfred, willie, peter)

---

## Deployment Summary

### Components Deployed

**1. Lynis Auditor Script (256 lines)**
- File: `scripts/lynis-auditor.py`
- Purpose: Python wrapper for Lynis security tool
- Features:
  - Runs Lynis system audit
  - Parses output and extracts findings
  - Calculates hardening index
  - Stores results in PostgreSQL database
  - Classifies warnings and suggestions by severity

**2. Sudo Wrapper Script**
- File: `scripts/run-lynis-audit.sh`
- Purpose: Execute Lynis with required sudo privileges
- Usage: `sudo bash scripts/run-lynis-audit.sh <server-name>`

**3. Database Schema (230 lines)**
- File: `sql/06-lynis-schema.sql`
- Deployed to: eqmon.blueteam schema
- Tables: 2 (lynis_audits, lynis_findings)
- Views: 4 (latest, unresolved, trend, security posture)
- Functions: 2 (get_stats, resolve_finding)

**4. Documentation (420 lines)**
- File: `docs/LYNIS_INTEGRATION.md`
- Comprehensive usage guide
- Troubleshooting section
- Database query examples
- Integration details

**5. README Updates**
- Version bumped: 1.2.0 → 1.3.0
- Added Lynis section
- Updated features list
- Added database query examples

---

## Database Schema Details

### Tables

**blueteam.lynis_audits**
```sql
CREATE TABLE blueteam.lynis_audits (
    audit_id SERIAL PRIMARY KEY,
    server_name VARCHAR(255) NOT NULL,
    audit_date TIMESTAMP NOT NULL DEFAULT NOW(),
    hardening_index INTEGER NOT NULL DEFAULT 0,
    tests_performed INTEGER NOT NULL DEFAULT 0,
    warnings_count INTEGER NOT NULL DEFAULT 0,
    suggestions_count INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);
```

**blueteam.lynis_findings**
```sql
CREATE TABLE blueteam.lynis_findings (
    finding_id SERIAL PRIMARY KEY,
    audit_id INTEGER NOT NULL REFERENCES blueteam.lynis_audits(audit_id),
    test_id VARCHAR(255) NOT NULL,
    finding_type VARCHAR(50) NOT NULL,  -- 'warning', 'suggestion'
    severity VARCHAR(20) NOT NULL,      -- 'high', 'medium', 'low'
    description TEXT NOT NULL,
    resolved BOOLEAN NOT NULL DEFAULT FALSE,
    resolved_date TIMESTAMP,
    resolution_notes TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);
```

### Views

**1. v_latest_lynis_audits**
- Most recent audit for each server
- Includes unresolved findings count
- Quick overview of current state

**2. v_unresolved_lynis_findings**
- All unresolved findings from latest audits
- Sorted by severity and server
- Actionable remediation list

**3. v_lynis_hardening_trend**
- Hardening index changes over time
- Shows improvement/degradation
- Per-server trending

**4. v_security_posture (COMBINED VIEW)**
- **Integrates compliance scanner + Lynis results**
- Shows both compliance score and hardening index
- Calculates combined security score
- Total unresolved issues across both systems
- **This is the master security dashboard view**

### Functions

**1. get_lynis_stats(server_name)**
- Returns comprehensive statistics for a server
- Latest and previous hardening index
- Change calculation
- Warnings and suggestions counts
- Unresolved findings count

**2. resolve_lynis_finding(finding_id, notes)**
- Mark a finding as resolved
- Add resolution notes
- Track resolution date
- Audit trail for remediation work

---

## Integration with Compliance Scanner

The Lynis integration complements the existing compliance scanner:

| Aspect | Compliance Scanner | Lynis Auditor |
|--------|-------------------|---------------|
| **Focus** | Specific configurations | System-wide hardening |
| **Tests** | ~10-15 checks | 200+ security tests |
| **Output** | Pass/Fail | Hardening index 0-100 |
| **Scope** | SSH, firewall, Docker, AWS | Full CIS benchmarks |
| **Frequency** | Automated daily/weekly | Manual/scheduled |
| **Integration** | blueteam.compliance_scans | blueteam.lynis_audits |

**Combined View:**
```sql
SELECT
    server_name,
    compliance_score,      -- From compliance scanner (0-100)
    lynis_hardening,       -- From Lynis (0-100)
    combined_score,        -- Average of both
    compliance_issues,     -- Critical+high+medium findings
    lynis_issues           -- Warnings + suggestions
FROM blueteam.v_security_posture
ORDER BY combined_score DESC;
```

This provides a comprehensive security posture assessment combining:
- Configuration compliance (compliance scanner)
- System hardening (Lynis CIS benchmarks)
- Combined score and issue counts

---

## Usage Instructions

### Run Local Audit

```bash
cd /opt/claude-workspace/projects/cyber-guardian
sudo bash scripts/run-lynis-audit.sh alfred
```

### Run Remote Audit

**Option 1: SSH and run locally**
```bash
ssh willie
cd /opt/claude-workspace/projects/cyber-guardian
sudo bash scripts/run-lynis-audit.sh willie
```

**Option 2: Deploy scripts to remote server**
```bash
# Install Lynis on remote server
ssh willie "sudo apt-get install -y lynis"

# Copy scripts
scp scripts/lynis-auditor.py willie:/opt/claude-workspace/projects/cyber-guardian/scripts/
scp scripts/run-lynis-audit.sh willie:/opt/claude-workspace/projects/cyber-guardian/scripts/

# Run remotely
ssh willie "cd /opt/claude-workspace/projects/cyber-guardian && sudo bash scripts/run-lynis-audit.sh willie"
```

### Audit All Servers

```bash
for server in alfred willie peter; do
    echo "Auditing $server..."
    sudo bash scripts/run-lynis-audit.sh $server
    echo ""
done
```

---

## Expected Output

```
==================================
Lynis Security Audit
==================================
Server: alfred
Date: Mon Mar 10 01:45:23 CDT 2026
==================================

2026-03-10 01:45:23 - lynis-auditor - INFO - Starting Lynis audit for alfred
2026-03-10 01:45:53 - lynis-auditor - INFO - Audit complete: 46 findings
2026-03-10 01:45:53 - lynis-auditor - INFO - Database connection established
2026-03-10 01:45:53 - lynis-auditor - INFO - Inserted audit record: audit_id=1
2026-03-10 01:45:53 - lynis-auditor - INFO - Inserted 46 findings
2026-03-10 01:45:53 - lynis-auditor - INFO - Hardening index: 78/100
2026-03-10 01:45:53 - lynis-auditor - INFO - Warnings: 12
2026-03-10 01:45:53 - lynis-auditor - INFO - Suggestions: 34
2026-03-10 01:45:53 - lynis-auditor - INFO - Database connection closed

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

## Database Verification Queries

**View latest audits:**
```sql
SELECT
    server_name,
    audit_date,
    hardening_index,
    tests_performed,
    warnings_count,
    suggestions_count,
    unresolved_findings
FROM blueteam.v_latest_lynis_audits
ORDER BY server_name;
```

**View combined security posture:**
```sql
SELECT * FROM blueteam.v_security_posture;
```

**View unresolved findings:**
```sql
SELECT
    server_name,
    severity,
    test_id,
    description
FROM blueteam.v_unresolved_lynis_findings
WHERE server_name = 'alfred'
ORDER BY
    CASE severity
        WHEN 'high' THEN 1
        WHEN 'medium' THEN 2
        WHEN 'low' THEN 3
    END;
```

**Get comprehensive statistics:**
```sql
SELECT * FROM blueteam.get_lynis_stats('alfred');
```

---

## Hardening Index Interpretation

| Score Range | Rating | Action Required |
|-------------|--------|-----------------|
| 90-100 | Excellent | Minimal improvements needed |
| 80-89 | Good | Minor hardening recommended |
| 70-79 | Fair | Several improvements recommended |
| 60-69 | Poor | Significant hardening needed |
| 0-59 | Critical | Major security overhaul required |

**Industry Benchmarks:**
- Production servers: **Target 80+**
- Development servers: **Target 70+**
- Personal systems: **Target 60+**

---

## Next Steps

### Immediate (This Session)

1. **Run initial audit on alfred**
   ```bash
   sudo bash scripts/run-lynis-audit.sh alfred
   ```

2. **Verify database integration**
   ```sql
   SELECT * FROM blueteam.v_latest_lynis_audits WHERE server_name = 'alfred';
   ```

3. **Review findings and create remediation plan**
   ```sql
   SELECT * FROM blueteam.v_unresolved_lynis_findings WHERE server_name = 'alfred';
   ```

### Short-Term (Next 7 Days)

4. **Run audits on willie and peter**
   ```bash
   ssh willie "cd /opt/claude-workspace/projects/cyber-guardian && sudo bash scripts/run-lynis-audit.sh willie"
   ```

5. **Address high-severity findings**
   - Review warnings from all servers
   - Prioritize by severity and impact
   - Create mitigation tasks

6. **Configure automated audits**
   - Add to cron for weekly execution
   - Set up email alerts for hardening index drops

### Medium-Term (Next 30 Days)

7. **Implement dashboard UI integration**
   - Add Lynis tab to security dashboard
   - Display hardening index and trends
   - Show combined security posture

8. **Establish baseline and targets**
   - Document initial hardening scores
   - Set target scores for each server
   - Track improvement over time

9. **Create remediation workflow**
   - Document common findings and fixes
   - Create scripts for automated remediation
   - Track resolution progress in database

---

## Automation

### Weekly Cron Job

```bash
# Add to root crontab
sudo crontab -e

# Weekly Lynis audit on Sunday at 2 AM
0 2 * * 0 /opt/claude-workspace/projects/cyber-guardian/scripts/run-lynis-audit.sh alfred >> /var/log/lynis-cron.log 2>&1

# Audit all servers (if needed)
0 2 * * 0 for server in alfred willie peter; do /opt/claude-workspace/projects/cyber-guardian/scripts/run-lynis-audit.sh $server; done >> /var/log/lynis-cron.log 2>&1
```

---

## Troubleshooting

**Problem: Permission denied when running script**
- Solution: Run with sudo: `sudo bash scripts/run-lynis-audit.sh alfred`

**Problem: Database connection failed**
- Solution: Verify ~/.pgpass exists with eqmon credentials
- Check: `cat ~/.pgpass | grep eqmon`

**Problem: Lynis not found**
- Solution: Install Lynis: `sudo apt-get install lynis`
- Verify: `lynis show version`

**Problem: No findings recorded**
- Solution: Check /var/log/lynis-report.dat exists
- Permissions: `sudo ls -la /var/log/lynis-report.dat`

---

## Git Commit

**Commit:** ad52209
**Message:** Add Lynis CIS audit integration for comprehensive system hardening

**Files Added:**
- scripts/lynis-auditor.py (256 lines)
- scripts/run-lynis-audit.sh
- sql/06-lynis-schema.sql (230 lines)
- docs/LYNIS_INTEGRATION.md (420 lines)

**Files Modified:**
- README.md (version 1.2.0 → 1.3.0)

**Total Lines:** ~1,237 insertions

---

## Success Criteria

- ✅ Database schema deployed to eqmon.blueteam
- ✅ Python auditor script created and executable
- ✅ Sudo wrapper script created
- ✅ Documentation complete
- ✅ README updated with Lynis section
- ✅ Git commit pushed
- ⏳ **Pending:** First audit execution on alfred
- ⏳ **Pending:** Audits on willie and peter
- ⏳ **Pending:** Remediation plan creation

---

## References

- Complete Documentation: `docs/LYNIS_INTEGRATION.md`
- Database Schema: `sql/06-lynis-schema.sql`
- Python Script: `scripts/lynis-auditor.py`
- Wrapper Script: `scripts/run-lynis-audit.sh`
- README: `README.md` (v1.3.0)
- Compliance Scanner: `findings/COMPLIANCE_TEST_REPORT_2026-03-10.md`
- Mitigation Summary: `findings/MITIGATION_SUMMARY_2026-03-10.md`

---

## Notes

**Lynis Version:** 3.0.9 (already installed on alfred)
**Database:** eqmon.blueteam schema (integrated with compliance scanner)
**Execution:** Requires sudo privileges (reads system configuration files)
**Duration:** 30-60 seconds per audit
**Storage:** ~100KB per audit in database

**Integration Point:**
The v_security_posture view provides a unified dashboard combining:
- Compliance scanner results (specific configuration checks)
- Lynis audit results (comprehensive CIS benchmarks)
- Combined security score
- Total unresolved issues across both systems

This creates a complete security assessment framework covering both targeted compliance checks and broad system hardening.

---

**Deployment Status:** ✅ COMPLETE
**Ready for Execution:** YES
**Next Action:** Run first audit on alfred

---

**End of Report**
