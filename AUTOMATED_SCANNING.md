# Automated Security Scanning

**Status:** ✅ ACTIVE
**Schedule:** Hourly (at minute 0 of every hour)
**Last Updated:** 2026-03-07

---

## Overview

The Blue Team Codebase Security Scanner runs automatically every hour to monitor for new security vulnerabilities across all WordPress plugins, mu-plugins, and development projects.

**Performance:**
- Scan duration: ~45 seconds
- Files scanned: 23,360 PHP files
- Projects scanned: 64
- Overhead: Minimal (runs during minute 0 of each hour)

---

## Automated Monitoring

### Cron Schedule

```cron
0 * * * * /opt/claude-workspace/projects/cyber-guardian/scripts/hourly-security-scan.sh >> /opt/claude-workspace/projects/cyber-guardian/.scan-state/cron.log 2>&1
```

**Schedule:** Every hour at minute 0 (12:00 AM, 1:00 AM, 2:00 AM, etc.)

### What Gets Monitored

**Scanned Locations:**
- `/var/www/html/wordpress/wp-content/plugins/*` - All WordPress plugins
- `/var/www/html/wordpress/wp-content/mu-plugins/*` - Must-use plugins
- `/opt/claude-workspace/projects/*` - Development projects

**Vulnerability Categories:**
1. SQL Injection (CWE-89)
2. Cross-Site Scripting (XSS) (CWE-79)
3. File Upload Vulnerabilities (CWE-434)
4. Path Traversal (CWE-22)
5. Hardcoded Credentials (CWE-798)
6. Weak Cryptography (CWE-327)
7. Insecure Deserialization (CWE-502)

---

## Alert System

### Severity Change Detection

The scanner automatically detects and logs when issue counts change:

**Alert Triggers:**
- ✅ **CRITICAL issues increase** - Immediate attention required
- ✅ **HIGH issues increase** - Review recommended
- ✅ **Total issues decrease** - Logged as improvement

**Alert Output:**
```
[2026-03-07 09:19:13] ALERT: Severity increased!
[2026-03-07 09:19:13]   CRITICAL: 3408 → 3410 (+2)
[2026-03-07 09:19:13]   HIGH: 114 → 116 (+2)
```

### Future Alert Integrations

The script includes a TODO for external notifications:

```bash
# TODO: Send email/Slack notification here
# Example: send-alert.sh "Security scan: +$CRITICAL_DIFF CRITICAL, +$HIGH_DIFF HIGH issues"
```

**Recommended Integrations:**
- Email notifications to security team
- Slack/Teams webhooks
- PagerDuty for CRITICAL severity increases
- Integration with existing monitoring systems

---

## Reports

### Report Generation

**Location:** `/opt/claude-workspace/projects/cyber-guardian/reports/`

**Format:**
- `codebase-security-scan-YYYYMMDD_HHMMSS.json` - Machine-readable
- `codebase-security-scan-YYYYMMDD_HHMMSS.md` - Human-readable

**Retention:** 7 days (168 hours) - older reports are automatically deleted

**Example Report Files:**
```
reports/codebase-security-scan-20260307_085551.json
reports/codebase-security-scan-20260307_085551.md
```

### Viewing Reports

**Latest scan summary:**
```bash
tail -20 /opt/claude-workspace/projects/cyber-guardian/.scan-state/scan.log
```

**Current issue counts:**
```bash
cat /opt/claude-workspace/projects/cyber-guardian/.scan-state/latest-counts.txt
# Output: CRITICAL HIGH MEDIUM TOTAL
# Example: 3410 116 545 4071
```

**Full report:**
```bash
# Find latest report
LATEST=$(ls -t /opt/claude-workspace/projects/cyber-guardian/reports/*.md | head -1)
less "$LATEST"
```

**JSON query examples:**
```bash
LATEST_JSON=$(ls -t /opt/claude-workspace/projects/cyber-guardian/reports/*.json | head -1)

# Summary statistics
jq '.summary' "$LATEST_JSON"

# All XSS vulnerabilities
jq '.projects[].issues[] | select(.category == "xss")' "$LATEST_JSON"

# Issues in specific plugin
jq '.projects[] | select(.name == "cxq-facebot")' "$LATEST_JSON"
```

---

## Log Files

### Scan Logs

**Location:** `/opt/claude-workspace/projects/cyber-guardian/.scan-state/scan.log`

**Content:**
- Scan start/completion timestamps
- Issue count summaries
- Severity change alerts
- Error messages (if any)

**Example:**
```
[2026-03-07 09:24:28] Starting hourly security scan...
[2026-03-07 09:25:09] Scan complete: 4071 issues (3410 CRITICAL, 116 HIGH, 545 MEDIUM)
[2026-03-07 09:25:09] Hourly scan complete
```

### Cron Logs

**Location:** `/opt/claude-workspace/projects/cyber-guardian/.scan-state/cron.log`

**Content:**
- Redirected stdout/stderr from cron execution
- Any errors during automated runs

**View recent cron activity:**
```bash
tail -50 /opt/claude-workspace/projects/cyber-guardian/.scan-state/cron.log
```

---

## Maintenance

### Manual Scan

**Run scanner immediately:**
```bash
cd /opt/claude-workspace/projects/cyber-guardian
python3 blueteam/cli_codebase_scan.py
```

**Run with hourly script (includes state tracking):**
```bash
/opt/claude-workspace/projects/cyber-guardian/scripts/hourly-security-scan.sh
```

### View Cron Job

**Check current schedule:**
```bash
crontab -l | grep hourly-security-scan
```

### Disable Automated Scanning

**Temporary (until next reboot):**
```bash
crontab -e
# Comment out the hourly-security-scan.sh line with #
```

**Permanent:**
```bash
crontab -e
# Delete the hourly-security-scan.sh line
```

### Re-enable Automated Scanning

**If accidentally removed:**
```bash
/tmp/install-hourly-scan-cron.sh
```

Or manually add to crontab:
```cron
0 * * * * /opt/claude-workspace/projects/cyber-guardian/scripts/hourly-security-scan.sh >> /opt/claude-workspace/projects/cyber-guardian/.scan-state/cron.log 2>&1
```

---

## State Files

**Location:** `/opt/claude-workspace/projects/cyber-guardian/.scan-state/`

**Files:**
- `latest-counts.txt` - Most recent scan counts (CRITICAL HIGH MEDIUM TOTAL)
- `previous-counts.txt` - Previous scan counts (for comparison)
- `scan.log` - Detailed scan activity log
- `cron.log` - Cron execution output

**Reset State (starts fresh baseline):**
```bash
rm /opt/claude-workspace/projects/cyber-guardian/.scan-state/*.txt
```

---

## Troubleshooting

### Scan Not Running

**Check cron job:**
```bash
crontab -l | grep hourly-security-scan
```

**Check cron service:**
```bash
systemctl status cron
```

**Verify script permissions:**
```bash
ls -l /opt/claude-workspace/projects/cyber-guardian/scripts/hourly-security-scan.sh
# Should show: -rwxr-xr-x (executable)
```

### No Reports Generated

**Check scanner directly:**
```bash
cd /opt/claude-workspace/projects/cyber-guardian
python3 blueteam/cli_codebase_scan.py
```

**Check for errors:**
```bash
tail -50 /opt/claude-workspace/projects/cyber-guardian/.scan-state/scan.log
tail -50 /opt/claude-workspace/projects/cyber-guardian/.scan-state/cron.log
```

### High False Positive Rate

**Known issue:** SQL injection pattern is too broad - matches any string concatenation.

**See:** `SECURITY_MITIGATION_PLAN.md` "Scanner Pattern Refinement" section

**Current workaround:** Manual review to separate false positives from real vulnerabilities.

**Future fix:** Update pattern to require database context:
```python
# BEFORE (too broad):
"pattern": r'"\\s*\\.\\s*\\$'

# AFTER (more specific):
"pattern": r'\\$wpdb->(query|get_results|get_row|get_var)\\s*\\([^)]*"\\s*\\.\\s*\\$'
```

---

## Integration with Security Workflow

### Phase 1: Automated Monitoring (CURRENT)
- ✅ Hourly scans running
- ✅ Baseline established
- ✅ Change detection active
- ⏳ Alert notifications (pending)

### Phase 2: Active Remediation
- Plugin-specific TODO files created
- Manual review process documented
- Mitigation plan in progress

### Phase 3: Continuous Improvement
- Refine detection patterns
- Reduce false positives
- Add automated fixes where possible
- Integrate with CI/CD pipeline

---

## Performance Metrics

**Baseline Scan (2026-03-07):**
- Duration: 43.8 seconds
- Files: 23,360 PHP files
- Projects: 64
- Issues Found: 4,071 total
  - CRITICAL: 3,410 (mostly false positive SQL injection)
  - HIGH: 116
  - MEDIUM: 545
  - LOW: 0

**Hourly Impact:**
- CPU: <1 minute per hour
- Disk: ~2.6 MB per report (JSON + Markdown)
- Storage: ~440 MB per week (auto-cleaned)
- Network: None (local filesystem only)

---

## References

- **Scanner Implementation:** `blueteam/api/codebase_scanner.py`
- **CLI Tool:** `blueteam/cli_codebase_scan.py`
- **Hourly Script:** `scripts/hourly-security-scan.sh`
- **Mitigation Plan:** `SECURITY_MITIGATION_PLAN.md`
- **Master TODO Index:** `SECURITY_TODO_INDEX.md`

---

**Installation Date:** 2026-03-07
**Next Review:** 2026-03-14 (weekly)
**Status:** ✅ PRODUCTION - ACTIVE
