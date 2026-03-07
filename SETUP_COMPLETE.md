# Cyber-Guardian Setup Complete

**Date:** 2026-03-06
**Status:** ✅ Operational
**Setup Script:** `scripts/setup-cyber-guardian.sh`

---

## Installation Summary

### What Was Configured

1. **Python Virtual Environment**
   - Location: `/opt/claude-workspace/projects/cyber-guardian/venv`
   - Dependencies: aiohttp, pyyaml, psycopg2-binary
   - Isolated from system Python

2. **CVE Data Sources**
   - ✅ KEV (CISA Known Exploited Vulnerabilities)
   - ✅ ExploitDB (Exploit Database)
   - ⏳ CVEListV5 (Pending first nightly sync - large dataset)

3. **Cron Jobs**
   - Daily 1:00 AM: CVE data sync
   - Daily 2:00 AM: Full nightly scan (CVE + Malware)

4. **Directory Structure**
   ```
   cyber-guardian/
   ├── venv/                    # Python virtual environment
   ├── data/cve/                # CVE data cache
   ├── logs/                    # Scan logs
   ├── reports/nightly/         # JSON reports (30-day retention)
   └── scripts/
       ├── setup-cyber-guardian.sh    # Keystone setup script
       ├── run-cve-scan.sh           # CVE sync wrapper (uses venv)
       ├── run-nightly-scan.sh       # Nightly scan wrapper (uses venv)
       └── quick-cve-check.py        # Manual CVE lookup tool
   ```

---

## Usage

### Activate Virtual Environment

```bash
cd /opt/claude-workspace/projects/cyber-guardian
source venv/bin/activate
```

### CVE Commands

```bash
# Check CVE data status
python3 -m redteam.cve status

# Sync all CVE sources (runs automatically at 1 AM)
python3 -m redteam.cve sync

# Sync specific source
python3 -m redteam.cve sync --source kev
python3 -m redteam.cve sync --source exploitdb
python3 -m redteam.cve sync --source cvelistv5

# Look up CVEs
python3 -m redteam.cve lookup "wordpress 6.4"
python3 -m redteam.cve lookup "nginx 1.24.0"
python3 -m redteam.cve lookup "php 8.2" --min-cvss 7.0

# Get JSON output
python3 -m redteam.cve lookup "wordpress 6.4" --json

# WordPress-specific
python3 -m redteam.cve lookup "wordpress 6.4.1" --ecosystem wordpress-core
```

### Manual Scan

```bash
# Run nightly scan manually
bash scripts/nightly-scan.sh

# Or use the wrapper (uses venv automatically)
bash scripts/run-nightly-scan.sh
```

---

## Test Results

### CVE Scanner Test (2026-03-06)

**Nginx 1.24:**
- Found: 25 CVEs
- Includes: CVE-2019-11043 (PHP-FPM RCE), CVE-2013-2028 (DoS), etc.
- Sources: KEV + ExploitDB

**WordPress 6.4:**
- Found: 3 CVEs
- Sources: KEV + ExploitDB

### Data Source Status

| Source      | Status | Last Sync                          | Max Age |
|-------------|--------|------------------------------------|---------|
| KEV         | ✅ OK  | 2026-03-07 03:55:13 UTC            | 168h    |
| ExploitDB   | ✅ OK  | 2026-03-07 03:58:51 UTC            | 168h    |
| cvelistv5   | ⚠️ STALE | Never (will sync on first nightly) | 24h     |

---

## Known Issues

### Bug: CVE Display Formatting Error

**Issue:** When using table output (non-JSON), some CVE lookups encounter AttributeError:
```
AttributeError: 'str' object has no attribute 'cvss_v31_score'
```

**Workaround:** Use `--json` flag for reliable output:
```bash
python3 -m redteam.cve lookup "wordpress 6.4" --json | python3 -m json.tool
```

**Status:** Bug exists in upstream code from latest commit (7139854). Scanner is functional, JSON output works correctly.

---

## Cron Schedule

```cron
# Cyber-Guardian Security Scans
# Daily at 1:00 AM - CVE data sync
0 1 * * * ublirnevire /opt/claude-workspace/projects/cyber-guardian/scripts/run-cve-scan.sh

# Daily at 2:00 AM - Full nightly scan
0 2 * * * ublirnevire /opt/claude-workspace/projects/cyber-guardian/scripts/run-nightly-scan.sh
```

**Email Alerts:** Configured to send to `admin@quigs.com`

---

## Log Files

| Type | Location | Description |
|------|----------|-------------|
| CVE Sync | `logs/cve-sync.log` | Daily CVE data synchronization |
| Nightly Scan | `logs/nightly-YYYY-MM-DD.log` | Full scan logs (CVE + Malware) |

---

## Reports

**Location:** `reports/nightly/`
**Format:** JSON
**Retention:** 30 days (automatic cleanup)
**Filename Pattern:** `redteam-report-YYYYMMDD_HHMMSS-*.json`

---

## Next Steps

1. ✅ **Setup Complete** - Scanner is operational
2. ⏳ **First Nightly Scan** - Will run automatically at 2 AM
3. ⏳ **CVEListV5 Sync** - Will download on first nightly scan (~30 min)
4. 🔄 **Monitor Logs** - Check `logs/nightly-*.log` after first run

---

## Quick Reference

### Re-run Setup

```bash
sudo bash scripts/setup-cyber-guardian.sh admin@quigs.com
```

### Check Cron Jobs

```bash
cat /etc/cron.d/cyber-guardian
```

### View Recent Reports

```bash
ls -lth reports/nightly/ | head -10
```

### View Latest Log

```bash
tail -f logs/nightly-$(date +%Y-%m-%d).log
```

---

**Setup Completed By:** Claude Sonnet 4.5
**Repository:** https://github.com/Quig-Enterprises/cyber-guardian
**Latest Commit:** 9a112f2 (Add cyber-guardian keystone setup script with venv support)
