# Automated Lynis Scanning Configuration

**Version:** 1.0.0
**Date:** 2026-03-10
**Status:** Production Ready

---

## Overview

Automated weekly Lynis security audits for all servers (alfred, willie, peter). Results are centrally stored in the blueteam database with historical trending and alerting capabilities.

**Schedule:** Every Sunday at 2:00 AM CDT
**Duration:** ~20-30 minutes (all three servers)
**Storage:** Central blueteam database on alfred
**Logging:** `/var/log/cyber-guardian/lynis-weekly-YYYYMMDD.log`

---

## Cron Configuration

### Current Schedule

```bash
# Weekly Lynis security audits - Every Sunday at 2:00 AM
0 2 * * 0 /opt/claude-workspace/projects/cyber-guardian/scripts/weekly-audit-cron.sh >> /var/log/cyber-guardian/cron.log 2>&1
```

### View Cron Jobs

```bash
crontab -l | grep lynis
```

### Modify Schedule

**Edit crontab:**
```bash
crontab -e
```

**Common schedules:**
- Weekly (Sunday 2 AM): `0 2 * * 0`
- Daily (2 AM): `0 2 * * *`
- Bi-weekly (Sunday/Wednesday 2 AM): `0 2 * * 0,3`
- Monthly (1st of month, 2 AM): `0 2 1 * *`

### Disable Automated Scanning

```bash
# Comment out the cron job
crontab -e
# Add # at the beginning of the lynis line
# 0 2 * * 0 /opt/claude-workspace/projects/...
```

---

## Scripts

### 1. weekly-audit-cron.sh

**Location:** `/opt/claude-workspace/projects/cyber-guardian/scripts/weekly-audit-cron.sh`

**Purpose:** Wrapper script for automated scanning

**Features:**
- Runs `audit-all-servers.sh`
- Logs output with timestamps
- Checks for score degradation
- Sends alerts on failures (configurable)
- Rotates old logs (keeps 12 weeks)

**Manual execution:**
```bash
bash /opt/claude-workspace/projects/cyber-guardian/scripts/weekly-audit-cron.sh
```

### 2. audit-all-servers.sh

**Location:** `/opt/claude-workspace/projects/cyber-guardian/scripts/audit-all-servers.sh`

**Purpose:** Execute Lynis audits on all servers

**Process:**
1. Audit alfred (local)
2. Audit willie (remote via SSH)
3. Audit peter (remote via SSH)
4. Store all results in central database

---

## Logging

### Log Files

**Weekly audit logs:**
```
/var/log/cyber-guardian/lynis-weekly-YYYYMMDD.log
```

**Cron execution log:**
```
/var/log/cyber-guardian/cron.log
```

**Error log:**
```
/var/log/cyber-guardian/lynis-errors.log
```

### View Logs

**Latest weekly audit:**
```bash
ls -lt /var/log/cyber-guardian/lynis-weekly-*.log | head -1 | xargs cat
```

**Cron output:**
```bash
tail -f /var/log/cyber-guardian/cron.log
```

**Recent audit summaries:**
```bash
grep "Audit Completed" /var/log/cyber-guardian/lynis-weekly-*.log
```

### Log Rotation

**Automatic rotation:** Logs older than 84 days (12 weeks) are automatically deleted

**Manual cleanup:**
```bash
find /var/log/cyber-guardian -name "lynis-weekly-*.log" -mtime +84 -delete
```

---

## Alerting

### Email Alerts (Optional)

**Enable email notifications:**

1. Edit `weekly-audit-cron.sh`
2. Uncomment the mail command in `send_alert()` function
3. Set recipient email address
4. Ensure `mailx` or `sendmail` is configured

**Example configuration:**
```bash
send_alert() {
    local subject="$1"
    local message="$2"

    # Enable this line
    echo "$message" | mail -s "$subject" admin@quigs.com
}
```

### Alert Conditions

**Alerts are triggered on:**
1. Audit script failure
2. Combined security score < 70/100
3. Unable to SSH to remote server
4. Database connection errors

---

## Monitoring

### Check Last Execution

```bash
# View last cron run
tail -20 /var/log/cyber-guardian/cron.log
```

### View Audit History

```sql
SELECT
    server_name,
    audit_date,
    hardening_index,
    warnings_count,
    suggestions_count
FROM blueteam.lynis_audits
ORDER BY audit_date DESC
LIMIT 20;
```

### Score Trend Analysis

```sql
SELECT
    server_name,
    audit_date::date,
    hardening_index,
    hardening_change
FROM blueteam.v_lynis_hardening_trend
WHERE server_name = 'alfred'
ORDER BY audit_date DESC
LIMIT 10;
```

### Current Security Posture

```sql
SELECT * FROM blueteam.v_security_posture ORDER BY server_name;
```

---

## Dashboard Integration (Future)

### Planned Features

**Cyber-Guardian Dashboard UI:**
- Schedule configuration interface
- Real-time audit status
- Historical trend charts
- Finding management
- Email notification settings
- Manual audit triggers

**API Endpoints (To Be Implemented):**
- `GET /api/lynis/schedule` - Get current cron schedule
- `POST /api/lynis/schedule` - Update cron schedule
- `POST /api/lynis/run-now` - Trigger immediate audit
- `GET /api/lynis/status` - Check last audit status
- `GET /api/lynis/trends` - Historical data for charts

**Configuration Options:**
- Scan frequency (daily/weekly/monthly)
- Time of day
- Email recipients
- Alert thresholds
- Which servers to include

### Current Manual Configuration

**For now, schedule changes require:**
1. SSH to alfred server
2. Run `crontab -e`
3. Modify the schedule line
4. Save and exit

**Example modification:**
```bash
# Change from Sunday 2 AM to every day at 3 AM
# OLD: 0 2 * * 0 /path/to/script
# NEW: 0 3 * * * /path/to/script
```

---

## Troubleshooting

### Cron Job Not Running

**Check cron service:**
```bash
sudo systemctl status cron
```

**Check cron logs:**
```bash
sudo grep CRON /var/log/syslog | grep lynis
```

**Verify crontab:**
```bash
crontab -l | grep lynis
```

### Audit Fails to Complete

**Check log for errors:**
```bash
cat /var/log/cyber-guardian/lynis-weekly-$(date +%Y%m%d).log
```

**Common issues:**
- SSH key permissions incorrect
- Remote server unreachable
- Database connection failed
- Lynis not installed on remote server

**Test manually:**
```bash
bash /opt/claude-workspace/projects/cyber-guardian/scripts/audit-all-servers.sh
```

### Database Connection Errors

**Verify .pgpass file:**
```bash
cat ~/.pgpass | grep eqmon
```

**Test connection:**
```bash
psql postgresql://eqmon:PASSWORD@localhost/eqmon -c "SELECT version();"
```

### SSH Connection Failures

**Test SSH to remote servers:**
```bash
ssh -i ~/.ssh/bq_laptop_rsa ubuntu@mailcow.tailce791f.ts.net "hostname"
ssh -i ~/.ssh/webhost_key ubuntu@webhost.tailce791f.ts.net "hostname"
```

**Verify SSH keys:**
```bash
ls -l ~/.ssh/bq_laptop_rsa ~/.ssh/webhost_key
```

---

## Performance Impact

**Resource Usage:**
- CPU: Moderate during audit execution (~10-15% per server)
- Network: Low (SSH traffic only)
- Disk: ~100KB per audit in database
- Duration: 2-5 minutes per server

**Scheduled Time:** 2:00 AM chosen to minimize impact
- Low traffic period
- Before business hours
- After daily backup window

---

## Security Considerations

**SSH Keys:**
- Private keys stored in ~/.ssh/ with 600 permissions
- Only alfred has keys to remote servers
- Keys are passwordless for automation

**Database Access:**
- Local connection only (localhost)
- Credentials in ~/.pgpass (600 permissions)
- No remote database access needed

**Sudo Permissions:**
- Lynis requires sudo for comprehensive audits
- Configured via /etc/sudoers.d/ drop-ins
- Minimal permissions (only for Lynis execution)

---

## Maintenance

### Weekly Tasks

**None required** - Fully automated

### Monthly Review

**Recommended:**
1. Review trend data for degradation
2. Address persistent medium/high findings
3. Verify remote servers are being audited
4. Check log file sizes

### Quarterly Tasks

**Recommended:**
1. Review automation effectiveness
2. Update baseline targets if needed
3. Audit SSH key rotation
4. Review alert recipients

---

## Next Steps

### Immediate

- ✅ Automated scanning configured
- ✅ First manual test complete
- ⏳ Wait for first Sunday execution

### Short-Term (Next 30 Days)

- Dashboard UI integration
- Web-based schedule configuration
- Real-time audit status display
- Email notification setup

### Medium-Term (Next 90 Days)

- Automated remediation scripts
- Trend analysis dashboards
- Integration with alerting systems
- Mobile notifications

---

## References

- Cron configuration: `/etc/crontab`
- Script location: `/opt/claude-workspace/projects/cyber-guardian/scripts/`
- Log location: `/var/log/cyber-guardian/`
- Database: `eqmon.blueteam` schema
- Lynis documentation: https://cisofy.com/lynis/

---

**Last Updated:** 2026-03-10
**Status:** Production Ready
**Next Execution:** Sunday, 2026-03-14 at 2:00 AM CDT
