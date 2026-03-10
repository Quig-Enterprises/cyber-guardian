# Lynis Remote Deployment Summary

**Date:** 2026-03-10
**Status:** ✅ COMPLETE (peter audit in progress)
**Architecture:** Remote-execution via SSH

---

## Deployment Summary

Successfully deployed remote Lynis audit capability to willie and peter. All audits are orchestrated from alfred and results are centrally stored in alfred's blueteam database.

###Servers Deployed

**1. Alfred (Local)**
- Execution: Local python script
- Hardening Index: 64/100
- Status: ✅ COMPLETE

**2. Willie (AWS EC2)**
- Execution: Remote via SSH
- Hardening Index: 64/100
- Status: ✅ COMPLETE

**3. Peter (Production)**
- Execution: Remote via SSH
- Hardening Index: Pending
- Status: ⏳ AUDIT RUNNING (~10+ minutes for large production server)

---

## Architecture

### Remote-Execution Model

```
┌──────────┐
│  Alfred  │ (Control Server - localhost)
└─────┬────┘
      │
      ├─ Run: python3 lynis-auditor.py alfred
      │  └─ Local Lynis execution
      │  └─ Direct database storage
      │
      ├─ SSH: willie (mailcow.tailce791f.ts.net)
      │  └─ Run: sudo lynis audit system
      │  └─ Retrieve: /var/log/lynis-report.dat
      │  └─ Parse and store in alfred database
      │
      └─ SSH: peter (webhost.tailce791f.ts.net)
         └─ Run: sudo lynis audit system
         └─ Retrieve: /var/log/lynis-report.dat
         └─ Parse and store in alfred database

┌──────────────────┐
│ blueteam.lynis_* │ (PostgreSQL on alfred)
└──────────────────┘
```

###Benefits

1. **Central Data Storage** - All results in one database
2. **No Remote DB Access** - Simpler security model
3. **Consistent Architecture** - Matches compliance scanner
4. **Single Source of Truth** - One dashboard for all servers

---

## Scripts Created

### 1. audit-remote-server.sh (New)

**Purpose:** Run Lynis audit on a remote server via SSH

**Usage:**
```bash
bash scripts/audit-remote-server.sh <server-name> <ssh-host> <ssh-key>
```

**Example:**
```bash
bash scripts/audit-remote-server.sh willie mailcow.tailce791f.ts.net ~/.ssh/bq_laptop_rsa
```

**Process:**
1. SSH to remote server
2. Run `sudo lynis audit system` remotely
3. Retrieve `/var/log/lynis-report.dat` via SSH
4. Parse report file locally
5. Store findings in alfred's blueteam database

### 2. audit-all-servers.sh (New)

**Purpose:** Audit all three servers with one command

**Usage:**
```bash
bash scripts/audit-all-servers.sh
```

**Process:**
- Audits alfred (local)
- Audits willie (remote via SSH)
- Audits peter (remote via SSH)
- Displays combined security posture

---

## Current Security Posture

### Scores

| Server | Compliance | Lynis Hardening | Combined | Status |
|--------|------------|-----------------|----------|--------|
| alfred | 100/100 | 64/100 | **82.0/100** | ✓ Good |
| willie | 100/100 | 64/100 | **82.0/100** | ✓ Good |
| peter | 95/100 | Pending | Pending | ⏳ Audit Running |

### Findings Summary

**Alfred:**
- Tests: 283
- Warnings: 2 (medium)
- Suggestions: 55 (low)
- Unresolved: 57

**Willie:**
- Tests: 263
- Warnings: 1 (medium)
- Suggestions: 48 (low)
- Unresolved: 49

**Peter:**
- Pending audit completion

---

## Installation Details

### Willie Deployment

```bash
# Install Lynis
ssh ubuntu@mailcow.tailce791f.ts.net "sudo apt-get install -y lynis"

# Verify installation
ssh ubuntu@mailcow.tailce791f.ts.net "lynis show version"
# Output: 3.0.9

# Run first audit
bash scripts/audit-remote-server.sh willie mailcow.tailce791f.ts.net ~/.ssh/bq_laptop_rsa

# Result: Hardening Index 64/100
```

### Peter Deployment

```bash
# Install Lynis
ssh ubuntu@webhost.tailce791f.ts.net "sudo apt-get install -y lynis"

# Verify installation
ssh ubuntu@webhost.tailce791f.ts.net "lynis show version"
# Output: 3.0.9

# Run first audit (in progress)
bash scripts/audit-remote-server.sh peter webhost.tailce791f.ts.net ~/.ssh/webhost_key

# Status: Running (10+ minutes for large production server)
```

---

## Database Integration

**Schema:** blueteam (PostgreSQL on alfred)

**Tables:**
- `lynis_audits` - Audit summary records
- `lynis_findings` - Individual warnings/suggestions

**Views:**
- `v_latest_lynis_audits` - Most recent audit per server
- `v_security_posture` - **Combined compliance + Lynis scores**
- `v_unresolved_lynis_findings` - Actionable remediation list

**Query Examples:**

```sql
-- View all server scores
SELECT * FROM blueteam.v_security_posture ORDER BY combined_score DESC;

-- View willie findings
SELECT * FROM blueteam.v_unresolved_lynis_findings
WHERE server_name = 'willie'
ORDER BY severity;

-- View hardening trend
SELECT server_name, audit_date, hardening_index
FROM blueteam.lynis_audits
ORDER BY server_name, audit_date DESC;
```

---

## Next Steps

### Immediate (After Peter Audit Completes)

1. **Verify Peter Results**
   ```sql
   SELECT * FROM blueteam.v_latest_lynis_audits WHERE server_name = 'peter';
   ```

2. **Review Combined Security Posture**
   ```sql
   SELECT * FROM blueteam.v_security_posture;
   ```

3. **Identify High-Priority Findings**
   ```sql
   SELECT * FROM blueteam.v_unresolved_lynis_findings
   WHERE severity IN ('high', 'medium')
   ORDER BY severity, server_name;
   ```

### Short-Term (Next 7 Days)

4. **Configure Automated Scanning**
   - Add weekly cron job on alfred
   - Email alerts for hardening index drops

5. **Address Medium-Severity Findings**
   - SMTP banner information disclosure
   - System reboot requirements
   - Redis configuration hardening

6. **Dashboard Integration**
   - Add Lynis tab to security dashboard UI
   - Display hardening trends
   - Show top findings across all servers

### Medium-Term (Next 30 Days)

7. **Establish Baseline Targets**
   - Production servers: 80+ hardening index
   - Document acceptable exceptions
   - Track improvement over time

8. **Create Remediation Playbooks**
   - Common finding fixes
   - Automated remediation scripts
   - Resolution tracking

9. **Security Posture Monitoring**
   - Weekly audit execution
   - Trend analysis
   - Compliance reporting

---

## Troubleshooting

### Long Audit Times on Production Servers

**Symptom:** Peter audit taking 10-15 minutes
**Cause:** Large number of files in WordPress installations
**Solution:** Normal behavior - production servers with many files take longer
**Mitigation:** Run audits during low-traffic periods

### SSH Connection Issues

**Symptom:** "Connection refused" or "Permission denied"
**Cause:** SSH keys not configured or firewall blocking
**Solution:** Use correct SSH key for each server:
- willie: `~/.ssh/bq_laptop_rsa`
- peter: `~/.ssh/webhost_key`

### Database Connection Errors

**Symptom:** "Connection refused" to PostgreSQL
**Cause:** PostgreSQL not configured for remote access
**Solution:** Use remote-execution architecture (current implementation)
- Run audits via SSH
- Store results locally on alfred
- No remote database connections needed

---

## Git Commits

**1. Lynis Integration (ad52209)**
- Initial Lynis deployment
- Database schema
- Local auditor script
- Documentation

**2. Sudoers Configuration (74bb270)**
- Passwordless sudo for Lynis
- Report file read permissions
- Alfred configuration

**3. Remote Execution Scripts (7287af9)**
- audit-remote-server.sh
- audit-all-servers.sh
- Remote deployment to willie and peter

---

## Files Modified/Created

**New Scripts:**
- `scripts/audit-remote-server.sh` (263 lines)
- `scripts/audit-all-servers.sh` (45 lines)

**Modified Scripts:**
- `scripts/lynis-auditor.py` - Added sudo for report reading

**New Documentation:**
- `findings/LYNIS_DEPLOYMENT_2026-03-10.md`
- `findings/LYNIS_REMOTE_DEPLOYMENT_2026-03-10.md` (this file)

**Configuration:**
- `/etc/sudoers.d/90-lynis-cyber-guardian` (alfred)

---

## Success Criteria

- ✅ Lynis installed on all three servers
- ✅ Remote audit execution working
- ✅ Central database storage on alfred
- ✅ Alfred audit complete (64/100)
- ✅ Willie audit complete (64/100)
- ⏳ Peter audit in progress
- ✅ Combined security posture view working
- ✅ Documentation complete

---

## Performance Metrics

### Audit Execution Times

| Server | Type | Duration | Tests | Findings |
|--------|------|----------|-------|----------|
| alfred | Local | ~75s | 283 | 57 |
| willie | Remote (AWS) | ~120s | 263 | 49 |
| peter | Remote (Production) | ~600s+ | Pending | Pending |

**Note:** Peter's longer execution time is expected due to:
- Large production WordPress installation
- Multiple sites and files
- Comprehensive file system scanning

---

## References

- Lynis Documentation: https://cisofy.com/lynis/
- CIS Benchmarks: https://www.cisecurity.org/cis-benchmarks
- Compliance Scanner: `findings/COMPLIANCE_TEST_REPORT_2026-03-10.md`
- Lynis Integration Docs: `docs/LYNIS_INTEGRATION.md`

---

**Deployment Status:** ✅ COMPLETE (awaiting peter audit completion)
**Next Action:** Monitor peter audit, verify results, configure automation

---

**End of Report**
