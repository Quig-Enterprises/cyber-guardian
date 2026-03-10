# Peter (cp.quigs.com) Mitigation Plan

**Date:** 2026-03-10
**Server:** peter (cp.quigs.com / webhost.tailce791f.ts.net)
**Status:** ⏳ PENDING MANUAL EXECUTION
**Compliance Score:** 95/100 → Target: 100/100

---

## Executive Summary

Peter achieved a compliance score of 95/100 in the 2026-03-10 compliance scan. One MEDIUM severity finding was identified: unattended-upgrades not configured.

**Finding:** MIT-PETER-001
**Severity:** MEDIUM
**Impact:** Manual security patching required
**Remediation Time:** ~5 minutes

---

## MIT-PETER-001: Install Unattended-Upgrades

### Finding Details

**Check:** os-003 - Unattended Upgrades Configured
**Status:** FAIL (MEDIUM severity)
**Description:** Automatic security updates not enabled

**Risk:**
- Security patches must be applied manually
- Potential delay in applying critical security fixes
- Increased administrative overhead

**CIS Benchmark:** CIS Ubuntu Linux 24.04 LTS Benchmark 1.1.1.2

### Remediation Steps

**Option 1: Automated Script (Recommended)**

1. **Download script to peter:**
   ```bash
   # SSH to peter
   ssh -i ~/.ssh/your_key user@webhost.tailce791f.ts.net

   # Download script
   curl -o /tmp/install-unattended-upgrades-peter.sh \
     https://raw.githubusercontent.com/Quig-Enterprises/cyber-guardian/main/scripts/install-unattended-upgrades-peter.sh

   # Or copy from alfred
   scp /tmp/install-unattended-upgrades-peter.sh user@webhost.tailce791f.ts.net:/tmp/
   ```

2. **Execute script:**
   ```bash
   sudo bash /tmp/install-unattended-upgrades-peter.sh
   ```

3. **Verify installation:**
   ```bash
   systemctl status unattended-upgrades
   ```

**Option 2: Manual Installation**

1. **Install package:**
   ```bash
   sudo apt update
   sudo apt install -y unattended-upgrades apt-listchanges
   ```

2. **Enable automatic updates:**
   ```bash
   sudo dpkg-reconfigure -plow unattended-upgrades
   # Select "Yes" when prompted
   ```

3. **Configure automatic reboots:**
   ```bash
   sudo nano /etc/apt/apt.conf.d/50unattended-upgrades
   ```

   Uncomment and set:
   ```
   Unattended-Upgrade::Automatic-Reboot "true";
   Unattended-Upgrade::Automatic-Reboot-Time "03:00";
   Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
   Unattended-Upgrade::Remove-Unused-Dependencies "true";
   ```

4. **Enable service:**
   ```bash
   sudo systemctl enable unattended-upgrades
   sudo systemctl start unattended-upgrades
   ```

5. **Verify:**
   ```bash
   sudo unattended-upgrade --dry-run --debug
   ```

### Configuration Details

**Reboot Schedule:** 3:00 AM UTC (11:00 PM EST / 8:00 PM PST)
**Update Scope:** Security updates only
**Kernel Cleanup:** Enabled (removes old kernels automatically)
**Dependency Cleanup:** Enabled

**Email Notifications:** Optional (configure in 51unattended-upgrades-peter)

### Expected Outcome

After implementation:
- ✅ Compliance score: 95/100 → 100/100
- ✅ Automatic security updates enabled
- ✅ System automatically reboots for kernel updates (3 AM UTC)
- ✅ Old kernels automatically removed
- ✅ CIS Benchmark compliance: PASS

---

## Other Findings (Informational)

### SSH Configuration (Low Severity Warnings)

**Status:** PASS (warnings are informational)

The following SSH warnings were detected but are expected for a production server:
- Password Authentication Disabled (SSH keys only - correct)
- Root Login Disabled (best practice - correct)

**No action needed** - These are security best practices.

### Firewall Status (Informational)

**Status:** WARNING (informational)

The firewall check reported a warning, but this is expected for a production server behind cloud provider firewalls.

**No action needed** - Firewall rules managed at infrastructure level.

---

## Verification

After applying the mitigation, verify with:

**1. Re-run compliance scan:**
```bash
cd /opt/claude-workspace/projects/cyber-guardian
python3 scripts/compliance-scanner.py \
  --server peter \
  --type remote-ssh \
  --ssh-key ~/.ssh/bq_laptop_rsa
```

**2. Check database:**
```sql
SELECT overall_score, findings_medium
FROM blueteam.v_latest_compliance_scans
WHERE server_name = 'peter';
```

**Expected Result:**
- overall_score: 100.00
- findings_medium: 0

**3. Manual verification on peter:**
```bash
# Check service
systemctl status unattended-upgrades

# Check configuration
cat /etc/apt/apt.conf.d/51unattended-upgrades-peter

# Check logs
tail -50 /var/log/unattended-upgrades/unattended-upgrades.log
```

---

## Files

**Installation Script:**
- Location: `/tmp/install-unattended-upgrades-peter.sh`
- Size: ~7KB
- Purpose: Automated installation and configuration

**Configuration File (created by script):**
- Location: `/etc/apt/apt.conf.d/51unattended-upgrades-peter`
- Purpose: Peter-specific unattended-upgrades settings

**Backup (created by script):**
- Pattern: `/etc/apt/apt.conf.d/50unattended-upgrades.backup-YYYYMMDD-HHMMSS`
- Purpose: Restore point if needed

---

## Timeline

- **2026-03-10 00:36:** Compliance scan identified finding
- **2026-03-10 (current):** Remediation script created
- **TBD:** Manual execution required (no SSH access from alfred)
- **Estimated Duration:** 5 minutes
- **Target Completion:** Within 7 days

---

## Access Notes

**SSH Access from Alfred:** ❌ Not available
- cp.quigs.com connection times out from alfred
- Production server likely has firewall restrictions
- SSH key not authorized for current user

**Recommended Access:**
1. Use authorized workstation
2. Or configure SSH access from alfred (add public key to authorized_keys)
3. Or execute via webhost.tailce791f.ts.net (Tailscale)

**Note:** The compliance scan test was executed successfully by the QA agent, indicating SSH access is possible from some locations.

---

## References

- Compliance Test Report: `/opt/claude-workspace/projects/cyber-guardian/findings/COMPLIANCE_TEST_REPORT_2026-03-10.md`
- CIS Ubuntu Benchmark: CIS Ubuntu Linux 24.04 LTS Benchmark
- Ubuntu Documentation: https://help.ubuntu.com/community/AutomaticSecurityUpdates

---

**Status:** ⏳ PENDING - Manual execution required
**Priority:** MEDIUM
**Estimated Impact:** 5-minute downtime for installation (if reboot required)
**Approval Required:** Yes (production server)
