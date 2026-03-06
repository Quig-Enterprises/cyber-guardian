# Shared Scripts Directory

**Version:** 1.0.0
**Last Updated:** 2026-03-06

---

## Security Scanning Scripts

### server-security-setup.sh

**Complete security scanner deployment for Project Keystone servers**

```bash
sudo bash server-security-setup.sh [email@example.com]
```

**Installs:**
- ClamAV (antivirus)
- Linux Malware Detect (web malware)
- rkhunter (rootkit detection)
- chkrootkit (rootkit detection)
- Lynis (security auditing)

**Configures:**
- Daily automated WordPress scans
- Weekly system security scans
- Email alerts on detections
- Log rotation and archival

**Time:** ~5-10 minutes
**Requires:** root access

**Documentation:**
- Full Guide: `/opt/claude-workspace/shared-resources/docs/MALWARE_SCANNING.md`
- Quick Ref: `/opt/claude-workspace/shared-resources/docs/MALWARE_SCANNING_QUICK_REF.md`
- Server Scripts: `/opt/claude-workspace/shared-resources/SERVER_SCRIPTS.md`

---

### install-malware-scanners.sh

**Low-level scanner installation** (called by server-security-setup.sh)

```bash
sudo bash install-malware-scanners.sh
```

Installs all security scanning tools without configuration.

---

### setup-malware-scans.sh

**Configure automated scans** (called by server-security-setup.sh)

```bash
sudo bash setup-malware-scans.sh [email@example.com]
```

Creates cron jobs and scan scripts. Use to reconfigure email alerts.

---

## Usage

### New Server Deployment

```bash
# 1. Install all security scanners
cd /opt/claude-workspace/shared-resources/scripts
sudo bash server-security-setup.sh admin@quigs.com

# 2. Verify installation
sudo systemctl status clamav-daemon
sudo cat /etc/cron.d/malware-scanning

# 3. Test scan
sudo clamscan -r /var/www/html --infected
```

### Existing Server (Reconfigure Email)

```bash
# Update email alerts
sudo bash setup-malware-scans.sh newemail@example.com
```

---

## Integration

**Part of Project Keystone standard deployment:**
1. Base Ubuntu installation
2. WordPress stack (LEMP/LAMP)
3. **Security scanners** (this system) ← NEW
4. Monitoring and logging
5. Backup configuration

---

## Support

See documentation:
- `/opt/claude-workspace/shared-resources/docs/MALWARE_SCANNING.md`
- `/opt/claude-workspace/shared-resources/SERVER_SCRIPTS.md`
