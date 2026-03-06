# Server Management Scripts Reference

**Version:** 1.0.0
**Last Updated:** 2026-02-24
**Server:** cp.quigs.com (webhost.tailce791f.ts.net)

---

## Table of Contents

1. [Permission Management Scripts](#permission-management-scripts)
2. [WordPress Management Scripts](#wordpress-management-scripts)
3. [Security Scanning Scripts](#security-scanning-scripts)
4. [Deployment Scripts](#deployment-scripts)
5. [Maintenance Scripts](#maintenance-scripts)

---

## Permission Management Scripts

### fixperms

**Location:** `/home/ubuntu/fixperms`
**Owner:** ubuntu:ubuntu
**Permissions:** 755 (executable)

**Purpose:** Fix file and directory permissions for WordPress sites on cp.quigs.com

**Usage:**
```bash
bash ~/fixperms <domain1> <domain2> ...
```

**Examples:**
```bash
bash ~/fixperms sandbox.quigs.com
bash ~/fixperms waldvogelsealcoating.com quigs.com
```

**What It Does:**

1. **Base Permissions:**
   - `/home/brandon/web/*/` → 771 (brandon:brandon)
   - `public_html/` → 771 (brandon:www-data)
   - `.htaccess` → 664

2. **WordPress-Specific:**
   - `wp-config.php` → 660 (brandon:www-data)
   - All CxQ plugins → 771 recursive (brandon:www-data)
   - `wp-content/` → 775 recursive
   - `wp-includes/` → 775 recursive
   - `wp-admin/` → 775 recursive
   - `wp-login.php` → 664

3. **Special Cases:**
   - **WooCommerce logs:** `wp-content/uploads/wc-logs/` → 775 recursive
   - **All-in-One WP Migration storage:** `wp-content/plugins/all-in-one-wp-migration/storage/` → 777
   - **oauth.quigs.com:** Special treatment (custom config)

**Important Notes:**

- ✅ **Safe to run on production sites**
- ✅ **Preserves All-in-One WP Migration storage permissions** (777 required)
- ✅ **Preserves ownership** (brandon:www-data)
- ⚠️ **Must be run from /home/brandon/web/ or use full domain paths**

**Recent Changes:**

- **2026-02-24:** Added All-in-One WP Migration storage directory preservation (777)
  - Previously would reset storage to 775, breaking plugin functionality
  - Now explicitly restores 777 after bulk chmod operations
  - Backup created: `/home/ubuntu/fixperms.backup.20260224-005520`

---

### fixpermsall

**Location:** `/home/ubuntu/fixpermsall`
**Owner:** ubuntu:ubuntu
**Permissions:** 755 (executable)

**Purpose:** Run fixperms on ALL WordPress sites in parallel (4 concurrent)

**Usage:**
```bash
sudo bash ~/fixpermsall
```

**What It Does:**

1. Finds all WordPress sites in `/home/brandon/web/`
2. Runs `fixperms` on each domain
3. Processes up to 4 domains simultaneously for speed
4. Reports total time elapsed

**Output Example:**
```
[domain1.com] Starting...
[domain2.com] Starting...
[domain1.com] -- Fixing ownership...
[domain2.com] -- Fixing ownership...
[domain1.com] Complete
[domain2.com] Complete
...
ALL DONE!
Time elapsed: 45s
```

**Important Notes:**

- ⚠️ **Requires sudo** (verifies at startup)
- ✅ Inherits all fixperms behaviors (including All-in-One WP Migration fix)
- ✅ Safe to run on production
- ⏱️ Typical runtime: 30-60 seconds for ~40 sites

**When to Use:**

- After bulk plugin deployments
- After server migrations
- When multiple sites show permission errors
- As part of maintenance routines

---

## WordPress Management Scripts

### cxq-wp-doctor.sh

**Location:** `/home/ubuntu/cxq-wp-doctor.sh`
**Owner:** root:root
**Permissions:** 755 (executable)

**Purpose:** WordPress performance analysis and diagnostics

**Usage:**
```bash
sudo /home/ubuntu/cxq-wp-doctor.sh
```

**Features:**
- Benchmark mode: TTFB testing across all sites
- Performance analysis
- Reports slowest sites first
- Identifies unresponsive sites

---

### cxq-wp-update.sh

**Location:** `/home/ubuntu/cxq-wp-update.sh`
**Owner:** root:root
**Permissions:** 755 (executable)

**Purpose:** WordPress core and plugin updates

---

### cxq-setup-wordfence.sh

**Location:** `/home/ubuntu/cxq-setup-wordfence.sh`
**Owner:** root:root
**Permissions:** 755 (executable)

**Purpose:** Install and configure Wordfence security plugin

**Usage:**
```bash
sudo /home/ubuntu/cxq-setup-wordfence.sh [domain]
```

**Notes:**
- If no domain specified, processes all sites
- Applies configuration template from wordfence.com

---

## Security Scanning Scripts

### server-security-setup.sh

**Location:** `/opt/claude-workspace/shared-resources/scripts/server-security-setup.sh`
**Owner:** ublirnevire:brandon
**Permissions:** 755 (executable)

**Purpose:** Complete security scanner installation for new Project Keystone deployments

**Usage:**
```bash
sudo bash /opt/claude-workspace/shared-resources/scripts/server-security-setup.sh [email@example.com]
```

**Examples:**
```bash
# Install on Alfred with default email
sudo bash /opt/claude-workspace/shared-resources/scripts/server-security-setup.sh admin@quigs.com

# Install on Artemis with custom email
sudo bash /opt/claude-workspace/shared-resources/scripts/server-security-setup.sh security@example.com
```

**What It Installs:**

**Tier 1 - Essential Security:**
- **ClamAV** - Antivirus scanner with daily WordPress scans
- **rkhunter** - Rootkit detector with weekly system scans
- **Linux Malware Detect (maldet)** - Web-specific malware detection

**Tier 2 - Enhanced Security:**
- **chkrootkit** - Alternative rootkit detection
- **Lynis** - Security auditing and compliance checking

**Automated Scan Schedule:**
- Daily 2:00 AM - ClamAV scan of `/var/www/html/`
- Daily 3:00 AM - maldet scan of recent changes
- Sunday 4:00 AM - rkhunter system scan
- Sunday 4:30 AM - chkrootkit system scan

**Update Schedule:**
- Every 6 hours - ClamAV virus definitions
- Daily 1:00 AM - maldet signatures
- Daily 1:30 AM - rkhunter database

**Output:**
```
Phase 1: Installing Malware Scanners
  ✓ ClamAV - Antivirus scanner
  ✓ rkhunter - Rootkit detector
  ✓ chkrootkit - Rootkit checker
  ✓ Lynis - Security auditing
  ✓ maldet - Linux Malware Detect

Phase 2: Configuring Automated Scans
  ✓ Created daily ClamAV scan script
  ✓ Created daily maldet scan script
  ✓ Created weekly rkhunter scan script
  ✓ Created weekly chkrootkit scan script
  ✓ Configured cron jobs

Phase 3: Initial Security Baseline
  ✓ Created rkhunter baseline
  ✓ Updated maldet signatures
  ✓ Ran initial Lynis audit

Phase 4: Verification
  ✓ All services running
  ✓ Cron jobs configured
  ✓ Log directory created
```

**Email Alerts:**
- Sent when malware/rootkits detected
- Contains full scan log
- Subject: `⚠️ [Tool]: Malware Detected on [hostname]`

**Log Files:**
- Location: `/var/log/malware-scans/`
- Format: `[tool]-YYYYMMDD.log`
- Retention: 30 days (compressed after 7 days)

**Important Notes:**
- ✅ **Part of standard Project Keystone deployment**
- ✅ **Run on all new Ubuntu servers (Alfred, Artemis, etc.)**
- ⚠️ **Requires root permissions (use sudo)**
- ⚠️ **Installation takes ~5-10 minutes**

**Documentation:**
See `/opt/claude-workspace/shared-resources/docs/MALWARE_SCANNING.md` for:
- Manual scanning commands
- Handling detections
- Performance impact
- Troubleshooting
- Integration with existing security

---

### install-malware-scanners.sh

**Location:** `/opt/claude-workspace/shared-resources/scripts/install-malware-scanners.sh`
**Purpose:** Low-level installation script (called by server-security-setup.sh)

**Usage:**
```bash
sudo bash /opt/claude-workspace/shared-resources/scripts/install-malware-scanners.sh
```

**Note:** Normally called by `server-security-setup.sh`. Use directly only if you need to reinstall scanners without reconfiguring automation.

---

### setup-malware-scans.sh

**Location:** `/opt/claude-workspace/shared-resources/scripts/setup-malware-scans.sh`
**Purpose:** Configure automated scans and cron jobs (called by server-security-setup.sh)

**Usage:**
```bash
sudo bash /opt/claude-workspace/shared-resources/scripts/setup-malware-scans.sh [email@example.com]
```

**Note:** Normally called by `server-security-setup.sh`. Use directly to reconfigure email alerts or scan schedules.

---

### Manual Scan Commands

After installation, these commands are available:

**Daily ClamAV Scan:**
```bash
sudo /usr/local/bin/clamav-daily-scan.sh
```

**Daily maldet Scan:**
```bash
sudo /usr/local/bin/maldet-daily-scan.sh
```

**Weekly rkhunter Scan:**
```bash
sudo /usr/local/bin/rkhunter-weekly-scan.sh
```

**Weekly chkrootkit Scan:**
```bash
sudo /usr/local/bin/chkrootkit-weekly-scan.sh
```

**On-Demand Security Audit:**
```bash
sudo lynis audit system
```

**Quick Scan Examples:**
```bash
# Scan specific WordPress site
sudo clamscan -r /var/www/html/example.com --infected

# Scan WordPress uploads
sudo maldet -a /var/www/html/*/public_html/wp-content/uploads

# Quick rootkit check
sudo rkhunter --check --skip-keypress --report-warnings-only
```

---

## Deployment Scripts

### deploy-site-manager-client.sh

**Location:** `/home/ubuntu/deploy-site-manager-client.sh`
**Owner:** ubuntu:ubuntu
**Permissions:** 755 (executable)

**Purpose:** Deploy cxq-site-manager-client plugin to all WordPress sites

**Usage:**
```bash
./deploy-site-manager-client.sh [--dry-run]
```

**Source Site:** maplewoodgolfcourse.com
**Excluded Sites:** quigs.com (main domain)

**Features:**
- Dry-run mode for testing
- Syncs from source to all other WordPress sites
- Preserves site-specific configurations

---

### cxq-deploy-mu-plugin.sh

**Location:** `/home/ubuntu/cxq-deploy-mu-plugin.sh`
**Owner:** root:root
**Permissions:** 755 (executable)

**Purpose:** Deploy or delete mu-plugin files/directories to/from WordPress sites

**Usage:**
```bash
sudo /home/ubuntu/cxq-deploy-mu-plugin.sh [--delete] <plugin_file_or_directory> [domain.com]
```

**Features:**
- Deploy to single domain or all domains
- Delete mode for removal
- Validates plugin structure
- Sets correct permissions automatically

---

## Maintenance Scripts

### cleanup.sh

**Location:** `/home/ubuntu/cleanup.sh`
**Owner:** ubuntu:ubuntu
**Permissions:** 755 (executable)

**Purpose:** Cleanup old files and logs across all WordPress sites

**What It Removes:**
- `wp-content/debug.log` (recreated as needed)
- `wp-config-sample.php`
- `install.php`

**What It Locks Down:**
- `.user.ini` → 660
- `license.txt` → 660
- `readme.html` → 660

**Also Runs:**
- MySQL binary log cleanup (logs > 3 days)

---

### cxq-monitor-apache.sh

**Location:** `/home/ubuntu/cxq-monitor-apache.sh`
**Owner:** root:root
**Permissions:** 755 (executable)

**Purpose:** Monitor Apache server performance and resource usage

---

### list-all-plugins.sh

**Location:** `/home/brandon/scripts/list-all-plugins.sh`
**Owner:** brandon:brandon
**Permissions:** 755 (executable)

**Purpose:** List all WordPress plugins across all sites

**Usage:**
```bash
/home/brandon/scripts/list-all-plugins.sh [domain] [--csv] [--by-plugin]
```

**Options:**
- `[domain]` - Filter to specific domain
- `--csv` - Output in CSV format
- `--by-plugin` - Group by plugin name instead of domain

**Output Formats:**
- **Default:** Grouped by domain
- **--by-plugin:** Grouped by plugin with versions
- **--csv:** CSV format for spreadsheets

**Features:**
- Reads plugin headers directly (no database)
- Detects both regular plugins and mu-plugins
- Shows plugin names and versions
- Works across all sites

---

## Backup Information

### fixperms Backups

All backups located in `/home/ubuntu/`:

- `fixperms.backup.20260110-223443` - Pre-optimization version
- `fixperms.backup.20260224-005520` - Before All-in-One WP Migration fix

### fixpermsall Backups

- `fixpermsall.backup.20260110-223634` - Original version

**Backup Convention:** `<scriptname>.backup.YYYYMMDD-HHMMSS`

---

## Common Workflows

### After Plugin Deployment

```bash
# 1. Deploy plugin
sudo /home/ubuntu/cxq-deploy-mu-plugin.sh plugin-name.php

# 2. Fix permissions on all sites
sudo bash ~/fixpermsall
```

### After Code Changes

```bash
# Fix permissions for specific site
bash ~/fixperms sandbox.quigs.com
```

### Site Health Check

```bash
# 1. Performance check
sudo /home/ubuntu/cxq-wp-doctor.sh

# 2. Fix any permission issues
sudo bash ~/fixpermsall

# 3. Cleanup old files
/home/ubuntu/cleanup.sh
```

---

## Important Reminders

1. **Always use fixperms/fixpermsall** after:
   - Deploying plugins
   - Manual file uploads via SFTP
   - Git pulls
   - Bulk file operations

2. **All-in-One WP Migration requires 777** on storage directory:
   - fixperms now handles this automatically
   - If plugin fails after running fixperms, check storage permissions
   - Manual fix: `sudo chmod 777 /path/to/plugins/all-in-one-wp-migration/storage`

3. **Special Sites:**
   - oauth.quigs.com has custom permission handling in fixperms
   - Check script source for specific requirements

4. **Ownership Standard:**
   - All WordPress files: `brandon:www-data`
   - Directories: 775 or 771
   - Files: 664
   - wp-config.php: 660 (more restrictive)

---

## Troubleshooting

### "Permission denied" errors in WordPress

**Solution:**
```bash
bash ~/fixperms <affected-domain>
```

### All-in-One WP Migration cannot create storage files

**Check:**
```bash
ls -ld /home/brandon/web/<domain>/public_html/wp-content/plugins/all-in-one-wp-migration/storage
```

**Should show:** `drwxrwxrwx` (777)

**Fix:**
```bash
sudo chmod 777 /home/brandon/web/<domain>/public_html/wp-content/plugins/all-in-one-wp-migration/storage
```

### Script not found

**Verify locations:**
```bash
ls -la /home/ubuntu/*.sh
ls -la /home/brandon/scripts/*.sh
```

---

## Script Locations Quick Reference

| Script | Location | Sudo Required |
|--------|----------|---------------|
| fixperms | /home/ubuntu/fixperms | No* |
| fixpermsall | /home/ubuntu/fixpermsall | Yes |
| cxq-wp-doctor.sh | /home/ubuntu/ | Yes |
| cxq-wp-update.sh | /home/ubuntu/ | Yes |
| cxq-setup-wordfence.sh | /home/ubuntu/ | Yes |
| cxq-deploy-mu-plugin.sh | /home/ubuntu/ | Yes |
| deploy-site-manager-client.sh | /home/ubuntu/ | No |
| cleanup.sh | /home/ubuntu/ | No* |
| list-all-plugins.sh | /home/brandon/scripts/ | No |

*Uses sudo internally for permission changes

---

**Document Version:** 1.0.0
**Created:** 2026-02-24
**Last Updated:** 2026-02-24
**Maintainer:** Alfred (Claude Code Worker)
