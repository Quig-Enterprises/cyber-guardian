# WordPress Log Accessibility Scanner

**Version:** 1.0.0
**Date:** 2026-03-11

## Overview

Automated security scanner that tests WordPress sites for publicly accessible log files. Detects information disclosure vulnerabilities where sensitive log files can be accessed without authentication.

## Features

- **Comprehensive Coverage:** Tests 18+ common log file paths
- **Severity Classification:** HIGH for debug/error logs, MEDIUM for others
- **Multi-Site Support:** Scan individual sites or entire servers
- **JSON Output:** Structured results for integration with dashboards
- **Exit Codes:** Returns non-zero if vulnerabilities found (for CI/CD)

## Usage

### Scan Specific Sites

```bash
python3 wordpress-log-scanner.py --sites pickerel-pearson.com,lakelucernewi.org
```

### Scan All Sites on Server

```bash
python3 wordpress-log-scanner.py --server peter
```

### Output to JSON File

```bash
python3 wordpress-log-scanner.py --server peter --output /tmp/wp-log-scan.json
```

### Quiet Mode (Errors Only)

```bash
python3 wordpress-log-scanner.py --sites example.com --quiet
```

## Tested Log Paths

The scanner tests these common WordPress log file locations:

### Debug Logs
- `/wp-content/debug.log` - WordPress debug log (HIGH severity)
- `/wp-content/debug_log` - Alternative debug log
- `/debug.log` - Root debug log

### CxQ Plugin Logs
- `/wp-content/uploads/cxq-antispam-fallback.log`
- `/wp-content/cxq-logs/antispam.log`
- `/wp-content/cxq-logs/membership.log`
- `/wp-content/cxq-logs/firewall.log`

### WooCommerce Logs
- `/wp-content/uploads/wc-logs/fatal-errors.log` (should be protected by WooCommerce .htaccess)

### Generic Error Logs
- `/error_log`, `/error.log`, `/php-error.log`
- `/wp-content/uploads/error_log`
- `/wp-content/uploads/php_errors.log`
- `/wp-content/uploads/wp-errors.log`

### Security Plugin Logs
- `/wp-content/uploads/sucuri/sucuri-auditqueue.php`
- `/wp-content/uploads/sucuri/sucuri-failedlogins.php`

### Backup Logs
- `/wp-content/ai1wm-backups/error.log`
- `/wp-content/backup-logs/backup.log`

## Output Format

### JSON Structure

```json
{
  "scan_time": "2026-03-11T17:00:00.000000",
  "scanner_version": "1.0.0",
  "total_sites": 2,
  "vulnerable_sites": 1,
  "total_vulnerable_logs": 1,
  "sites": [
    {
      "domain": "example.com",
      "scan_time": "2026-03-11T17:00:00.000000",
      "status": "VULNERABLE",
      "vulnerable_logs": [
        {
          "path": "/wp-content/uploads/cxq-antispam-fallback.log",
          "url": "https://example.com/wp-content/uploads/cxq-antispam-fallback.log",
          "content_type": "text/plain",
          "severity": "MEDIUM"
        }
      ],
      "protected_logs": [
        "/wp-content/debug.log"
      ],
      "total_tested": 18
    }
  ]
}
```

### Exit Codes

- **0:** All sites secure - no vulnerabilities found
- **1:** Vulnerable log files detected
- **130:** Scan interrupted by user (Ctrl+C)

## Integration

### Hourly Security Scan

The scanner is integrated into `hourly-security-scan.sh` and runs every 6 hours:

```bash
# Runs at: 00:00, 06:00, 12:00, 18:00
python3 scripts/wordpress-log-scanner.py --server peter --output reports/wordpress-log-scan-*.json
```

### Alert Conditions

Sends email alert if:
- Any site has vulnerable_sites > 0
- Any log files return HTTP 200 (publicly accessible)

### Compliance Scanner Integration

Can be integrated into `compliance-scanner.py` as a WordPress-specific check category.

## Remediation

### .htaccess Protection (Recommended)

Create `.htaccess` in `wp-content/uploads/`:

```apache
# Protect log files from public access
<FilesMatch "\.(log)$">
  Order allow,deny
  Deny from all
</FilesMatch>
```

Deploy to affected site:

```bash
sudo cp .htaccess /home/brandon/web/SITE.com/public_html/wp-content/uploads/
sudo chown brandon:brandon /home/brandon/web/SITE.com/public_html/wp-content/uploads/.htaccess
sudo chmod 644 /home/brandon/web/SITE.com/public_html/wp-content/uploads/.htaccess
```

### Alternative: Move Logs Outside Web Root

Better security - logs completely inaccessible:

```bash
# Move logs to /home/brandon/logs/
mkdir -p /home/brandon/logs/SITE.com
```

Update plugin configurations to log to `/home/brandon/logs/SITE.com/` instead.

## Testing

### Verify Protection

```bash
# Should return HTTP 403 or 404
curl -I https://example.com/wp-content/uploads/debug.log
```

### Test Scanner

```bash
# Test on known-good site
python3 wordpress-log-scanner.py --sites pickerel-pearson.com

# Should output:
# ✓ All sites secure - no publicly accessible log files found
```

## Security Considerations

### What This Scanner Detects

- Publicly accessible log files (HTTP 200)
- Information disclosure vulnerabilities
- Misconfigurations in web server or plugin logging

### What This Scanner Does NOT Detect

- Log files inside web root but properly protected (403/404)
- Logs outside web root (already secure)
- Authentication-protected admin areas
- Log files with obscure random names

### False Positives

- Sites behind Cloudflare or CDN may show different responses
- Some plugins may intentionally expose logs (misconfiguration)
- 404 responses are considered secure (file doesn't exist or is blocked)

## Maintenance

### Adding New Log Paths

Edit `LOG_PATHS` list in `wordpress-log-scanner.py`:

```python
LOG_PATHS = [
    # Add new path
    "/wp-content/custom-plugin/logs/debug.log",
    ...
]
```

### Excluding Sites

Currently scans all sites on server. To exclude:

```bash
# Manual scan with specific sites only
python3 wordpress-log-scanner.py --sites site1.com,site2.com
```

## History

- **2026-03-11 v1.0.0:** Initial release
  - Detects 18 common log file paths
  - Integrated into hourly-security-scan.sh
  - Severity classification (HIGH/MEDIUM)
  - JSON output format

## Related Tools

- `hourly-security-scan.sh` - Main security automation script
- `compliance-scanner.py` - Infrastructure compliance scanner
- `send-security-alert.sh` - Email alerting system

## Support

See main README.md for Cyber-Guardian documentation.
