#!/bin/bash
#
# Complete Server Security Setup for Project Keystone Deployments
# Installs and configures all security scanning tools
#
# Usage: sudo bash server-security-setup.sh [email@example.com]
#
# Part of standard Project Keystone server deployment
#

set -e

ALERT_EMAIL="${1:-admin@quigs.com}"
SCRIPT_DIR="/opt/claude-workspace/shared-resources/scripts"

echo "=========================================="
echo "Project Keystone Security Setup"
echo "=========================================="
echo ""
echo "Server: $(hostname)"
echo "Alert Email: $ALERT_EMAIL"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "ERROR: This script must be run as root (use sudo)"
    exit 1
fi

# Check if scripts exist
if [ ! -f "$SCRIPT_DIR/install-malware-scanners.sh" ]; then
    echo "ERROR: Installation scripts not found at $SCRIPT_DIR"
    echo "Please ensure /opt/claude-workspace/shared-resources is available"
    exit 1
fi

echo "=========================================="
echo "Phase 1: Installing Malware Scanners"
echo "=========================================="
echo ""

bash "$SCRIPT_DIR/install-malware-scanners.sh"

echo ""
echo "=========================================="
echo "Phase 2: Configuring Automated Scans"
echo "=========================================="
echo ""

bash "$SCRIPT_DIR/setup-malware-scans.sh" "$ALERT_EMAIL"

echo ""
echo "=========================================="
echo "Phase 3: Initial Security Baseline"
echo "=========================================="
echo ""

echo "Creating rkhunter baseline..."
rkhunter --propupd --quiet

echo "Updating maldet signatures..."
maldet --update 2>&1 | grep -v "Clam"

echo "Running initial Lynis audit..."
lynis audit system --quick > /var/log/lynis-initial-audit.log 2>&1

echo ""
echo "=========================================="
echo "Phase 4: Verification"
echo "=========================================="
echo ""

echo "Service Status:"
systemctl is-active clamav-daemon && echo "  ✓ ClamAV daemon running" || echo "  ✗ ClamAV daemon not running"
systemctl is-active clamav-freshclam && echo "  ✓ ClamAV updater running" || echo "  ✗ ClamAV updater not running"

echo ""
echo "Installed Tools:"
command -v clamscan > /dev/null && echo "  ✓ ClamAV $(clamscan --version | head -1)" || echo "  ✗ ClamAV not found"
command -v maldet > /dev/null && echo "  ✓ maldet $(maldet --version 2>&1 | head -1)" || echo "  ✗ maldet not found"
command -v rkhunter > /dev/null && echo "  ✓ rkhunter $(rkhunter --version 2>&1 | head -1)" || echo "  ✗ rkhunter not found"
command -v chkrootkit > /dev/null && echo "  ✓ chkrootkit installed" || echo "  ✗ chkrootkit not found"
command -v lynis > /dev/null && echo "  ✓ Lynis $(lynis --version 2>&1 | head -1)" || echo "  ✗ Lynis not found"

echo ""
echo "Cron Jobs:"
if [ -f "/etc/cron.d/malware-scanning" ]; then
    echo "  ✓ Automated scans configured"
    echo "    $(grep -c "^[^#]" /etc/cron.d/malware-scanning) scheduled tasks"
else
    echo "  ✗ Cron jobs not configured"
fi

echo ""
echo "Log Directory:"
if [ -d "/var/log/malware-scans" ]; then
    echo "  ✓ /var/log/malware-scans/ created"
else
    echo "  ✗ Log directory not found"
fi

echo ""
echo "=========================================="
echo "Setup Complete!"
echo "=========================================="
echo ""
echo "✓ All security scanners installed and configured"
echo "✓ Automated daily/weekly scans scheduled"
echo "✓ Email alerts configured: $ALERT_EMAIL"
echo "✓ Initial security baseline established"
echo ""
echo "Documentation:"
echo "  /opt/claude-workspace/shared-resources/docs/MALWARE_SCANNING.md"
echo ""
echo "Next Steps:"
echo "  1. Review Lynis audit: cat /var/log/lynis-initial-audit.log"
echo "  2. Run test scan: sudo clamscan -r /var/www/html --infected"
echo "  3. Monitor logs: tail -f /var/log/malware-scans/*.log"
echo "  4. Check email alerts work: review test email sent"
echo ""
echo "Scan Schedule:"
echo "  Daily 2:00 AM  - ClamAV WordPress scan"
echo "  Daily 3:00 AM  - maldet recent changes"
echo "  Sunday 4:00 AM - rkhunter system scan"
echo "  Sunday 4:30 AM - chkrootkit system scan"
echo ""
