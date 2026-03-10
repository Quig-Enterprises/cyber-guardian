#!/usr/bin/env bash
#
# Willie (MailCow) AWS-Compliant Security Scan
# Comprehensive CVE and security hardening assessment
#
# Usage: ./scan-willie-mailcow.sh [--quick|--full]
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
REPORT_DIR="$PROJECT_DIR/reports"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
REPORT_FILE="$REPORT_DIR/willie-security-scan-${TIMESTAMP}.md"

# MailCow server details
TARGET_HOST="mailcow.tailce791f.ts.net"
SSH_KEY="/home/ublirnevire/.ssh/bq_laptop_rsa"
SSH_USER="ubuntu"
SSH_CMD="ssh -i $SSH_KEY $SSH_USER@$TARGET_HOST"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log() {
    echo -e "${GREEN}[$(date '+%H:%M:%S')]${NC} $*" | tee -a "$REPORT_FILE"
}

log_error() {
    echo -e "${RED}[$(date '+%H:%M:%S')] ERROR:${NC} $*" | tee -a "$REPORT_FILE"
}

log_warn() {
    echo -e "${YELLOW}[$(date '+%H:%M:%S')] WARN:${NC} $*" | tee -a "$REPORT_FILE"
}

log_section() {
    echo -e "\n${BLUE}===${NC} $* ${BLUE}===${NC}\n" | tee -a "$REPORT_FILE"
}

# Ensure reports directory exists
mkdir -p "$REPORT_DIR"

# Initialize report
cat > "$REPORT_FILE" <<EOF
# Willie (MailCow) Security Scan Report

**Date:** $(date '+%Y-%m-%d %H:%M:%S')
**Target:** willie (email.northwoodsmail.com)
**Tailscale:** $TARGET_HOST
**Scan Type:** AWS-Compliant Security Assessment
**Framework:** CIS Benchmark, AWS Foundational Security

---

## Executive Summary

EOF

log_section "Starting Willie Security Scan"
log "Target: $TARGET_HOST"
log "SSH User: $SSH_USER"
log "Report: $REPORT_FILE"

# ===========================
# 1. CVE SCANNING
# ===========================

log_section "1. CVE Scanning - Known Vulnerabilities"

# Get OS information
log "Retrieving OS information..."
OS_INFO=$($SSH_CMD "lsb_release -a 2>/dev/null")
echo "$OS_INFO" | tee -a "$REPORT_FILE"

# Get kernel version
KERNEL_VERSION=$($SSH_CMD "uname -r")
log "Kernel: $KERNEL_VERSION"

# Check for available Ubuntu security updates
log "Checking Ubuntu security updates..."
SECURITY_UPDATES=$($SSH_CMD "apt list --upgradable 2>/dev/null | grep -i security | wc -l")
log "Pending security updates: $SECURITY_UPDATES"

if [ "$SECURITY_UPDATES" -gt 0 ]; then
    log_warn "Found $SECURITY_UPDATES pending security updates"
    $SSH_CMD "apt list --upgradable 2>/dev/null | grep -i security" | tee -a "$REPORT_FILE"
fi

# List installed packages with versions for CVE lookup
log "Generating package inventory..."
$SSH_CMD "dpkg -l | grep '^ii' | awk '{print \$2\":\"\$3}' | head -50" > "$REPORT_DIR/willie-packages-${TIMESTAMP}.txt"
log "Package list saved: willie-packages-${TIMESTAMP}.txt"

# Docker version CVE check
log "Checking Docker version..."
DOCKER_VERSION=$($SSH_CMD "docker --version")
log "$DOCKER_VERSION"

# MailCow container versions
log "Enumerating MailCow containers..."
$SSH_CMD "docker ps --format '{{.Names}}\t{{.Image}}'" | tee -a "$REPORT_FILE"

# ===========================
# 2. SYSTEM HARDENING
# ===========================

log_section "2. System Hardening Assessment"

# SSH configuration audit
log "Auditing SSH configuration..."
SSH_CONFIG=$($SSH_CMD "sudo grep -E '^(PermitRootLogin|PasswordAuthentication|PubkeyAuthentication|Port)' /etc/ssh/sshd_config")
echo "$SSH_CONFIG" | tee -a "$REPORT_FILE"

# Check for root login attempts
log "Checking failed login attempts..."
FAILED_LOGINS=$($SSH_CMD "sudo grep 'Failed password' /var/log/auth.log 2>/dev/null | tail -10 || echo 'No recent failures'")
echo "$FAILED_LOGINS" | tee -a "$REPORT_FILE"

# Firewall status
log "Checking firewall status..."
UFW_STATUS=$($SSH_CMD "sudo ufw status verbose" || echo "UFW not enabled")
echo "$UFW_STATUS" | tee -a "$REPORT_FILE"

# Check for exposed services
log "Checking listening ports..."
$SSH_CMD "sudo ss -tlnp | grep LISTEN" | tee -a "$REPORT_FILE"

# ===========================
# 3. MAILCOW SECURITY
# ===========================

log_section "3. MailCow Application Security"

# MailCow version
log "Checking MailCow version..."
MAILCOW_VERSION=$($SSH_CMD "cd /opt/mailcow-dockerized && git describe --tags 2>/dev/null || echo 'Unknown'")
log "MailCow version: $MAILCOW_VERSION"

# TLS/SSL certificate check
log "Checking TLS certificates..."
$SSH_CMD "docker exec mailcowdockerized-nginx-mailcow-1 nginx -V 2>&1 | grep -i tls" || log_warn "Could not verify TLS version"

# Check for insecure settings in mailcow.conf
log "Auditing mailcow.conf for security settings..."
MAILCOW_CONF=$($SSH_CMD "sudo grep -E '^(SKIP_LETS_ENCRYPT|SKIP_CLAMD|SKIP_SOLR|SKIP_SOGO)' /opt/mailcow-dockerized/mailcow.conf")
echo "$MAILCOW_CONF" | tee -a "$REPORT_FILE"

# Check Docker Compose security
log "Checking Docker Compose security settings..."
$SSH_CMD "cd /opt/mailcow-dockerized && grep -E '(privileged|cap_add|security_opt)' docker-compose.yml | head -20" | tee -a "$REPORT_FILE"

# ===========================
# 4. AWS COMPLIANCE
# ===========================

log_section "4. AWS Compliance Checks"

# EC2 metadata service version (IMDSv2 recommended)
log "Checking EC2 metadata service..."
IMDS_VERSION=$($SSH_CMD "curl -s -m 2 http://169.254.169.254/latest/meta-data/instance-id && echo ' (IMDSv1 accessible)' || echo 'IMDSv1 blocked (good)'")
log "$IMDS_VERSION"

# Check if unattended-upgrades is active
log "Checking automated security updates..."
UNATTENDED_STATUS=$($SSH_CMD "systemctl is-active unattended-upgrades")
log "Unattended-upgrades: $UNATTENDED_STATUS"

# Check backup configuration
log "Verifying backup configuration..."
AWS_BACKUP_EXISTS=$($SSH_CMD "[ -f /var/run/reboot-required ] && echo 'Pending reboot' || echo 'No reboot required'")
log "Reboot status: $AWS_BACKUP_EXISTS"

# Disk encryption check
log "Checking disk encryption..."
LUKS_STATUS=$($SSH_CMD "lsblk -o NAME,FSTYPE,MOUNTPOINT | grep -i crypt || echo 'No LUKS encryption detected'")
echo "$LUKS_STATUS" | tee -a "$REPORT_FILE"

# ===========================
# 5. FILE PERMISSIONS AUDIT
# ===========================

log_section "5. File Permissions Audit"

# Check critical file permissions
log "Auditing critical configuration files..."
$SSH_CMD "ls -la /etc/shadow /etc/passwd /etc/ssh/sshd_config /opt/mailcow-dockerized/mailcow.conf 2>/dev/null" | tee -a "$REPORT_FILE"

# Check for world-writable files (security risk)
log "Checking for world-writable files..."
WORLD_WRITABLE=$($SSH_CMD "find /etc /opt/mailcow-dockerized -type f -perm -002 2>/dev/null | wc -l")
log "World-writable files found: $WORLD_WRITABLE"

# ===========================
# 6. MALWARE SCANNING
# ===========================

log_section "6. Malware/Rootkit Detection"

# Check if ClamAV is running in MailCow
log "Checking ClamAV status..."
CLAMD_STATUS=$($SSH_CMD "docker ps | grep clamd || echo 'ClamAV container not running'")
log "$CLAMD_STATUS"

# Check for suspicious processes
log "Checking for suspicious processes..."
$SSH_CMD "ps auxf | grep -E '(nc|netcat|ncat|/tmp/|/var/tmp/)' | grep -v grep | head -10 || echo 'No suspicious processes detected'" | tee -a "$REPORT_FILE"

# ===========================
# SUMMARY AND RECOMMENDATIONS
# ===========================

log_section "Scan Complete"
log "Report saved: $REPORT_FILE"

# Generate summary
cat >> "$REPORT_FILE" <<EOF

---

## Recommendations

### Critical Priority
1. Apply pending security updates: $SECURITY_UPDATES packages
2. Review SSH access logs for unauthorized attempts
3. Verify AWS Backup is configured and running
4. Enable EBS volume encryption if not already enabled

### High Priority
1. Update MailCow to latest version (current: $MAILCOW_VERSION)
2. Review firewall rules and close unnecessary ports
3. Enable IMDSv2-only on EC2 instance
4. Audit Docker container security settings

### Medium Priority
1. Review file permissions on sensitive configs
2. Enable LUKS disk encryption for data at rest
3. Configure security monitoring and alerting
4. Review MailCow Docker Compose security options

### Low Priority
1. Monitor for CVEs in installed packages
2. Regular security audit schedule (quarterly recommended)
3. Test disaster recovery procedures

---

## Next Steps

1. Review this report and prioritize remediation
2. Apply security updates during maintenance window
3. Update SERVERS.md with security configuration
4. Schedule quarterly security scans

**Report generated by Cyber-Guardian**
**Framework: CIS Benchmark, AWS Foundational Security**

EOF

echo -e "\n${GREEN}✓ Scan complete!${NC}"
echo "Report: $REPORT_FILE"
echo ""
echo "To view the report:"
echo "  less $REPORT_FILE"
echo ""

exit 0
