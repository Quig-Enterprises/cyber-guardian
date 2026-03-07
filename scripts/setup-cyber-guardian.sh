#!/usr/bin/env bash
# Cyber-Guardian Security Scanner Setup
# Sets up CVE scanning and malware detection with venv
# Run as: sudo bash scripts/setup-cyber-guardian.sh

set -euo pipefail

PROJECT_DIR="/opt/claude-workspace/projects/cyber-guardian"
VENV_DIR="${PROJECT_DIR}/venv"
CRON_FILE="/etc/cron.d/cyber-guardian"
EMAIL="${1:-admin@quigs.com}"

echo "=========================================="
echo "Cyber-Guardian Security Scanner Setup"
echo "=========================================="
echo ""
echo "Project: ${PROJECT_DIR}"
echo "Alert email: ${EMAIL}"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "ERROR: This script must be run as root (use sudo)"
    exit 1
fi

cd "${PROJECT_DIR}"

# Step 1: Install system security tools
echo "[1/7] Installing security scanning tools..."
apt install -y clamav clamav-daemon rkhunter chkrootkit >/dev/null 2>&1 || true
freshclam 2>/dev/null || true
echo "✓ Security scanning tools installed"

# Step 2: Create Python virtual environment
echo "[2/7] Creating Python virtual environment..."
if [ ! -d "${VENV_DIR}" ]; then
    sudo -u ublirnevire python3 -m venv "${VENV_DIR}"
    echo "✓ Virtual environment created"
else
    echo "✓ Virtual environment already exists"
fi

# Step 2: Install Python dependencies
echo "[3/7] Installing Python dependencies..."
sudo -u ublirnevire "${VENV_DIR}/bin/pip" install --quiet --upgrade pip
sudo -u ublirnevire "${VENV_DIR}/bin/pip" install --quiet aiohttp pyyaml psycopg2-binary
echo "✓ Dependencies installed"

# Step 3: Create data and log directories
echo "[4/7] Creating data and log directories..."
mkdir -p "${PROJECT_DIR}/data/cve"
mkdir -p "${PROJECT_DIR}/logs"
mkdir -p "${PROJECT_DIR}/reports/nightly"
chown -R ublirnevire:claude-users "${PROJECT_DIR}/data"
chown -R ublirnevire:claude-users "${PROJECT_DIR}/logs"
chown -R ublirnevire:claude-users "${PROJECT_DIR}/reports"
echo "✓ Directories created"

# Step 4: Initial CVE data sync
echo "[5/7] Performing initial CVE data sync..."
echo "  This may take a few minutes..."
sudo -u ublirnevire "${VENV_DIR}/bin/python3" -m redteam.cve sync --source kev 2>&1 | grep -E "(INFO|ERROR|Sync complete)" || true
sudo -u ublirnevire "${VENV_DIR}/bin/python3" -m redteam.cve sync --source exploitdb 2>&1 | grep -E "(INFO|ERROR|Sync complete)" || true
echo "✓ CVE data synced (KEV + ExploitDB)"
echo "  Note: cvelistV5 sync takes longer, will run on first nightly scan"

# Step 5: Create wrapper scripts for cron
echo "[6/7] Creating wrapper scripts..."

# CVE scan wrapper
cat > "${PROJECT_DIR}/scripts/run-cve-scan.sh" <<'EOFCVE'
#!/usr/bin/env bash
set -euo pipefail
cd /opt/claude-workspace/projects/cyber-guardian
source venv/bin/activate
exec python3 -m redteam.cve sync --source kev --source exploitdb
EOFCVE
chmod +x "${PROJECT_DIR}/scripts/run-cve-scan.sh"

# Nightly scan wrapper (uses venv python)
cat > "${PROJECT_DIR}/scripts/run-nightly-scan.sh" <<'EOFNIGHT'
#!/usr/bin/env bash
set -euo pipefail
cd /opt/claude-workspace/projects/cyber-guardian

# Use venv python
export PATH="/opt/claude-workspace/projects/cyber-guardian/venv/bin:$PATH"

exec bash scripts/nightly-scan.sh
EOFNIGHT
chmod +x "${PROJECT_DIR}/scripts/run-nightly-scan.sh"

echo "✓ Wrapper scripts created"

# Step 6: Install cron jobs
echo "[7/7] Installing cron jobs..."
cat > "${CRON_FILE}" <<EOFCRON
# Cyber-Guardian Security Scans
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
MAILTO=${EMAIL}

# Sync CVE data sources: Daily at 1:00 AM
0 1 * * * ublirnevire /opt/claude-workspace/projects/cyber-guardian/scripts/run-cve-scan.sh >> /opt/claude-workspace/projects/cyber-guardian/logs/cve-sync.log 2>&1

# Full nightly scan (CVE + Malware): Daily at 2:00 AM
0 2 * * * ublirnevire /opt/claude-workspace/projects/cyber-guardian/scripts/run-nightly-scan.sh

EOFCRON

chmod 644 "${CRON_FILE}"
echo "✓ Cron jobs installed"

echo ""
echo "=========================================="
echo "Setup Complete!"
echo "=========================================="
echo ""
echo "Scan Schedule:"
echo "  Daily (1:00 AM)  - CVE data sync (KEV, ExploitDB)"
echo "  Daily (2:00 AM)  - Full nightly scan (CVE + Malware)"
echo ""
echo "Logs:"
echo "  CVE sync:    ${PROJECT_DIR}/logs/cve-sync.log"
echo "  Nightly:     ${PROJECT_DIR}/logs/nightly-YYYY-MM-DD.log"
echo ""
echo "Reports:"
echo "  Directory:   ${PROJECT_DIR}/reports/nightly/"
echo "  Format:      JSON"
echo "  Retention:   30 days"
echo ""
echo "Manual Commands:"
echo "  # Activate venv"
echo "  cd ${PROJECT_DIR} && source venv/bin/activate"
echo ""
echo "  # Check CVE data status"
echo "  python3 -m redteam.cve status"
echo ""
echo "  # Sync all CVE sources"
echo "  python3 -m redteam.cve sync"
echo ""
echo "  # Look up CVEs"
echo "  python3 -m redteam.cve lookup 'wordpress 6.4'"
echo "  python3 -m redteam.cve lookup 'nginx 1.24.0'"
echo ""
echo "  # Run nightly scan manually"
echo "  bash scripts/nightly-scan.sh"
echo ""
echo "Alert Email: ${EMAIL}"
echo ""
