#!/usr/bin/env bash
# Cyber-Guardian Nightly Scan
# Runs CVE (with data sync) and malware scans, generates reports.
# Designed to be called by systemd timer or cron.

set -euo pipefail

PROJECT_DIR="/opt/claude-workspace/projects/cyber-guardian"
REPORT_DIR="${PROJECT_DIR}/reports/nightly"
LOG_DIR="${PROJECT_DIR}/logs"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
DATE=$(date +%Y-%m-%d)
LOG_FILE="${LOG_DIR}/nightly-${DATE}.log"

mkdir -p "${REPORT_DIR}" "${LOG_DIR}"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "${LOG_FILE}"
}

cd "${PROJECT_DIR}"
export PYTHONPATH="${PROJECT_DIR}"

log "=== Cyber-Guardian Nightly Scan Starting ==="

# Phase 1: Sync CVE data
log "Phase 1: Syncing CVE data sources..."
if python3 -m redteam.cve.sync >> "${LOG_FILE}" 2>&1; then
    log "CVE data sync complete"
else
    log "WARNING: CVE data sync had errors (continuing anyway)"
fi

# Phase 2: CVE scan
log "Phase 2: Running CVE scan..."
python3 redteam/runner.py \
    --category cve \
    --target app \
    --report console json \
    --output "${REPORT_DIR}" \
    >> "${LOG_FILE}" 2>&1 || true
log "CVE scan complete"

# Phase 3: Malware scan
log "Phase 3: Running malware scan..."
python3 redteam/runner.py \
    --category malware \
    --target app \
    --report console json \
    --output "${REPORT_DIR}" \
    >> "${LOG_FILE}" 2>&1 || true
log "Malware scan complete"

# Phase 4: Cleanup old nightly reports (keep 30 days)
find "${REPORT_DIR}" -name "*.json" -mtime +30 -delete 2>/dev/null || true
find "${LOG_DIR}" -name "nightly-*.log" -mtime +30 -delete 2>/dev/null || true

log "=== Cyber-Guardian Nightly Scan Complete ==="

# Print summary for systemd journal
VULN_COUNT=$(grep -c '"status": "vulnerable"' "${REPORT_DIR}"/redteam-report-${TIMESTAMP}*.json 2>/dev/null || echo "0")
log "Summary: ${VULN_COUNT} vulnerable finding(s) in tonight's scan"
