#!/usr/bin/env bash
# Cyber-Guardian Nightly Scan
# Runs CVE (with data sync) and malware scans, generates reports.
# Designed to be called by systemd timer or cron.

set -euo pipefail

PROJECT_DIR="/opt/claude-workspace/projects/cyber-guardian"
REPORT_DIR="${PROJECT_DIR}/reports/nightly"
LOG_DIR="${PROJECT_DIR}/logs"
MARKER_FILE="/tmp/cyber-guardian-scan-active.marker"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
DATE=$(date +%Y-%m-%d)
LOG_FILE="${LOG_DIR}/nightly-${DATE}.log"

mkdir -p "${REPORT_DIR}" "${LOG_DIR}"

# Clean up scan marker on exit (normal or error)
cleanup_marker() {
    rm -f "${MARKER_FILE}"
}
trap cleanup_marker EXIT

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "${LOG_FILE}"
}

cd "${PROJECT_DIR}"
export PYTHONPATH="${PROJECT_DIR}"

log "=== Cyber-Guardian Nightly Scan Starting ==="

# Set scan-active marker so blue team alerts are tagged as internal testing
echo "{\"source\": \"cyber-guardian-nightly\", \"started\": \"$(date -Iseconds)\", \"pid\": $$}" > "${MARKER_FILE}"
log "Scan marker set: ${MARKER_FILE}"

# Phase 1: Sync CVE data
log "Phase 1: Syncing CVE data sources..."
if python3 -m redteam.cve.sync >> "${LOG_FILE}" 2>&1; then
    log "CVE data sync complete"
else
    log "WARNING: CVE data sync had errors (continuing anyway)"
fi

# Phase 2: CVE scan
CVE_REPORT="${REPORT_DIR}/cve-scan-${DATE}.txt"
log "Phase 2: Running CVE scan..."
python3 redteam/runner.py \
    --category cve \
    --target app \
    --report console json \
    --output "${REPORT_DIR}" \
    --verbose \
    2>&1 | tee -a "${CVE_REPORT}" >> "${LOG_FILE}" || true
log "CVE scan complete — report: ${CVE_REPORT}"

# Phase 3: Malware scan
MALWARE_REPORT="${REPORT_DIR}/malware-scan-${DATE}.txt"
log "Phase 3: Running malware scan..."
python3 redteam/runner.py \
    --category malware \
    --target app \
    --report console json \
    --output "${REPORT_DIR}" \
    --verbose \
    2>&1 | tee -a "${MALWARE_REPORT}" >> "${LOG_FILE}" || true
log "Malware scan complete — report: ${MALWARE_REPORT}"

# Phase 4: Cleanup old nightly reports (keep 30 days)
find "${REPORT_DIR}" -name "*.json" -mtime +30 -delete 2>/dev/null || true
find "${REPORT_DIR}" -name "*.txt" -mtime +30 -delete 2>/dev/null || true
find "${LOG_DIR}" -name "nightly-*.log" -mtime +30 -delete 2>/dev/null || true

log "=== Cyber-Guardian Nightly Scan Complete ==="

# Print summary for systemd journal
VULN_COUNT=$(grep -c '"status": "vulnerable"' "${REPORT_DIR}"/redteam-report-${TIMESTAMP}*.json 2>/dev/null || echo "0")
log "Summary: ${VULN_COUNT} vulnerable finding(s) in tonight's scan"
