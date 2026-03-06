#!/usr/bin/env bash
# Cyber-Guardian Red Team - Autonomous Runner
#
# Runs red team attacks, copies reports to the dashboard directory,
# and imports results into the blue team posture scoring system.
#
# Usage:
#   run-redteam.sh                  # Run all attacks
#   run-redteam.sh --category ai    # Run specific category
#   run-redteam.sh --category compliance --no-cleanup
#
# Environment:
#   EQMON_AUTH_DB_PASS  - Required for blue team import
#
# Cron examples:
#   # Full suite weekly (Sunday 2am)
#   0 2 * * 0 /opt/claude-workspace/projects/cyber-guardian/bin/run-redteam.sh --all 2>&1 | logger -t redteam
#
#   # Compliance-only daily (3am)
#   0 3 * * * /opt/claude-workspace/projects/cyber-guardian/bin/run-redteam.sh --category compliance 2>&1 | logger -t redteam

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
REPORT_DIR="$PROJECT_DIR/reports"
DASHBOARD_REPORT_DIR="/opt/security-red-team/reports"
BLUETEAM_DIR="/opt/security-blue-team"
LOG_DIR="$PROJECT_DIR/logs"
LOCKFILE="/tmp/redteam-runner.lock"

# Default to --all if no arguments
RUNNER_ARGS="${@:---all}"

# Ensure log directory exists
mkdir -p "$LOG_DIR"

LOGFILE="$LOG_DIR/redteam-$(date +%Y%m%d_%H%M%S).log"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOGFILE"
}

# Prevent concurrent runs
if [ -f "$LOCKFILE" ]; then
    LOCK_PID=$(cat "$LOCKFILE" 2>/dev/null || echo "")
    if [ -n "$LOCK_PID" ] && kill -0 "$LOCK_PID" 2>/dev/null; then
        log "ERROR: Another run is in progress (PID $LOCK_PID). Exiting."
        exit 1
    else
        log "WARN: Stale lock file found. Removing."
        rm -f "$LOCKFILE"
    fi
fi
echo $$ > "$LOCKFILE"
trap 'rm -f "$LOCKFILE"' EXIT

log "=== Cyber-Guardian Red Team Run ==="
log "Args: $RUNNER_ARGS"
log "Project: $PROJECT_DIR"

# Activate venv
cd "$PROJECT_DIR"
source venv/bin/activate

# Run attacks with all report formats
log "Starting attack suite..."
RUN_START=$(date +%s)

python -m redteam.runner $RUNNER_ARGS --report console json html 2>&1 | tee -a "$LOGFILE"
RUN_EXIT=$?

RUN_END=$(date +%s)
RUN_DURATION=$((RUN_END - RUN_START))
log "Attack suite finished in ${RUN_DURATION}s (exit code: $RUN_EXIT)"

if [ $RUN_EXIT -ne 0 ]; then
    log "ERROR: Runner exited with code $RUN_EXIT"
    # Continue anyway to copy whatever reports were generated
fi

# Find the latest JSON and HTML reports
LATEST_JSON=$(ls -t "$REPORT_DIR"/redteam-report-*.json 2>/dev/null | head -1)
LATEST_HTML=$(ls -t "$REPORT_DIR"/redteam-report-*.html 2>/dev/null | head -1)

if [ -z "$LATEST_JSON" ]; then
    log "ERROR: No JSON report found. Exiting."
    exit 1
fi

log "Latest report: $(basename "$LATEST_JSON")"

# Copy reports to dashboard directory
if [ -d "$DASHBOARD_REPORT_DIR" ]; then
    cp "$LATEST_JSON" "$DASHBOARD_REPORT_DIR/"
    [ -n "$LATEST_HTML" ] && cp "$LATEST_HTML" "$DASHBOARD_REPORT_DIR/"
    log "Reports copied to $DASHBOARD_REPORT_DIR"
else
    log "WARN: Dashboard report directory not found: $DASHBOARD_REPORT_DIR"
fi

# Import into blue team posture scoring
if [ -d "$BLUETEAM_DIR" ] && [ -f "$BLUETEAM_DIR/venv/bin/blueteam" ]; then
    DB_PASS="${EQMON_AUTH_DB_PASS:-3eK4NNHxLQakuTQK5KcnB3Vz}"
    log "Importing report into blue team posture scoring..."
    cd "$BLUETEAM_DIR"
    source venv/bin/activate
    EQMON_AUTH_DB_PASS="$DB_PASS" blueteam redteam import "$LATEST_JSON" 2>&1 | tee -a "$LOGFILE"
    log "Blue team import complete"
else
    log "WARN: Blue team not found at $BLUETEAM_DIR, skipping import"
fi

# Cleanup old logs (keep 30 days)
find "$LOG_DIR" -name "redteam-*.log" -mtime +30 -delete 2>/dev/null || true

log "=== Run complete ==="
log "Duration: ${RUN_DURATION}s"
log "Report: $(basename "$LATEST_JSON")"
