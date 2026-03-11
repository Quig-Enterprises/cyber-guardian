#!/bin/bash
#
# Hourly Security Scan - Automated Codebase Scanner
#
# Runs Blue Team codebase scanner every hour and:
# - Generates timestamped reports
# - Checks for new CRITICAL/HIGH issues
# - Sends alerts if severity increases
# - Maintains scan history
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
REPORTS_DIR="$PROJECT_DIR/reports"
STATE_DIR="$PROJECT_DIR/.scan-state"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Colors for output
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

# Ensure state directory exists
mkdir -p "$STATE_DIR"

# Log function
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$STATE_DIR/scan.log"
}

log "Starting hourly security scan..."

# Run the scan (allow non-zero exit code if vulnerabilities found)
cd "$PROJECT_DIR"
python3 blueteam/cli_codebase_scan.py --quiet > /dev/null 2>&1 || true

# Find the latest report
LATEST_JSON=$(ls -t "$REPORTS_DIR"/codebase-security-scan-*.json 2>/dev/null | head -1)

if [ -z "$LATEST_JSON" ] || [ ! -f "$LATEST_JSON" ]; then
    log "ERROR: No scan report generated"
    exit 1
fi

# Extract severity counts from latest scan
CRITICAL=$(jq -r '.summary.critical' "$LATEST_JSON")
HIGH=$(jq -r '.summary.high' "$LATEST_JSON")
MEDIUM=$(jq -r '.summary.medium' "$LATEST_JSON")
TOTAL=$(jq -r '.summary.total_issues' "$LATEST_JSON")

# Save current counts
echo "$CRITICAL $HIGH $MEDIUM $TOTAL" > "$STATE_DIR/latest-counts.txt"

# Track individual issues (not just counts)
log "Tracking individual vulnerabilities..."
python3 "$PROJECT_DIR/blueteam/api/issue_tracker.py" "$LATEST_JSON" > "$STATE_DIR/tracker-output.txt" 2>&1

# Extract tracker results
NEW_ISSUES=$(grep "^New issues:" "$STATE_DIR/tracker-output.txt" | awk '{print $3}')
FIXED_ISSUES=$(grep "^Fixed issues:" "$STATE_DIR/tracker-output.txt" | awk '{print $3}')
PERSISTENT_ISSUES=$(grep "^Persistent issues:" "$STATE_DIR/tracker-output.txt" | awk '{print $3}')

# Check for changes from previous scan
if [ -f "$STATE_DIR/previous-counts.txt" ]; then
    read PREV_CRITICAL PREV_HIGH PREV_MEDIUM PREV_TOTAL < "$STATE_DIR/previous-counts.txt"

    CRITICAL_DIFF=$((CRITICAL - PREV_CRITICAL))
    HIGH_DIFF=$((HIGH - PREV_HIGH))
    TOTAL_DIFF=$((TOTAL - PREV_TOTAL))

    log "Scan complete: $TOTAL issues ($CRITICAL CRITICAL, $HIGH HIGH, $MEDIUM MEDIUM)"

    # Report on individual issue changes
    if [ -n "$NEW_ISSUES" ] && [ "$NEW_ISSUES" -gt 0 ]; then
        log "${YELLOW}NEW: $NEW_ISSUES vulnerabilities appeared${NC}"
    fi

    if [ -n "$FIXED_ISSUES" ] && [ "$FIXED_ISSUES" -gt 0 ]; then
        log "${GREEN}FIXED: $FIXED_ISSUES vulnerabilities resolved ✓${NC}"
    fi

    # Alert if severity increased
    if [ $CRITICAL_DIFF -gt 0 ] || [ $HIGH_DIFF -gt 0 ]; then
        log "${RED}ALERT: Severity increased!${NC}"
        log "  CRITICAL: $PREV_CRITICAL → $CRITICAL (+$CRITICAL_DIFF)"
        log "  HIGH: $PREV_HIGH → $HIGH (+$HIGH_DIFF)"

        # Send email notification
        ALERT_SUBJECT="[Cyber-Guardian] Security Alert: +$CRITICAL_DIFF CRITICAL, +$HIGH_DIFF HIGH issues"
        ALERT_BODY="Security scan detected increased severity on $(hostname):

Previous scan: $PREV_CRITICAL CRITICAL, $PREV_HIGH HIGH
Current scan:  $CRITICAL CRITICAL, $HIGH HIGH

Changes:
  CRITICAL: +$CRITICAL_DIFF
  HIGH:     +$HIGH_DIFF

New vulnerabilities: $NEW_ISSUES
Fixed vulnerabilities: $FIXED_ISSUES
Persistent vulnerabilities: $PERSISTENT_ISSUES

Latest report: $LATEST_JSON

Security Dashboard: https://8qdj5it341kfv92u.brandonquig.com/security-dashboard/

Generated at: $(date '+%Y-%m-%d %H:%M:%S')"

        "$SCRIPT_DIR/send-security-alert.sh" "$ALERT_SUBJECT" "$ALERT_BODY" >> "$STATE_DIR/scan.log" 2>&1 || log "WARNING: Failed to send email alert"
    elif [ $TOTAL_DIFF -lt 0 ]; then
        log "${GREEN}IMPROVEMENT: $((TOTAL_DIFF * -1)) total issues resolved${NC}"
    fi
else
    log "Scan complete: $TOTAL issues ($CRITICAL CRITICAL, $HIGH HIGH, $MEDIUM MEDIUM)"
    log "First scan - baseline established"
fi

# Update previous counts for next run
cp "$STATE_DIR/latest-counts.txt" "$STATE_DIR/previous-counts.txt"

# Run WordPress log accessibility scan (every 6 hours)
HOUR=$(date +%H)
if [ "$((HOUR % 6))" -eq 0 ]; then
    log "Running WordPress log accessibility scan..."
    WP_LOG_REPORT="$REPORTS_DIR/wordpress-log-scan-$TIMESTAMP.json"
    python3 "$PROJECT_DIR/scripts/wordpress-log-scanner.py" --server peter --output "$WP_LOG_REPORT" >> "$STATE_DIR/wp-log-scan.log" 2>&1

    # Check for vulnerabilities
    if [ -f "$WP_LOG_REPORT" ]; then
        VULNERABLE_SITES=$(jq -r '.vulnerable_sites' "$WP_LOG_REPORT")
        TOTAL_VULNERABLE_LOGS=$(jq -r '.total_vulnerable_logs' "$WP_LOG_REPORT")

        if [ "$VULNERABLE_SITES" -gt 0 ]; then
            log "${RED}WARNING: $VULNERABLE_SITES WordPress sites have exposed log files!${NC}"
            log "  Total vulnerable logs: $TOTAL_VULNERABLE_LOGS"

            # Send alert
            WP_ALERT_SUBJECT="[Cyber-Guardian] WordPress Log Exposure: $VULNERABLE_SITES sites vulnerable"
            WP_ALERT_BODY="WordPress log accessibility scan detected exposed log files on $(hostname):

Vulnerable sites: $VULNERABLE_SITES
Total exposed log files: $TOTAL_VULNERABLE_LOGS

Report: $WP_LOG_REPORT

Security Dashboard: https://8qdj5it341kfv92u.brandonquig.com/security-dashboard/

Generated at: $(date '+%Y-%m-%d %H:%M:%S')"

            "$SCRIPT_DIR/send-security-alert.sh" "$WP_ALERT_SUBJECT" "$WP_ALERT_BODY" >> "$STATE_DIR/scan.log" 2>&1 || log "WARNING: Failed to send email alert"
        else
            log "${GREEN}✓ WordPress log scan: All sites secure${NC}"
        fi
    fi
fi

# Generate mitigation TODOs and dashboard (once daily at midnight)
if [ "$HOUR" = "00" ]; then
    log "Generating mitigation TODOs and dashboard..."
    python3 "$PROJECT_DIR/scripts/generate-mitigation-todos.py" >> "$STATE_DIR/todo-generation.log" 2>&1
    log "TODO generation complete"
fi

# Cleanup old reports (keep last 168 hours = 1 week)
find "$REPORTS_DIR" -name "codebase-security-scan-*.json" -mtime +7 -delete 2>/dev/null || true
find "$REPORTS_DIR" -name "codebase-security-scan-*.md" -mtime +7 -delete 2>/dev/null || true

log "Hourly scan complete"
