#!/bin/bash
#
# Weekly Lynis Audit Cron Job
# Runs comprehensive Lynis audits on all servers and logs results
#
# Schedule: Every Sunday at 2:00 AM CDT
# Cron entry: 0 2 * * 0 /opt/claude-workspace/projects/cyber-guardian/scripts/weekly-audit-cron.sh

set -e

SCRIPT_DIR="/opt/claude-workspace/projects/cyber-guardian/scripts"
LOG_DIR="/var/log/cyber-guardian"
LOG_FILE="$LOG_DIR/lynis-weekly-$(date +%Y%m%d).log"
ERROR_LOG="$LOG_DIR/lynis-errors.log"

# Create log directory if it doesn't exist
mkdir -p "$LOG_DIR"

# Function to log with timestamp
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# Function to send email alert (optional - requires mailx/sendmail)
send_alert() {
    local subject="$1"
    local message="$2"

    # Uncomment to enable email alerts
    # echo "$message" | mail -s "$subject" admin@quigs.com

    log "ALERT: $subject - $message"
}

# Start audit
log "========================================="
log "Weekly Lynis Audit Started"
log "========================================="

# Check if audit script exists
if [ ! -f "$SCRIPT_DIR/audit-all-servers.sh" ]; then
    send_alert "Lynis Cron Error" "audit-all-servers.sh script not found"
    log "ERROR: Script not found at $SCRIPT_DIR/audit-all-servers.sh"
    exit 1
fi

# Run audit and capture output
log "Running comprehensive audit on all servers..."
if bash "$SCRIPT_DIR/audit-all-servers.sh" >> "$LOG_FILE" 2>&1; then
    log "✓ All audits completed successfully"

    # Get current scores from database
    SCORES=$(psql postgresql://eqmon:Mtd2l6LXNlcnAiF25vZGVyZ@localhost/eqmon -t -c "
        SELECT server_name || ': ' || combined_score || '/100'
        FROM blueteam.v_security_posture
        ORDER BY server_name;
    " 2>/dev/null || echo "Unable to retrieve scores")

    log "Current Security Scores:"
    echo "$SCORES" | while read -r line; do
        log "  $line"
    done

    # Check for score degradation
    DEGRADED=$(psql postgresql://eqmon:Mtd2l6LXNlcnAiF25vZGVyZ@localhost/eqmon -t -c "
        SELECT COUNT(*)
        FROM blueteam.v_security_posture
        WHERE combined_score < 70;
    " 2>/dev/null || echo "0")

    if [ "$DEGRADED" -gt 0 ]; then
        send_alert "Lynis Score Alert" "$DEGRADED server(s) below 70/100 threshold"
        log "⚠ WARNING: $DEGRADED server(s) below threshold"
    fi

else
    send_alert "Lynis Audit Failed" "Weekly audit encountered errors - check logs"
    log "✗ ERROR: Audit failed - see $LOG_FILE for details"
    exit 1
fi

# Log rotation - keep last 12 weeks
log "Rotating old logs..."
find "$LOG_DIR" -name "lynis-weekly-*.log" -mtime +84 -delete 2>/dev/null || true
log "Log rotation complete"

log "========================================="
log "Weekly Lynis Audit Completed"
log "========================================="

# Print summary
echo ""
echo "Weekly Audit Summary - $(date)"
echo "Log file: $LOG_FILE"
echo ""
echo "View results:"
echo "  cat $LOG_FILE"
echo "  psql postgresql://eqmon:PASSWORD@localhost/eqmon -c \"SELECT * FROM blueteam.v_security_posture;\""
echo ""

exit 0
