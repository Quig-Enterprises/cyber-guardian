#!/usr/bin/env bash
# apply-crontab.sh - Safely apply managed red team crontab entries
#
# Reads managed schedule lines from stdin, preserves all non-managed
# crontab lines, writes the combined result.
#
# Usage:
#   echo "0 2 * * 0 /path/to/run-redteam.sh --all" | ./apply-crontab.sh
#
# Sudoers rule (add to /etc/sudoers.d/cyber-guardian):
#   www-data ALL=(brandon) NOPASSWD: /opt/claude-workspace/projects/cyber-guardian/bin/apply-crontab.sh

set -euo pipefail

MARKER_BEGIN="# BEGIN cyber-guardian-schedules"
MARKER_END="# END cyber-guardian-schedules"

# Read new managed entries from stdin
MANAGED_LINES=$(cat)

# Get current crontab (suppress error if empty)
CURRENT=$(crontab -l 2>/dev/null || true)

# Remove existing managed block
CLEANED=$(echo "$CURRENT" | sed "/${MARKER_BEGIN}/,/${MARKER_END}/d")

# Build new crontab
{
    echo "$CLEANED"
    echo ""
    echo "$MARKER_BEGIN"
    if [ -n "$MANAGED_LINES" ]; then
        echo "$MANAGED_LINES"
    fi
    echo "$MARKER_END"
} | crontab -

echo "Crontab updated successfully"
