#!/usr/bin/env bash
# scan-job-wrapper.sh - Runs a red team scan for a given job_id and updates DB on completion.
#
# Usage: scan-job-wrapper.sh <job_id> <log_file> [runner args...]
#
# All runner args after log_file are passed verbatim to run-redteam.sh (already shell-safe).
# --job-id <N> is stripped before passing to the runner.

set -uo pipefail

JOB_ID="$1"
LOG_FILE="$2"
shift 2

PROJECT_DIR="/opt/claude-workspace/projects/cyber-guardian"
RUN_SCRIPT="$PROJECT_DIR/bin/run-redteam.sh"
DBHOST="127.0.0.1"
DBUSER="alfred_admin"
DBPASS="Xk9OUuMWtRkBEnY2jugt6992"
DBNAME="alfred_admin"

pg_exec() {
    PGPASSWORD="$DBPASS" psql -h "$DBHOST" -U "$DBUSER" -d "$DBNAME" -c "$1" -q 2>/dev/null || true
}

# Strip --job-id <N> from args before passing to runner
RUNNER_ARGS=()
skip_next=false
for arg in "$@"; do
    if $skip_next; then
        skip_next=false
        continue
    fi
    if [ "$arg" = "--job-id" ]; then
        skip_next=true
        continue
    fi
    RUNNER_ARGS+=("$arg")
done

# When multiple --category args are passed, run-redteam.sh doesn't support that natively.
# Detect and convert: if we have multiple --category flags, build a comma-separated list
# and run the runner once per category (simplest approach: loop).
CATEGORIES=()
OTHER_ARGS=()
i=0
args_arr=("${RUNNER_ARGS[@]:-}")
while [ $i -lt ${#args_arr[@]} ]; do
    a="${args_arr[$i]}"
    if [ "$a" = "--category" ]; then
        i=$((i+1))
        CATEGORIES+=("${args_arr[$i]}")
    elif [ "$a" = "--all" ]; then
        CATEGORIES=("all")
    else
        OTHER_ARGS+=("$a")
    fi
    i=$((i+1))
done

# Find latest report in the redteam reports directory
get_latest_report() {
    ls -t "$PROJECT_DIR/redteam/reports"/redteam-report-*.json 2>/dev/null | head -1 | xargs -r basename
}

EXIT_CODE=0
# Record timestamp before run so we can identify the report this job produced
RUN_START_TIME=$(date +%s)

if [ ${#CATEGORIES[@]} -eq 0 ] || ([ ${#CATEGORIES[@]} -eq 1 ] && [ "${CATEGORIES[0]}" = "all" ]); then
    bash "$RUN_SCRIPT" --all "${OTHER_ARGS[@]:-}" 2>&1
    EXIT_CODE=$?
else
    # Run each category sequentially
    for cat in "${CATEGORIES[@]}"; do
        bash "$RUN_SCRIPT" --category "$cat" "${OTHER_ARGS[@]:-}" 2>&1 || EXIT_CODE=$?
    done
fi

# Find the report created during this job (newer than when we started)
REPORT=$(ls -t "$PROJECT_DIR/redteam/reports"/redteam-report-*.json 2>/dev/null \
    | while read -r f; do
        [ "$(stat -c %Y "$f")" -ge "$RUN_START_TIME" ] && basename "$f" && break
      done)
# Fallback to latest if none matched by timestamp
[ -z "$REPORT" ] && REPORT=$(get_latest_report)
STATUS="done"
[ $EXIT_CODE -ne 0 ] && STATUS="failed"

pg_exec "UPDATE blueteam.scan_jobs SET status='$STATUS', finished_at=NOW(), exit_code=$EXIT_CODE, report_json=$([ -n "$REPORT" ] && echo "'$REPORT'" || echo "NULL") WHERE job_id=$JOB_ID"

echo "[scan-job-wrapper] Job $JOB_ID finished: status=$STATUS exit_code=$EXIT_CODE report=$REPORT"
