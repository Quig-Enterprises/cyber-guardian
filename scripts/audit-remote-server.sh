#!/bin/bash
#
# Remote Lynis Audit Runner
# Runs Lynis audit on a remote server via SSH and stores results in alfred's database
#
# Usage: bash audit-remote-server.sh <server-name> <ssh-host> <ssh-key>
# Example: bash audit-remote-server.sh willie mailcow.tailce791f.ts.net ~/.ssh/bq_laptop_rsa

set -e

# Check arguments
if [ $# -lt 3 ]; then
    echo "Usage: $0 <server-name> <ssh-host> <ssh-key>"
    echo "Example: $0 willie mailcow.tailce791f.ts.net ~/.ssh/bq_laptop_rsa"
    exit 1
fi

SERVER_NAME="$1"
SSH_HOST="$2"
SSH_KEY="$3"
SSH_USER="${4:-ubuntu}"

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
TEMP_DIR="/tmp/lynis-audit-$$"

echo "========================================"
echo "Remote Lynis Audit"
echo "========================================"
echo "Server: $SERVER_NAME"
echo "SSH Host: $SSH_HOST"
echo "SSH User: $SSH_USER"
echo "Date: $(date)"
echo "========================================"
echo ""

# Create temp directory
mkdir -p "$TEMP_DIR"

# Step 1: Run Lynis on remote server
echo "[1/4] Running Lynis audit on $SERVER_NAME..."
ssh -i "$SSH_KEY" -o ConnectTimeout=10 "$SSH_USER@$SSH_HOST" \
    "sudo lynis audit system --no-colors --quiet" > "$TEMP_DIR/lynis-output.txt" 2>&1 || true

echo "✓ Lynis audit complete"

# Step 2: Copy report file from remote server
echo "[2/4] Retrieving audit report..."
ssh -i "$SSH_KEY" "$SSH_USER@$SSH_HOST" \
    "sudo cat /var/log/lynis-report.dat" > "$TEMP_DIR/lynis-report.dat" 2>&1

if [ ! -s "$TEMP_DIR/lynis-report.dat" ]; then
    echo "Error: Failed to retrieve Lynis report"
    exit 1
fi

echo "✓ Report retrieved ($(wc -l < "$TEMP_DIR/lynis-report.dat") lines)"

# Step 3: Parse report and store in database
echo "[3/4] Parsing findings and storing in database..."

# Create a modified version of the auditor that reads from a file
python3 - <<EOF
import sys
import os
import psycopg2
from psycopg2.extras import execute_values
from datetime import datetime
from pathlib import Path

# Database configuration
DB_CONFIG = {
    'host': os.getenv('DB_HOST', 'localhost'),
    'port': int(os.getenv('DB_PORT', '5432')),
    'database': os.getenv('DB_NAME', 'eqmon'),
    'user': os.getenv('DB_USER', 'eqmon'),
}

# Get password from .pgpass
PGPASS_FILE = Path.home() / ".pgpass"
if PGPASS_FILE.exists():
    with open(PGPASS_FILE) as f:
        for line in f:
            parts = line.strip().split(":")
            if len(parts) == 5 and parts[0] == DB_CONFIG["host"] and \
               parts[2] == DB_CONFIG["database"] and parts[3] == DB_CONFIG["user"]:
                DB_CONFIG["password"] = parts[4]
                break

# Parse report file
findings = []
report_data = {}

with open('$TEMP_DIR/lynis-report.dat', 'r') as f:
    for line in f:
        line = line.strip()
        if not line or line.startswith('#'):
            continue

        if line.startswith('warning[]='):
            warning = line.split('=', 1)[1]
            parts = warning.split('|', 1)
            if len(parts) == 2:
                test_id, description = parts
            else:
                test_id = 'unknown'
                description = warning

            findings.append({
                'test_id': test_id.strip(),
                'finding_type': 'warning',
                'severity': 'medium',
                'description': description.strip()
            })

        elif line.startswith('suggestion[]='):
            suggestion = line.split('=', 1)[1]
            parts = suggestion.split('|', 1)
            if len(parts) == 2:
                test_id, description = parts
            else:
                test_id = 'unknown'
                description = suggestion

            findings.append({
                'test_id': test_id.strip(),
                'finding_type': 'suggestion',
                'severity': 'low',
                'description': description.strip()
            })

        elif line.startswith('hardening_index='):
            report_data['hardening_index'] = int(line.split('=')[1])

        elif line.startswith('lynis_tests_done='):
            report_data['tests_performed'] = int(line.split('=')[1])

# Store in database
try:
    conn = psycopg2.connect(**DB_CONFIG)
    cur = conn.cursor()

    # Insert audit record
    cur.execute("""
        INSERT INTO blueteam.lynis_audits (
            server_name,
            audit_date,
            hardening_index,
            tests_performed,
            warnings_count,
            suggestions_count
        )
        VALUES (%s, %s, %s, %s, %s, %s)
        RETURNING audit_id
    """, (
        '$SERVER_NAME',
        datetime.now(),
        report_data.get('hardening_index', 0),
        report_data.get('tests_performed', 0),
        len([f for f in findings if f['finding_type'] == 'warning']),
        len([f for f in findings if f['finding_type'] == 'suggestion'])
    ))

    audit_id = cur.fetchone()[0]

    # Insert findings
    if findings:
        finding_values = [
            (
                audit_id,
                f['test_id'],
                f['finding_type'],
                f['severity'],
                f['description']
            )
            for f in findings
        ]

        execute_values(
            cur,
            """
            INSERT INTO blueteam.lynis_findings (
                audit_id,
                test_id,
                finding_type,
                severity,
                description
            ) VALUES %s
            """,
            finding_values
        )

    conn.commit()

    print(f"✓ Database updated: audit_id={audit_id}, findings={len(findings)}")
    print(f"  Hardening Index: {report_data.get('hardening_index', 0)}/100")
    print(f"  Tests: {report_data.get('tests_performed', 0)}")
    print(f"  Warnings: {len([f for f in findings if f['finding_type'] == 'warning'])}")
    print(f"  Suggestions: {len([f for f in findings if f['finding_type'] == 'suggestion'])}")

    cur.close()
    conn.close()

except Exception as e:
    print(f"Database error: {e}")
    sys.exit(1)
EOF

# Step 4: Clean up
echo "[4/4] Cleaning up..."
rm -rf "$TEMP_DIR"

echo ""
echo "========================================"
echo "AUDIT COMPLETE"
echo "========================================"
echo "View results:"
echo "  SELECT * FROM blueteam.v_latest_lynis_audits WHERE server_name = '$SERVER_NAME';"
echo "  SELECT * FROM blueteam.v_security_posture;"
echo "========================================"
