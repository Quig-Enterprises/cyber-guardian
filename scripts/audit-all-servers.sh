#!/bin/bash
#
# Audit All Servers Script
# Runs Lynis audits on all configured servers
#
# Usage: bash audit-all-servers.sh

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

echo "========================================"
echo "Cyber-Guardian Lynis Audit"
echo "========================================"
echo "Date: $(date)"
echo "Auditing all servers..."
echo "========================================"
echo ""

# Audit alfred (local)
echo "[1/3] Auditing alfred (local)..."
python3 "$SCRIPT_DIR/lynis-auditor.py" alfred
echo ""

# Audit willie (AWS EC2)
echo "[2/3] Auditing willie (remote)..."
bash "$SCRIPT_DIR/audit-remote-server.sh" willie mailcow.tailce791f.ts.net ~/.ssh/bq_laptop_rsa
echo ""

# Audit peter (production server)
echo "[3/3] Auditing peter (remote)..."
bash "$SCRIPT_DIR/audit-remote-server.sh" peter webhost.tailce791f.ts.net ~/.ssh/webhost_key
echo ""

echo "========================================"
echo "ALL AUDITS COMPLETE"
echo "========================================"
echo ""
echo "View combined security posture:"
echo "  psql postgresql://eqmon:\$PASSWORD@localhost/eqmon -c \"SELECT * FROM blueteam.v_security_posture;\""
echo ""
echo "View detailed findings:"
echo "  psql postgresql://eqmon:\$PASSWORD@localhost/eqmon -c \"SELECT * FROM blueteam.v_unresolved_lynis_findings;\""
echo "========================================"
