#!/bin/bash
#
# Lynis Audit Runner Script
# Wrapper script to run Lynis audit with sudo privileges
#
# Usage: sudo bash run-lynis-audit.sh <server-name>
# Example: sudo bash run-lynis-audit.sh alfred

set -e

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Error: This script must be run as root (use sudo)"
    exit 1
fi

# Check arguments
if [ $# -lt 1 ]; then
    echo "Usage: sudo bash run-lynis-audit.sh <server-name>"
    echo "Example: sudo bash run-lynis-audit.sh alfred"
    exit 1
fi

SERVER_NAME="$1"
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

echo "=================================="
echo "Lynis Security Audit"
echo "=================================="
echo "Server: $SERVER_NAME"
echo "Date: $(date)"
echo "=================================="
echo ""

# Run Lynis audit as the calling user but with sudo for Lynis commands
sudo -u "$SUDO_USER" python3 "$SCRIPT_DIR/lynis-auditor.py" "$SERVER_NAME"

exit $?
