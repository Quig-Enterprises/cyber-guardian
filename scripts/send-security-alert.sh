#!/bin/bash
#
# Send Security Alert Email
#
# Sends email alerts for cyber-guardian security findings using Python SMTP
#

SUBJECT="$1"
BODY="$2"

# Get email from environment (falls back to hostname-based)
HOSTNAME=$(hostname)
TO_EMAIL="${CYBER_GUARDIAN_EMAIL:-${HOSTNAME}@devteam.quigs.com}"
FROM_EMAIL="${CYBER_GUARDIAN_EMAIL:-${HOSTNAME}@devteam.quigs.com}"

# Use Python to send via SMTP (more reliable than mail command)
python3 - "$SUBJECT" "$BODY" "$FROM_EMAIL" "$TO_EMAIL" << 'EOPY'
import smtplib
import sys
from email.mime.text import MIMEText
from datetime import datetime

subject = sys.argv[1]
body = sys.argv[2]
from_addr = sys.argv[3]
to_addr = sys.argv[4]

msg = MIMEText(body)
msg['Subject'] = subject
msg['From'] = from_addr
msg['To'] = to_addr
msg['Date'] = datetime.now().strftime('%a, %d %b %Y %H:%M:%S %z')

try:
    # Use local SMTP (postfix)
    server = smtplib.SMTP('localhost', 25, timeout=10)
    server.send_message(msg)
    server.quit()
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Sent email alert to {to_addr}: {subject}")
except Exception as e:
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] ERROR sending email: {e}")
    sys.exit(1)
EOPY

