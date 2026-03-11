#!/usr/bin/env python3
"""
Cyber-Guardian Matrix Notifier
Version: 1.1.0
Date: 2026-03-11

Sends security findings to Matrix #cyber-guardian room.
Posts CRITICAL and HIGH severity findings as separate messages.
Tags appropriate bot based on affected server.

Usage:
    python3 send-to-matrix.py --scan-report reports/codebase-security-scan-*.json
    python3 send-to-matrix.py --compliance-report reports/compliance-*.json
    python3 send-to-matrix.py --compliance-scan-id 21 --min-severity MEDIUM
    python3 send-to-matrix.py --wp-log-report reports/wordpress-log-scan-*.json
"""

import argparse
import json
import logging
import os
import sys
from pathlib import Path
from typing import List, Dict
import psycopg2
from psycopg2.extras import RealDictCursor

# Add lib directory to path
sys.path.insert(0, str(Path(__file__).parent.parent / "lib" / "matrix-client"))
from matrix_client import MatrixClient

CYBER_GUARDIAN_ROOM = "#cyber-guardian:artemis-matrix.ecoeyetech.com"

# Bot mention tags based on server
BOT_MENTIONS = {
    "artemis": "@artemis:artemis-matrix.ecoeyetech.com",
    "willie": "@alfred-bot:alfred-matrix.quigs.com",
    "peter": "@alfred-bot:alfred-matrix.quigs.com",
    "alfred": "@alfred-bot:alfred-matrix.quigs.com",
}

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("matrix-notifier")


def get_bot_mention(server: str) -> str:
    """Get appropriate bot mention for server."""
    server_lower = server.lower()
    for key, mention in BOT_MENTIONS.items():
        if key in server_lower:
            return mention
    return BOT_MENTIONS["alfred"]  # Default to alfred-bot


def format_codebase_finding(finding: Dict, server: str = "alfred") -> str:
    """Format a codebase scan finding for Matrix."""
    severity = finding.get("severity", "UNKNOWN")
    category = finding.get("category", "Unknown")
    title = finding.get("title", "No title")
    description = finding.get("description", "")
    file_path = finding.get("file", "")
    line = finding.get("line", "")

    bot_mention = get_bot_mention(server)

    message = f"**[{severity}] {category}**\n"
    message += f"{title}\n\n"

    if description:
        message += f"{description}\n\n"

    if file_path:
        location = f"`{file_path}`"
        if line:
            location += f":{line}"
        message += f"**Location:** {location}\n"

    message += f"**Server:** {server}\n"
    message += f"\n{bot_mention}"

    return message


def format_compliance_finding(finding: Dict, server: str) -> str:
    """Format a compliance scan finding for Matrix."""
    severity = finding.get("severity", "UNKNOWN")
    check_id = finding.get("check_id", "unknown")
    title = finding.get("title", "No title")
    description = finding.get("description", "")
    recommendation = finding.get("recommendation", "")

    bot_mention = get_bot_mention(server)

    message = f"**[{severity}] Compliance: {check_id}**\n"
    message += f"{title}\n\n"

    if description:
        message += f"**Finding:** {description}\n\n"

    if recommendation:
        message += f"**Recommendation:** {recommendation}\n\n"

    message += f"**Server:** {server}\n"
    message += f"\n{bot_mention}"

    return message


def format_wordpress_log_finding(site_data: Dict, server: str = "peter") -> List[str]:
    """Format WordPress log vulnerability findings for Matrix.

    Returns list of messages (one per vulnerable log file).
    """
    domain = site_data.get("domain", "unknown")
    vulnerable_logs = site_data.get("vulnerable_logs", [])

    if not vulnerable_logs:
        return []

    messages = []
    bot_mention = get_bot_mention(server)

    for log in vulnerable_logs:
        severity = log.get("severity", "MEDIUM")
        path = log.get("path", "")
        url = log.get("url", "")

        message = f"**[{severity}] WordPress Log Exposure**\n"
        message += f"Publicly accessible log file detected\n\n"
        message += f"**Domain:** {domain}\n"
        message += f"**Path:** `{path}`\n"
        message += f"**URL:** {url}\n\n"
        message += f"**Recommendation:** Add .htaccess protection to wp-content/uploads/\n"
        message += f"**Server:** {server}\n"
        message += f"\n{bot_mention}"

        messages.append(message)

    return messages


def process_codebase_scan(report_path: str, min_severity: str = "HIGH") -> List[Dict]:
    """Extract CRITICAL/HIGH findings from codebase scan report.

    Returns list of (message, severity) tuples.
    """
    with open(report_path) as f:
        report = json.load(f)

    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    min_level = severity_order.get(min_severity, 1)

    findings = []
    for issue in report.get("issues", []):
        severity = issue.get("severity", "MEDIUM")
        if severity_order.get(severity, 3) <= min_level:
            message = format_codebase_finding(issue, server="alfred")
            findings.append({"message": message, "severity": severity})

    return findings


def process_compliance_scan(report_path: str, min_severity: str = "HIGH") -> List[Dict]:
    """Extract CRITICAL/HIGH findings from compliance scan report.

    Returns list of (message, severity) tuples.
    """
    with open(report_path) as f:
        report = json.load(f)

    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    min_level = severity_order.get(min_severity, 1)

    server = report.get("server", "unknown")

    findings = []
    for finding in report.get("findings", []):
        severity = finding.get("severity", "MEDIUM")
        if severity_order.get(severity, 3) <= min_level:
            message = format_compliance_finding(finding, server)
            findings.append({"message": message, "severity": severity})

    return findings


def process_compliance_scan_from_db(scan_id: int, min_severity: str = "HIGH") -> List[Dict]:
    """Extract CRITICAL/HIGH findings from compliance scan in database.

    Returns list of (message, severity) tuples.
    """
    # Database config (same as compliance-scanner.py)
    db_config = {
        "host": os.getenv("DB_HOST", "localhost"),
        "port": int(os.getenv("DB_PORT", "5432")),
        "database": os.getenv("DB_NAME", "eqmon"),
        "user": os.getenv("DB_USER", "eqmon"),
    }

    # Get password from .pgpass if available
    pgpass_file = Path.home() / ".pgpass"
    if pgpass_file.exists():
        with open(pgpass_file) as f:
            for line in f:
                parts = line.strip().split(":")
                if len(parts) == 5 and parts[0] == db_config["host"] and \
                   parts[2] == db_config["database"] and parts[3] == db_config["user"]:
                    db_config["password"] = parts[4]
                    break

    # Connect to database
    conn = psycopg2.connect(**db_config)
    cur = conn.cursor(cursor_factory=RealDictCursor)

    # Get scan info
    cur.execute("""
        SELECT server_name, server_type, scan_date, overall_score
        FROM blueteam.compliance_scans
        WHERE scan_id = %s
    """, (scan_id,))
    scan_info = cur.fetchone()

    if not scan_info:
        logger.error(f"Scan ID {scan_id} not found")
        return []

    server = scan_info['server_name']

    # Get findings
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    min_level = severity_order.get(min_severity, 1)

    cur.execute("""
        SELECT check_id, check_name, status, severity,
               finding_summary, finding_details, remediation_steps
        FROM blueteam.compliance_findings
        WHERE scan_id = %s
        ORDER BY
            CASE severity
                WHEN 'CRITICAL' THEN 0
                WHEN 'HIGH' THEN 1
                WHEN 'MEDIUM' THEN 2
                WHEN 'LOW' THEN 3
                ELSE 4
            END
    """, (scan_id,))

    findings = []
    for row in cur.fetchall():
        severity = (row['severity'] or 'MEDIUM').upper()
        status = row['status']

        # Only include failed/warning findings
        if status.upper() not in ('FAIL', 'WARNING'):
            continue

        # Filter by severity
        if severity_order.get(severity, 3) <= min_level:
            # Map database fields to expected format
            finding_dict = {
                "check_id": row['check_id'],
                "title": row['check_name'] or row['finding_summary'] or "No title",
                "description": row['finding_details'] or row['finding_summary'] or "",
                "recommendation": row['remediation_steps'] or "",
                "severity": severity
            }
            message = format_compliance_finding(finding_dict, server)
            findings.append({"message": message, "severity": severity})

    cur.close()
    conn.close()

    return findings


def process_wordpress_log_scan(report_path: str) -> List[Dict]:
    """Extract WordPress log vulnerabilities from scan report.

    All log exposures are treated as HIGH severity.
    Returns list of (message, severity) tuples.
    """
    with open(report_path) as f:
        report = json.load(f)

    findings = []
    for site in report.get("sites", []):
        messages = format_wordpress_log_finding(site, server="peter")
        for msg in messages:
            findings.append({"message": msg, "severity": "HIGH"})

    return findings


def send_findings_to_matrix(findings: List[Dict], client: MatrixClient, room: str):
    """Send findings to Matrix room as separate messages."""
    if not findings:
        logger.info("No findings to send")
        return

    logger.info(f"Sending {len(findings)} findings to {room}")

    for idx, finding in enumerate(findings, 1):
        message = finding["message"]
        severity = finding["severity"]

        try:
            # Use send_alert for proper severity formatting
            client.send_alert(room, severity.lower(), message)
            logger.info(f"  [{idx}/{len(findings)}] Sent {severity} finding")

            # Small delay between messages to avoid rate limiting
            if idx < len(findings):
                import time
                time.sleep(0.5)

        except Exception as e:
            logger.error(f"  Failed to send finding {idx}: {e}")


def main():
    parser = argparse.ArgumentParser(description='Send cyber-guardian findings to Matrix')
    parser.add_argument('--scan-report', help='Codebase security scan JSON report')
    parser.add_argument('--compliance-report', help='Compliance scan JSON report')
    parser.add_argument('--compliance-scan-id', type=int, help='Compliance scan ID from database')
    parser.add_argument('--wp-log-report', help='WordPress log scan JSON report')
    parser.add_argument('--min-severity', default='HIGH',
                       choices=['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'],
                       help='Minimum severity to report (default: HIGH)')
    parser.add_argument('--room', default=CYBER_GUARDIAN_ROOM,
                       help='Matrix room (default: #cyber-guardian)')
    parser.add_argument('--dry-run', action='store_true',
                       help='Print messages without sending')

    args = parser.parse_args()

    # Collect findings from all provided reports
    all_findings = []

    if args.scan_report:
        logger.info(f"Processing codebase scan: {args.scan_report}")
        findings = process_codebase_scan(args.scan_report, args.min_severity)
        all_findings.extend(findings)
        logger.info(f"  Found {len(findings)} findings")

    if args.compliance_report:
        logger.info(f"Processing compliance scan: {args.compliance_report}")
        findings = process_compliance_scan(args.compliance_report, args.min_severity)
        all_findings.extend(findings)
        logger.info(f"  Found {len(findings)} findings")

    if args.compliance_scan_id:
        logger.info(f"Processing compliance scan ID {args.compliance_scan_id} from database")
        findings = process_compliance_scan_from_db(args.compliance_scan_id, args.min_severity)
        all_findings.extend(findings)
        logger.info(f"  Found {len(findings)} findings")

    if args.wp_log_report:
        logger.info(f"Processing WordPress log scan: {args.wp_log_report}")
        findings = process_wordpress_log_scan(args.wp_log_report)
        all_findings.extend(findings)
        logger.info(f"  Found {len(findings)} findings")

    if not all_findings:
        logger.info("No CRITICAL or HIGH severity findings to report")
        return 0

    # Sort by severity (CRITICAL first)
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    all_findings.sort(key=lambda f: severity_order.get(f["severity"], 3))

    if args.dry_run:
        print("\n=== DRY RUN - Would send these messages ===\n")
        for idx, finding in enumerate(all_findings, 1):
            print(f"\n--- Message {idx}/{len(all_findings)} ({finding['severity']}) ---")
            print(finding["message"])
        print(f"\n=== Total: {len(all_findings)} messages ===")
        return 0

    # Send to Matrix
    try:
        client = MatrixClient()
        send_findings_to_matrix(all_findings, client, args.room)
        logger.info(f"Successfully sent {len(all_findings)} findings to Matrix")
        return 0
    except Exception as e:
        logger.error(f"Failed to send to Matrix: {e}")
        return 1


if __name__ == '__main__':
    sys.exit(main())
