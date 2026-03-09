#!/usr/bin/env python3
"""
Import Red Team Scan Results to Mitigation Dashboard

Parses redteam scan JSON output and populates mitigation tracking database.
"""

import json
import sys
import psycopg2
from datetime import datetime
from pathlib import Path

# Database connection
DB_CONFIG = {
    'host': '172.200.1.1',
    'database': 'alfred_admin',
    'user': 'alfred_admin',
    'password': 'Xk9OUuMWtRkBEnY2jugt6992'
}

def connect_db():
    """Connect to PostgreSQL database"""
    return psycopg2.connect(**DB_CONFIG)

def create_project(conn, scan_report_path):
    """Create a mitigation project for this scan"""
    cursor = conn.cursor()

    # Extract scan date from filename (redteam-report-20260308_184540.json)
    filename = Path(scan_report_path).stem
    parts = filename.split('-')
    if len(parts) >= 3:
        date_str = parts[2].split('_')[0]  # 20260308
        scan_date = datetime.strptime(date_str, '%Y%m%d').date()
    else:
        scan_date = datetime.now().date()

    project_name = f"Red Team Scan - {scan_date}"
    description = f"Automated red team security scan conducted on {scan_date}"

    cursor.execute("""
        INSERT INTO blueteam.mitigation_projects
        (name, description, scan_date, scan_report_path, status)
        VALUES (%s, %s, %s, %s, 'active')
        RETURNING id
    """, (project_name, description, scan_date, scan_report_path))

    project_id = cursor.fetchone()[0]
    conn.commit()
    cursor.close()

    return project_id

def import_vulnerability(conn, project_id, result):
    """Import a single vulnerability finding"""
    cursor = conn.cursor()

    # Extract data from scan result
    attack_name = result.get('attack_name', 'unknown')
    variant = result.get('variant', '')
    status_finding = result.get('status', 'unknown')
    severity = result.get('severity', 'low')
    message = result.get('message', '')
    evidence = result.get('evidence', '')
    category = result.get('category', 'unknown')

    # Only import vulnerable findings
    if status_finding != 'vulnerable':
        return None

    # Create title
    title = f"{attack_name}"
    if variant:
        title += f" / {variant}"

    # Map severity to priority (1=critical, 2=high, 3=medium, 4=low)
    priority_map = {
        'critical': 1,
        'high': 2,
        'medium': 3,
        'low': 4
    }
    priority = priority_map.get(severity.lower(), 3)

    # Determine status based on severity
    status = 'not_started'

    # Set due date based on severity
    if severity.lower() == 'critical':
        # 48-72 hours for critical
        due_days = 3
    elif severity.lower() == 'high':
        # 30 days for high
        due_days = 30
    elif severity.lower() == 'medium':
        # 60 days for medium
        due_days = 60
    else:
        # 90 days for low
        due_days = 90

    from datetime import timedelta
    due_date = datetime.now().date() + timedelta(days=due_days)

    # Store request/response details as JSONB
    request_details = json.dumps(result.get('request', {}))
    response_details = json.dumps(result.get('response', {}))

    cursor.execute("""
        INSERT INTO blueteam.mitigation_issues
        (project_id, title, description, severity, category, attack_name, variant,
         status, priority, due_date, evidence, request_details, response_details)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s::jsonb)
        RETURNING id
    """, (project_id, title, message, severity, category, attack_name, variant,
          status, priority, due_date, evidence, request_details, response_details))

    issue_id = cursor.fetchone()[0]

    # Log initial activity
    cursor.execute("""
        INSERT INTO blueteam.mitigation_activity
        (issue_id, activity_type, comment, user_name)
        VALUES (%s, 'created', 'Imported from red team scan', 'system')
    """, (issue_id,))

    conn.commit()
    cursor.close()

    return issue_id

def import_scan(scan_report_path):
    """Import all vulnerable findings from a scan report"""

    # Load scan results
    with open(scan_report_path, 'r') as f:
        scan_data = json.load(f)

    conn = connect_db()

    try:
        # Create project
        project_id = create_project(conn, scan_report_path)
        print(f"Created mitigation project ID: {project_id}")

        # Import vulnerabilities
        results = scan_data.get('results', [])
        imported_count = 0

        for result in results:
            issue_id = import_vulnerability(conn, project_id, result)
            if issue_id:
                imported_count += 1

        print(f"Imported {imported_count} vulnerable findings")

        # Print summary by severity
        cursor = conn.cursor()
        cursor.execute("""
            SELECT severity, COUNT(*)
            FROM blueteam.mitigation_issues
            WHERE project_id = %s
            GROUP BY severity
            ORDER BY
                CASE severity
                    WHEN 'critical' THEN 1
                    WHEN 'high' THEN 2
                    WHEN 'medium' THEN 3
                    WHEN 'low' THEN 4
                END
        """, (project_id,))

        print("\nSummary by Severity:")
        for row in cursor.fetchall():
            print(f"  {row[0].upper()}: {row[1]}")

        cursor.close()

    finally:
        conn.close()

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python3 import-scan-to-mitigation.py <scan-report.json>")
        sys.exit(1)

    scan_report_path = sys.argv[1]

    if not Path(scan_report_path).exists():
        print(f"Error: File not found: {scan_report_path}")
        sys.exit(1)

    import_scan(scan_report_path)
    print("\nImport complete!")
