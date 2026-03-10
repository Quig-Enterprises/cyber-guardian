#!/usr/bin/env python3
"""
Lynis CIS Audit Integration for Cyber-Guardian

This script runs Lynis security audits and stores results in the blueteam database.
Integrates with the compliance scanning system to provide comprehensive security posture assessment.

Version: 1.0.0
Author: Cyber-Guardian Automated System
Database: blueteam.lynis_audits, blueteam.lynis_findings
"""

import subprocess
import json
import re
import sys
import os
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import psycopg2
from psycopg2.extras import execute_values

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('lynis-auditor')

# Database connection parameters (uses .pgpass for password)
DB_CONFIG = {
    'host': os.getenv('DB_HOST', 'localhost'),
    'port': int(os.getenv('DB_PORT', '5432')),
    'database': os.getenv('DB_NAME', 'eqmon'),
    'user': os.getenv('DB_USER', 'eqmon'),
}

# Get password from .pgpass if available
PGPASS_FILE = Path.home() / ".pgpass"
if PGPASS_FILE.exists():
    with open(PGPASS_FILE) as f:
        for line in f:
            parts = line.strip().split(":")
            if len(parts) == 5 and parts[0] == DB_CONFIG["host"] and \
               parts[2] == DB_CONFIG["database"] and parts[3] == DB_CONFIG["user"]:
                DB_CONFIG["password"] = parts[4]
                break


class LynisAuditor:
    """Run Lynis security audits and store results."""

    def __init__(self, server_name: str):
        self.server_name = server_name
        self.audit_date = datetime.now()
        self.findings = []
        self.report_data = {}

    def run_audit(self) -> bool:
        """
        Run Lynis audit and parse results.

        Returns:
            bool: True if audit completed successfully
        """
        logger.info(f"Starting Lynis audit for {self.server_name}")

        try:
            # Run Lynis audit
            # Note: This requires sudo permissions
            cmd = [
                'sudo', 'lynis', 'audit', 'system',
                '--no-colors',
                '--quiet'
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )

            if result.returncode != 0:
                logger.error(f"Lynis audit failed: {result.stderr}")
                return False

            # Parse Lynis output
            self._parse_lynis_output(result.stdout)

            # Parse Lynis report file
            self._parse_report_file()

            logger.info(f"Audit complete: {len(self.findings)} findings")
            return True

        except subprocess.TimeoutExpired:
            logger.error("Lynis audit timed out after 5 minutes")
            return False
        except Exception as e:
            logger.error(f"Error running Lynis audit: {e}")
            return False

    def _parse_lynis_output(self, output: str):
        """Parse Lynis console output for key metrics."""

        # Extract hardening index
        hardening_match = re.search(r'Hardening index\s*:\s*(\d+)', output)
        if hardening_match:
            self.report_data['hardening_index'] = int(hardening_match.group(1))

        # Extract tests performed
        tests_match = re.search(r'Tests performed\s*:\s*(\d+)', output)
        if tests_match:
            self.report_data['tests_performed'] = int(tests_match.group(1))

    def _parse_report_file(self):
        """Parse Lynis report file for detailed findings."""

        # Lynis report location
        report_file = Path('/var/log/lynis-report.dat')

        if not report_file.exists():
            logger.warning("Lynis report file not found")
            return

        try:
            # Use sudo to read the report file (owned by root)
            result = subprocess.run(
                ['sudo', 'cat', str(report_file)],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode != 0:
                logger.error(f"Failed to read Lynis report: {result.stderr}")
                return

            lines = result.stdout.splitlines()

            # Parse report data format: key=value
            for line in lines:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue

                # Parse warnings and suggestions
                if line.startswith('warning[]='):
                    warning = line.split('=', 1)[1]
                    self._add_finding('warning', warning)

                elif line.startswith('suggestion[]='):
                    suggestion = line.split('=', 1)[1]
                    self._add_finding('suggestion', suggestion)

                # Parse hardening index
                elif line.startswith('hardening_index='):
                    self.report_data['hardening_index'] = int(line.split('=')[1])

                # Parse test counts
                elif line.startswith('lynis_tests_done='):
                    self.report_data['tests_performed'] = int(line.split('=')[1])

        except Exception as e:
            logger.error(f"Error parsing Lynis report: {e}")

    def _add_finding(self, finding_type: str, message: str):
        """Add a finding to the results."""

        # Parse finding message format: test_id|message
        parts = message.split('|', 1)
        if len(parts) == 2:
            test_id, description = parts
        else:
            test_id = 'unknown'
            description = message

        # Map finding type to severity
        severity_map = {
            'warning': 'medium',
            'suggestion': 'low'
        }

        finding = {
            'test_id': test_id.strip(),
            'finding_type': finding_type,
            'severity': severity_map.get(finding_type, 'low'),
            'description': description.strip()
        }

        self.findings.append(finding)

    def save_to_database(self) -> bool:
        """Save audit results to database."""

        try:
            conn = psycopg2.connect(**DB_CONFIG)
            cur = conn.cursor()

            logger.info("Database connection established")

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
                self.server_name,
                self.audit_date,
                self.report_data.get('hardening_index', 0),
                self.report_data.get('tests_performed', 0),
                len([f for f in self.findings if f['finding_type'] == 'warning']),
                len([f for f in self.findings if f['finding_type'] == 'suggestion'])
            ))

            audit_id = cur.fetchone()[0]
            logger.info(f"Inserted audit record: audit_id={audit_id}")

            # Insert findings
            if self.findings:
                finding_values = [
                    (
                        audit_id,
                        f['test_id'],
                        f['finding_type'],
                        f['severity'],
                        f['description']
                    )
                    for f in self.findings
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

                logger.info(f"Inserted {len(self.findings)} findings")

            conn.commit()

            # Calculate summary
            cur.execute("""
                SELECT
                    hardening_index,
                    warnings_count,
                    suggestions_count
                FROM blueteam.lynis_audits
                WHERE audit_id = %s
            """, (audit_id,))

            hardening, warnings, suggestions = cur.fetchone()

            logger.info(f"Hardening index: {hardening}/100")
            logger.info(f"Warnings: {warnings}")
            logger.info(f"Suggestions: {suggestions}")

            cur.close()
            conn.close()
            logger.info("Database connection closed")

            return True

        except Exception as e:
            logger.error(f"Database error: {e}")
            if conn:
                conn.rollback()
                conn.close()
            return False


def main():
    """Main entry point."""

    if len(sys.argv) < 2:
        print("Usage: lynis-auditor.py <server-name>")
        print("Example: lynis-auditor.py alfred")
        sys.exit(1)

    server_name = sys.argv[1]

    # Create auditor
    auditor = LynisAuditor(server_name)

    # Run audit
    if not auditor.run_audit():
        logger.error("Audit failed")
        sys.exit(1)

    # Save results
    if not auditor.save_to_database():
        logger.error("Failed to save results")
        sys.exit(1)

    # Print summary
    print("\n" + "=" * 80)
    print("LYNIS AUDIT SUMMARY")
    print("=" * 80)
    print(f"Server: {server_name}")
    print(f"Hardening Index: {auditor.report_data.get('hardening_index', 0)}/100")
    print(f"Tests Performed: {auditor.report_data.get('tests_performed', 0)}")
    print(f"Warnings: {len([f for f in auditor.findings if f['finding_type'] == 'warning'])}")
    print(f"Suggestions: {len([f for f in auditor.findings if f['finding_type'] == 'suggestion'])}")
    print("=" * 80)
    print(f"\nView results: SELECT * FROM blueteam.v_latest_lynis_audits WHERE server_name = '{server_name}';")
    print("=" * 80)


if __name__ == '__main__':
    main()
