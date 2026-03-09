#!/usr/bin/env python3
"""
Import Hierarchical JSON Scan Reports to PostgreSQL

This script imports hierarchical JSON reports from redteam/reports/ into the
PostgreSQL database using the blueteam.scans schema structure.

Database Schema:
- blueteam.scans: Scan metadata and execution context
- blueteam.attack_catalog: Attack module definitions (pre-populated)
- blueteam.scan_attacks: Attack-level rollup statistics
- blueteam.findings: Individual variant-level findings

Usage:
    # Import single report
    python scripts/import-scan-to-db.py redteam/reports/hierarchical-20260308_214053.json

    # Import most recent report
    python scripts/import-scan-to-db.py --latest

    # Dry run (validate without inserting)
    python scripts/import-scan-to-db.py --dry-run redteam/reports/*.json

    # Verbose logging
    python scripts/import-scan-to-db.py --verbose --latest

    # Force re-import of existing scan
    python scripts/import-scan-to-db.py --force redteam/reports/hierarchical-*.json

    # Custom database connection
    python scripts/import-scan-to-db.py --host localhost --database alfred_admin \
        --user alfred_admin --password secret redteam/reports/hierarchical-*.json

Environment Variables:
    PGHOST: Database host (default: localhost)
    PGDATABASE: Database name (default: alfred_admin)
    PGUSER: Database user (default: alfred_admin)
    PGPASSWORD: Database password (optional)

Return Codes:
    0: Success
    1: Import error
    2: Database connection error
    3: File not found

Author: CxQ Development Team
Version: 1.0.0
Created: 2026-03-08
"""

import argparse
import json
import os
import sys
from datetime import datetime
from glob import glob
from pathlib import Path
from typing import Dict, List, Tuple, Optional

try:
    import psycopg2
    from psycopg2.extras import RealDictCursor, Json
except ImportError:
    print("ERROR: psycopg2 not installed. Run: pip install psycopg2-binary", file=sys.stderr)
    sys.exit(2)


class ScanImporter:
    """Imports hierarchical JSON scan reports into PostgreSQL"""

    def __init__(self, host: str, database: str, user: str, password: Optional[str],
                 dry_run: bool = False, verbose: bool = False, force: bool = False):
        """
        Initialize the importer.

        Args:
            host: Database host
            database: Database name
            user: Database user
            password: Database password (optional)
            dry_run: Validate only, don't insert
            verbose: Enable detailed logging
            force: Re-import existing scans
        """
        self.host = host
        self.database = database
        self.user = user
        self.password = password
        self.dry_run = dry_run
        self.verbose = verbose
        self.force = force
        self.conn = None
        self.cursor = None

        # Statistics
        self.stats = {
            'scans_imported': 0,
            'scans_skipped': 0,
            'attacks_inserted': 0,
            'findings_inserted': 0,
            'errors': 0
        }

    def connect(self) -> bool:
        """
        Connect to PostgreSQL database.

        Returns:
            True if connection successful, False otherwise
        """
        try:
            conn_params = {
                'host': self.host,
                'database': self.database,
                'user': self.user
            }
            if self.password:
                conn_params['password'] = self.password

            self.conn = psycopg2.connect(**conn_params)
            self.cursor = self.conn.cursor(cursor_factory=RealDictCursor)

            if self.verbose:
                print(f"Connected to PostgreSQL: {self.user}@{self.host}/{self.database}")

            return True

        except psycopg2.Error as e:
            print(f"ERROR: Failed to connect to database: {e}", file=sys.stderr)
            return False

    def disconnect(self):
        """Close database connection"""
        if self.cursor:
            self.cursor.close()
        if self.conn:
            self.conn.close()

    def load_json_report(self, filepath: str) -> Optional[Dict]:
        """
        Load and parse JSON report file.

        Args:
            filepath: Path to JSON report file

        Returns:
            Parsed JSON data or None if error
        """
        try:
            with open(filepath, 'r') as f:
                data = json.load(f)

            if self.verbose:
                print(f"Loaded report: {filepath}")

            return data

        except (FileNotFoundError, json.JSONDecodeError) as e:
            print(f"ERROR: Failed to load {filepath}: {e}", file=sys.stderr)
            self.stats['errors'] += 1
            return None

    def scan_exists(self, scan_id: str) -> bool:
        """
        Check if scan already exists in database.

        Args:
            scan_id: Scan identifier

        Returns:
            True if scan exists, False otherwise
        """
        if self.dry_run:
            return False

        self.cursor.execute(
            "SELECT id FROM blueteam.scans WHERE scan_id = %s",
            (scan_id,)
        )
        return self.cursor.fetchone() is not None

    def insert_scan_metadata(self, metadata: Dict, report_path: str) -> Optional[int]:
        """
        Insert scan metadata into blueteam.scans table.

        Args:
            metadata: scan_metadata from JSON report
            report_path: Path to the report file

        Returns:
            Database ID of inserted scan, or None if error/dry-run
        """
        try:
            scan_id = metadata['scan_id']
            target = metadata['target']
            execution = metadata['execution']

            # Check for existing scan
            if not self.force and self.scan_exists(scan_id):
                print(f"SKIPPED: Scan {scan_id} already exists (use --force to re-import)")
                self.stats['scans_skipped'] += 1
                return None

            if self.dry_run:
                print(f"[DRY RUN] Would insert scan: {scan_id}")
                return None

            # Delete existing scan if force re-import
            if self.force:
                self.cursor.execute(
                    "DELETE FROM blueteam.scans WHERE scan_id = %s",
                    (scan_id,)
                )
                if self.cursor.rowcount > 0:
                    print(f"Deleted existing scan: {scan_id}")

            # Parse timestamps
            scan_date = datetime.fromisoformat(execution['start_time'])

            # Insert scan metadata
            self.cursor.execute("""
                INSERT INTO blueteam.scans (
                    scan_id, target_url, target_name, target_type, environment,
                    scanner_version, config_hash, execution_mode, scan_date,
                    duration_ms, report_path, status
                ) VALUES (
                    %s, %s, %s, %s, %s,
                    %s, %s, %s, %s,
                    %s, %s, %s
                )
                RETURNING id
            """, (
                scan_id,
                target['url'],
                target.get('name'),
                target.get('type'),
                target.get('environment'),
                metadata.get('scanner_version'),
                metadata.get('config_hash'),
                execution.get('mode'),
                scan_date,
                execution.get('duration_ms'),
                report_path,
                'completed'
            ))

            scan_db_id = self.cursor.fetchone()['id']
            self.stats['scans_imported'] += 1

            if self.verbose:
                print(f"Inserted scan: {scan_id} (DB ID: {scan_db_id})")

            return scan_db_id

        except (KeyError, ValueError, psycopg2.Error) as e:
            print(f"ERROR: Failed to insert scan metadata: {e}", file=sys.stderr)
            self.stats['errors'] += 1
            return None

    def insert_scan_attack(self, scan_db_id: int, attack: Dict) -> Optional[int]:
        """
        Insert attack-level data into blueteam.scan_attacks table.

        Args:
            scan_db_id: Database ID of parent scan
            attack: Attack data from JSON report

        Returns:
            Database ID of inserted scan_attack, or None if error/dry-run
        """
        try:
            attack_id = attack['attack_id']
            results = attack['results_summary']

            if self.dry_run:
                print(f"  [DRY RUN] Would insert attack: {attack_id}")
                return None

            # Insert scan_attack
            self.cursor.execute("""
                INSERT INTO blueteam.scan_attacks (
                    scan_id, attack_id, duration_ms,
                    variants_tested, vulnerable_count, partial_count,
                    defended_count, error_count
                ) VALUES (
                    %s, %s, %s,
                    %s, %s, %s,
                    %s, %s
                )
                RETURNING id
            """, (
                scan_db_id,
                attack_id,
                attack.get('duration_ms'),
                results['variants_tested'],
                results['vulnerable'],
                results['partial'],
                results['defended'],
                results['errors']
            ))

            scan_attack_db_id = self.cursor.fetchone()['id']
            self.stats['attacks_inserted'] += 1

            if self.verbose:
                print(f"  Inserted attack: {attack_id} (DB ID: {scan_attack_db_id})")

            return scan_attack_db_id

        except (KeyError, psycopg2.Error) as e:
            print(f"ERROR: Failed to insert attack {attack.get('attack_id')}: {e}", file=sys.stderr)
            self.stats['errors'] += 1
            return None

    def insert_finding(self, scan_db_id: int, scan_attack_db_id: int,
                      attack_id: str, variant: Dict) -> bool:
        """
        Insert finding (variant-level result) into blueteam.findings table.

        Args:
            scan_db_id: Database ID of parent scan
            scan_attack_db_id: Database ID of parent scan_attack
            attack_id: Attack identifier
            variant: Variant data from JSON report

        Returns:
            True if successful, False otherwise
        """
        try:
            variant_id = variant['variant_id']
            evidence = variant.get('evidence', {})
            request = variant.get('request', {})
            response = variant.get('response', {})
            recommendation = variant.get('recommendation', {})

            if self.dry_run:
                print(f"    [DRY RUN] Would insert finding: {variant_id} ({variant['status']})")
                return True

            # Insert finding
            self.cursor.execute("""
                INSERT INTO blueteam.findings (
                    scan_id, scan_attack_id, attack_id, variant_id, variant_name,
                    status, severity, duration_ms,
                    evidence_summary, evidence_details, evidence_proof,
                    request_data, response_data,
                    recommendation, priority, references
                ) VALUES (
                    %s, %s, %s, %s, %s,
                    %s, %s, %s,
                    %s, %s, %s,
                    %s, %s,
                    %s, %s, %s
                )
            """, (
                scan_db_id,
                scan_attack_db_id,
                attack_id,
                variant_id,
                variant.get('name'),
                variant['status'],
                variant['severity'],
                variant.get('duration_ms'),
                evidence.get('summary'),
                evidence.get('technical_details'),
                Json(evidence.get('proof', {})),
                Json(request),
                Json(response),
                recommendation.get('remediation'),
                recommendation.get('priority'),
                recommendation.get('references', [])
            ))

            self.stats['findings_inserted'] += 1

            if self.verbose:
                print(f"    Inserted finding: {variant_id} ({variant['status']})")

            return True

        except (KeyError, psycopg2.Error) as e:
            print(f"ERROR: Failed to insert finding {variant.get('variant_id')}: {e}", file=sys.stderr)
            self.stats['errors'] += 1
            return False

    def import_report(self, filepath: str) -> bool:
        """
        Import a complete hierarchical JSON report.

        Args:
            filepath: Path to JSON report file

        Returns:
            True if successful, False otherwise
        """
        # Load JSON report
        data = self.load_json_report(filepath)
        if not data:
            return False

        # Validate structure
        if 'scan_metadata' not in data or 'attacks' not in data:
            print(f"ERROR: Invalid report structure in {filepath}", file=sys.stderr)
            self.stats['errors'] += 1
            return False

        # Insert scan metadata
        scan_db_id = self.insert_scan_metadata(data['scan_metadata'], filepath)
        if scan_db_id is None and not self.dry_run:
            return False  # Scan skipped or error

        # Insert attacks and findings
        for attack in data['attacks']:
            scan_attack_db_id = self.insert_scan_attack(scan_db_id, attack)
            if scan_attack_db_id is None and not self.dry_run:
                continue  # Skip failed attack

            # Insert findings for this attack
            for variant in attack.get('variants', []):
                self.insert_finding(scan_db_id, scan_attack_db_id, attack['attack_id'], variant)

        if not self.dry_run:
            self.conn.commit()
            print(f"Successfully imported: {filepath}")

        return True

    def import_reports(self, filepaths: List[str]) -> bool:
        """
        Import multiple reports.

        Args:
            filepaths: List of report file paths

        Returns:
            True if all successful, False if any errors
        """
        success = True

        for filepath in filepaths:
            if not self.import_report(filepath):
                success = False

        return success

    def print_statistics(self):
        """Print import statistics"""
        print("\n" + "="*60)
        print("Import Statistics")
        print("="*60)
        print(f"Scans imported:     {self.stats['scans_imported']}")
        print(f"Scans skipped:      {self.stats['scans_skipped']}")
        print(f"Attacks inserted:   {self.stats['attacks_inserted']}")
        print(f"Findings inserted:  {self.stats['findings_inserted']}")
        print(f"Errors:             {self.stats['errors']}")
        print("="*60)


def find_latest_report(pattern: str = "/opt/claude-workspace/projects/cyber-guardian/redteam/reports/hierarchical-*.json") -> Optional[str]:
    """
    Find the most recent hierarchical report.

    Args:
        pattern: Glob pattern for report files

    Returns:
        Path to latest report, or None if not found
    """
    reports = glob(pattern)
    if not reports:
        return None

    # Sort by modification time, newest first
    reports.sort(key=lambda f: os.path.getmtime(f), reverse=True)
    return reports[0]


def expand_file_patterns(patterns: List[str]) -> List[str]:
    """
    Expand glob patterns to actual file paths.

    Args:
        patterns: List of file paths or glob patterns

    Returns:
        List of expanded file paths
    """
    expanded = []
    for pattern in patterns:
        if '*' in pattern or '?' in pattern:
            expanded.extend(glob(pattern))
        else:
            expanded.append(pattern)

    return expanded


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="Import hierarchical JSON scan reports to PostgreSQL",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s redteam/reports/hierarchical-20260308_214053.json
  %(prog)s --latest
  %(prog)s --dry-run redteam/reports/*.json
  %(prog)s --verbose --force --latest
        """
    )

    # File arguments
    parser.add_argument('files', nargs='*', help='Report files to import (supports glob patterns)')
    parser.add_argument('--latest', action='store_true', help='Import most recent report')

    # Database connection
    parser.add_argument('--host', default=os.environ.get('PGHOST', 'localhost'),
                       help='Database host (default: localhost or PGHOST)')
    parser.add_argument('--database', default=os.environ.get('PGDATABASE', 'alfred_admin'),
                       help='Database name (default: alfred_admin or PGDATABASE)')
    parser.add_argument('--user', default=os.environ.get('PGUSER', 'alfred_admin'),
                       help='Database user (default: alfred_admin or PGUSER)')
    parser.add_argument('--password', default=os.environ.get('PGPASSWORD'),
                       help='Database password (default: PGPASSWORD)')

    # Options
    parser.add_argument('--dry-run', action='store_true',
                       help='Validate reports without inserting to database')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Enable verbose logging')
    parser.add_argument('--force', action='store_true',
                       help='Re-import existing scans (deletes and re-inserts)')

    args = parser.parse_args()

    # Determine files to import
    filepaths = []

    if args.latest:
        latest = find_latest_report()
        if latest:
            filepaths.append(latest)
            print(f"Latest report: {latest}")
        else:
            print("ERROR: No reports found", file=sys.stderr)
            return 3

    if args.files:
        filepaths.extend(expand_file_patterns(args.files))

    if not filepaths:
        parser.print_help()
        return 0

    # Validate files exist
    missing_files = [f for f in filepaths if not os.path.exists(f)]
    if missing_files:
        print(f"ERROR: Files not found: {', '.join(missing_files)}", file=sys.stderr)
        return 3

    # Create importer
    importer = ScanImporter(
        host=args.host,
        database=args.database,
        user=args.user,
        password=args.password,
        dry_run=args.dry_run,
        verbose=args.verbose,
        force=args.force
    )

    # Connect to database (skip for dry-run)
    if not args.dry_run:
        if not importer.connect():
            return 2
    else:
        print("\n*** DRY RUN MODE - No data will be inserted ***\n")

    try:
        # Import reports
        success = importer.import_reports(filepaths)

        # Print statistics
        importer.print_statistics()

        return 0 if success else 1

    finally:
        importer.disconnect()


if __name__ == '__main__':
    sys.exit(main())
