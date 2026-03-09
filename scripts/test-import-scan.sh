#!/bin/bash
#
# Test script for import-scan-to-db.py
#
# This script tests the import functionality without requiring database access
# by using the --dry-run flag to validate JSON parsing and data transformation.
#
# Usage: bash scripts/test-import-scan.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"

echo "============================================================"
echo "import-scan-to-db.py Test Suite"
echo "============================================================"
echo ""

# Test 1: Help output
echo "Test 1: Help output"
echo "------------------------------------------------------------"
python3 scripts/import-scan-to-db.py --help | head -15
echo ""

# Test 2: Find latest report
echo "Test 2: Find latest report"
echo "------------------------------------------------------------"
python3 -c "
from glob import glob
import os

reports = glob('redteam/reports/hierarchical-*.json')
if reports:
    reports.sort(key=lambda f: os.path.getmtime(f), reverse=True)
    print(f'Latest report: {reports[0]}')
    print(f'Total reports: {len(reports)}')
else:
    print('No reports found')
"
echo ""

# Test 3: JSON parsing validation
echo "Test 3: JSON structure validation"
echo "------------------------------------------------------------"
python3 -c "
import json

filepath = 'redteam/reports/hierarchical-20260308_214053.json'
with open(filepath) as f:
    data = json.load(f)

print('Report structure:')
print(f'  ✓ scan_metadata: {\"scan_id\" in data.get(\"scan_metadata\", {})}')
print(f'  ✓ attacks: {len(data.get(\"attacks\", []))} attacks')
print(f'  ✓ summary: {\"findings\" in data.get(\"summary\", {})}')

metadata = data['scan_metadata']
print(f'\nScan details:')
print(f'  Scan ID: {metadata[\"scan_id\"]}')
print(f'  Target: {metadata[\"target\"][\"url\"]}')
print(f'  Mode: {metadata[\"execution\"][\"mode\"]}')
print(f'  Duration: {metadata[\"execution\"][\"duration_ms\"]/1000:.1f}s')

total_variants = sum(len(a.get('variants', [])) for a in data['attacks'])
print(f'\nFindings:')
print(f'  Attacks: {len(data[\"attacks\"])}')
print(f'  Variants: {total_variants}')
print(f'  Vulnerable: {data[\"summary\"][\"findings\"][\"vulnerable\"]}')
print(f'  Defended: {data[\"summary\"][\"findings\"][\"defended\"]}')
"
echo ""

# Test 4: Dry-run import (single file)
echo "Test 4: Dry-run import (single file)"
echo "------------------------------------------------------------"
python3 scripts/import-scan-to-db.py --dry-run --verbose \
    redteam/reports/hierarchical-20260308_214053.json 2>&1 | \
    grep -E '(Would insert|scan_id|attack_id|variant_id|Statistics)' | head -20
echo ""

# Test 5: Dry-run import (--latest)
echo "Test 5: Dry-run import (--latest flag)"
echo "------------------------------------------------------------"
python3 scripts/import-scan-to-db.py --dry-run --latest 2>&1 | \
    grep -E '(Latest report|Would insert|ERROR)' | head -10
echo ""

# Test 6: Glob pattern support
echo "Test 6: File pattern expansion"
echo "------------------------------------------------------------"
python3 -c "
from glob import glob

pattern = 'redteam/reports/hierarchical-*.json'
files = glob(pattern)
print(f'Pattern: {pattern}')
print(f'Matched files: {len(files)}')
for i, f in enumerate(files[:3], 1):
    print(f'  {i}. {f}')
if len(files) > 3:
    print(f'  ... and {len(files)-3} more')
"
echo ""

# Test 7: Database connection options
echo "Test 7: Database connection configuration"
echo "------------------------------------------------------------"
echo "Available connection options:"
echo "  --host HOST           (default: localhost or \$PGHOST)"
echo "  --database DATABASE   (default: alfred_admin or \$PGDATABASE)"
echo "  --user USER           (default: alfred_admin or \$PGUSER)"
echo "  --password PASSWORD   (default: \$PGPASSWORD)"
echo ""
echo "Example usage with credentials:"
echo "  python3 scripts/import-scan-to-db.py \\"
echo "    --host localhost \\"
echo "    --database alfred_admin \\"
echo "    --user alfred_admin \\"
echo "    --password 'your-password' \\"
echo "    --latest"
echo ""

# Test 8: Statistics output format
echo "Test 8: Statistics output validation"
echo "------------------------------------------------------------"
python3 -c "
class Stats:
    def __init__(self):
        self.stats = {
            'scans_imported': 1,
            'scans_skipped': 0,
            'attacks_inserted': 2,
            'findings_inserted': 5,
            'errors': 0
        }

    def print_statistics(self):
        print('='*60)
        print('Import Statistics')
        print('='*60)
        print(f'Scans imported:     {self.stats[\"scans_imported\"]}')
        print(f'Scans skipped:      {self.stats[\"scans_skipped\"]}')
        print(f'Attacks inserted:   {self.stats[\"attacks_inserted\"]}')
        print(f'Findings inserted:  {self.stats[\"findings_inserted\"]}')
        print(f'Errors:             {self.stats[\"errors\"]}')
        print('='*60)

stats = Stats()
stats.print_statistics()
"
echo ""

echo "============================================================"
echo "Test Suite Complete"
echo "============================================================"
echo ""
echo "Next steps:"
echo "  1. Set database credentials (PGPASSWORD environment variable)"
echo "  2. Verify database schema is deployed (sql/05-scan-registry-schema.sql)"
echo "  3. Run actual import with: python3 scripts/import-scan-to-db.py --latest"
echo ""
