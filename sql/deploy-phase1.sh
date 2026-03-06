#!/bin/bash
#
# Deploy Phase 1: Malware Scanner Database Schema
# Created: 2026-03-06
#
# Usage: bash deploy-phase1.sh [--rollback]
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCHEMA_FILE="$SCRIPT_DIR/01-malware-schema.sql"
ROLLBACK_FILE="$SCRIPT_DIR/01-malware-schema-rollback.sql"

# Database connection parameters
DB_HOST="${DB_HOST:-localhost}"
DB_PORT="${DB_PORT:-5432}"
DB_NAME="${DB_NAME:-blueteam}"
DB_USER="${DB_USER:-blueteam_app}"

echo "=========================================="
echo "Phase 1: Database Schema Deployment"
echo "=========================================="
echo ""
echo "Database: $DB_NAME"
echo "Host: $DB_HOST:$DB_PORT"
echo "User: $DB_USER"
echo ""

# Check for rollback flag
if [ "$1" == "--rollback" ]; then
    echo "⚠️  ROLLBACK MODE"
    echo "This will DELETE all malware scan data!"
    echo ""
    read -p "Are you sure you want to rollback? (yes/no): " confirm
    if [ "$confirm" != "yes" ]; then
        echo "Rollback cancelled"
        exit 0
    fi

    echo ""
    echo "Executing rollback script..."
    psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -f "$ROLLBACK_FILE"

    echo ""
    echo "✓ Rollback complete"
    exit 0
fi

# Normal deployment
echo "Checking database connection..."
if ! psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -c "SELECT 1" > /dev/null 2>&1; then
    echo "❌ Database connection failed"
    echo ""
    echo "Troubleshooting:"
    echo "  1. Check database is running: sudo systemctl status postgresql"
    echo "  2. Verify connection: psql -h $DB_HOST -p $DB_PORT -U $DB_USER -d $DB_NAME"
    echo "  3. Set environment variables if needed:"
    echo "     export DB_HOST=hostname"
    echo "     export DB_PORT=5432"
    echo "     export DB_USER=username"
    echo "     export DB_NAME=blueteam"
    exit 1
fi

echo "✓ Database connection successful"
echo ""

# Check if schema already exists
if psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -tAc "SELECT 1 FROM information_schema.tables WHERE table_schema='blueteam' AND table_name='malware_scans'" | grep -q 1; then
    echo "⚠️  WARNING: malware_scans table already exists"
    echo ""
    read -p "Do you want to continue? This may update the schema. (yes/no): " confirm
    if [ "$confirm" != "yes" ]; then
        echo "Deployment cancelled"
        exit 0
    fi
fi

echo "Deploying schema..."
echo ""

# Execute schema script
if psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -f "$SCHEMA_FILE"; then
    echo ""
    echo "=========================================="
    echo "Deployment Successful!"
    echo "=========================================="
    echo ""

    # Verify deployment
    echo "Verification:"
    echo ""

    # Count tables
    table_count=$(psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -tAc "
        SELECT COUNT(*)
        FROM information_schema.tables
        WHERE table_schema = 'blueteam'
        AND table_name IN ('malware_scans', 'malware_detections')
    ")
    echo "  Tables created: $table_count/2"

    # Count views
    view_count=$(psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -tAc "
        SELECT COUNT(*)
        FROM information_schema.views
        WHERE table_schema = 'blueteam'
        AND table_name LIKE 'v_%'
    ")
    echo "  Views created: $view_count/3"

    # Count functions
    func_count=$(psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -tAc "
        SELECT COUNT(*)
        FROM information_schema.routines
        WHERE routine_schema = 'blueteam'
        AND routine_name IN ('calculate_malware_score', 'get_scan_stats')
    ")
    echo "  Functions created: $func_count/2"

    # Count sample data
    sample_count=$(psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -tAc "
        SELECT COUNT(*) FROM blueteam.malware_scans
    ")
    echo "  Sample records: $sample_count"

    echo ""
    echo "Quick Tests:"
    echo ""

    # Test malware score calculation
    score=$(psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -tAc "
        SELECT blueteam.calculate_malware_score()
    ")
    echo "  ✓ Malware score: $score/100"

    # Test latest scans view
    scan_types=$(psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -tAc "
        SELECT COUNT(*) FROM blueteam.v_latest_scans
    ")
    echo "  ✓ Latest scans: $scan_types scanner types"

    echo ""
    echo "Phase 1 Complete!"
    echo ""
    echo "Next Steps:"
    echo "  1. Review sample data:"
    echo "     psql -U $DB_USER -d $DB_NAME -c 'SELECT * FROM blueteam.v_latest_scans;'"
    echo ""
    echo "  2. Test queries:"
    echo "     psql -U $DB_USER -d $DB_NAME -c 'SELECT blueteam.calculate_malware_score();'"
    echo ""
    echo "  3. Proceed to Phase 2: Log Parser Development"
    echo ""

else
    echo ""
    echo "❌ Deployment failed"
    echo "Check the error messages above"
    exit 1
fi
