#!/bin/bash
# ============================================================================
# Cyber-Guardian: Compliance Schema Deployment Script
# ============================================================================
# Version: 1.0.0
# Date: 2026-03-10
# Purpose: Deploy compliance scanning database schema
# ============================================================================

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
DB_NAME="${DB_NAME:-eqmon}"
DB_USER="${DB_USER:-eqmon}"
DB_HOST="${DB_HOST:-localhost}"
DB_PORT="${DB_PORT:-5432}"

# Get password from .pgpass if available
if [ -f ~/.pgpass ]; then
    DB_PASS=$(grep "^${DB_HOST}:${DB_PORT}:${DB_NAME}:${DB_USER}:" ~/.pgpass | cut -d: -f5)
fi

if [ -z "$DB_PASS" ]; then
    DB_PASS="${DB_PASS:-}"
fi

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
SCHEMA_FILE="$SCRIPT_DIR/02-compliance-schema.sql"
ROLLBACK_FILE="$SCRIPT_DIR/02-compliance-schema-rollback.sql"

# ============================================================================
# Functions
# ============================================================================

print_header() {
    echo ""
    echo "============================================================================"
    echo "$1"
    echo "============================================================================"
}

print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

run_sql() {
    if [ -n "$DB_PASS" ]; then
        PGPASSWORD="$DB_PASS" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -v ON_ERROR_STOP=1 "$@"
    else
        psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -v ON_ERROR_STOP=1 "$@"
    fi
}

# ============================================================================
# Pre-flight checks
# ============================================================================

print_header "Compliance Schema Deployment"

echo "Configuration:"
echo "  Database: $DB_NAME"
echo "  User: $DB_USER"
echo "  Host: $DB_HOST:$DB_PORT"
echo ""

# Check if schema file exists
if [ ! -f "$SCHEMA_FILE" ]; then
    print_error "Schema file not found: $SCHEMA_FILE"
    exit 1
fi

# Test database connection
echo -n "Testing database connection... "
if run_sql -c "SELECT 1" > /dev/null 2>&1; then
    print_success "Connected"
else
    print_error "Connection failed"
    echo ""
    echo "Please check:"
    echo "  1. PostgreSQL is running: sudo systemctl status postgresql"
    echo "  2. Database exists: psql -l | grep $DB_NAME"
    echo "  3. User credentials are correct"
    echo "  4. Password in ~/.pgpass: ${DB_HOST}:${DB_PORT}:${DB_NAME}:${DB_USER}:password"
    exit 1
fi

# Check if blueteam schema exists
echo -n "Checking for blueteam schema... "
SCHEMA_EXISTS=$(run_sql -t -c "SELECT EXISTS(SELECT 1 FROM information_schema.schemata WHERE schema_name = 'blueteam');" | tr -d ' ')
if [ "$SCHEMA_EXISTS" = "t" ]; then
    print_success "Exists"
else
    print_warning "Not found - creating"
    run_sql -c "CREATE SCHEMA blueteam;"
    print_success "Created blueteam schema"
fi

# ============================================================================
# Deployment
# ============================================================================

print_header "Deploying Compliance Schema"

echo "Executing: $SCHEMA_FILE"
echo ""

# Run the schema file
if run_sql -f "$SCHEMA_FILE"; then
    print_success "Schema deployed successfully"
else
    print_error "Schema deployment failed"
    exit 1
fi

echo ""

# ============================================================================
# Verification
# ============================================================================

print_header "Verification"

# Count tables
TABLE_COUNT=$(run_sql -t -c "SELECT COUNT(*) FROM pg_tables WHERE schemaname = 'blueteam' AND tablename LIKE 'compliance%';" | tr -d ' ')
print_success "Tables created: $TABLE_COUNT/2"

# Count views
VIEW_COUNT=$(run_sql -t -c "SELECT COUNT(*) FROM pg_views WHERE schemaname = 'blueteam' AND viewname LIKE '%compliance%';" | tr -d ' ')
print_success "Views created: $VIEW_COUNT/4"

# Count functions
FUNCTION_COUNT=$(run_sql -t -c "SELECT COUNT(*) FROM information_schema.routines WHERE routine_schema = 'blueteam' AND routine_name LIKE '%compliance%';" | tr -d ' ')
print_success "Functions created: $FUNCTION_COUNT/2"

# Test compliance score function
echo ""
echo -n "Testing compliance score calculation... "
SCORE=$(run_sql -t -c "SELECT blueteam.calculate_compliance_score((SELECT MAX(scan_id) FROM blueteam.compliance_scans));" | tr -d ' ')
if [ -n "$SCORE" ]; then
    print_success "Score: $SCORE/100"
else
    print_warning "No sample data"
fi

# Show sample data
echo ""
echo "Sample scan record:"
run_sql -c "SELECT scan_id, server_name, server_type, overall_score, findings_critical, findings_high FROM blueteam.compliance_scans LIMIT 1;"

echo ""
echo "Sample findings:"
run_sql -c "SELECT check_category, check_name, status, severity FROM blueteam.compliance_findings LIMIT 4;"

# ============================================================================
# Summary
# ============================================================================

print_header "Deployment Complete"

echo "Database objects created:"
echo "  • compliance_scans table"
echo "  • compliance_findings table"
echo "  • v_latest_compliance_scans view"
echo "  • v_active_compliance_findings view"
echo "  • v_compliance_summary_by_server view"
echo "  • v_compliance_by_category view"
echo "  • calculate_compliance_score() function"
echo "  • get_compliance_stats() function"
echo ""

echo "Next steps:"
echo "  1. Run compliance scanner: python3 scripts/compliance-scanner.py"
echo "  2. View results: SELECT * FROM blueteam.v_latest_compliance_scans;"
echo "  3. Check findings: SELECT * FROM blueteam.v_active_compliance_findings;"
echo ""

print_success "Schema deployment successful!"
