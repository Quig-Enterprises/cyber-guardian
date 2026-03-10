-- ============================================================================
-- Cyber-Guardian: Compliance Schema Rollback
-- ============================================================================
-- Version: 1.0.0
-- Date: 2026-03-10
-- Purpose: Rollback compliance scanning schema (removes all objects)
-- WARNING: This will delete all compliance scan data!
-- ============================================================================

-- Drop functions
DROP FUNCTION IF EXISTS blueteam.get_compliance_stats(VARCHAR, TIMESTAMP, TIMESTAMP);
DROP FUNCTION IF EXISTS blueteam.calculate_compliance_score(INTEGER);

-- Drop views
DROP VIEW IF EXISTS blueteam.v_compliance_by_category;
DROP VIEW IF EXISTS blueteam.v_compliance_summary_by_server;
DROP VIEW IF EXISTS blueteam.v_active_compliance_findings;
DROP VIEW IF EXISTS blueteam.v_latest_compliance_scans;

-- Drop tables (CASCADE removes dependent objects)
DROP TABLE IF EXISTS blueteam.compliance_findings CASCADE;
DROP TABLE IF EXISTS blueteam.compliance_scans CASCADE;

-- Verify cleanup
SELECT 'Tables remaining:' as status, COUNT(*)
FROM pg_tables
WHERE schemaname = 'blueteam'
  AND tablename LIKE 'compliance%';

SELECT 'Views remaining:' as status, COUNT(*)
FROM pg_views
WHERE schemaname = 'blueteam'
  AND viewname LIKE '%compliance%';

SELECT 'Functions remaining:' as status, COUNT(*)
FROM information_schema.routines
WHERE routine_schema = 'blueteam'
  AND routine_name LIKE '%compliance%';

-- ============================================================================
-- Rollback complete
-- ============================================================================
