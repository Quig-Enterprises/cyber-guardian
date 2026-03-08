-- Red Team Schedule Management Schema
-- Phase 2: Schedule Management UI
-- Created: 2026-03-06
--
-- Purpose: Store configurable red team scan schedules managed via dashboard UI
--
-- Tables:
--   1. blueteam.redteam_schedules - Configurable cron schedules for red team scans

-- ===========================================================================
-- Table: redteam_schedules
-- ===========================================================================

CREATE TABLE IF NOT EXISTS blueteam.redteam_schedules (
    schedule_id SERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    cron_expr TEXT NOT NULL,
    category TEXT NOT NULL DEFAULT 'all' CHECK (category IN ('all', 'ai', 'api', 'web', 'compliance')),
    extra_args TEXT DEFAULT '',
    enabled BOOLEAN NOT NULL DEFAULT true,
    created_by INTEGER,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
    last_run_at TIMESTAMP,
    next_run_at TIMESTAMP
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_redteam_schedules_enabled ON blueteam.redteam_schedules(enabled);
CREATE INDEX IF NOT EXISTS idx_redteam_schedules_next_run ON blueteam.redteam_schedules(next_run_at);

-- Comments
COMMENT ON TABLE blueteam.redteam_schedules IS 'Configurable cron schedules for red team attack scans, managed via Security Dashboard UI';
COMMENT ON COLUMN blueteam.redteam_schedules.cron_expr IS 'Standard 5-field cron expression (minute hour day month weekday)';
COMMENT ON COLUMN blueteam.redteam_schedules.category IS 'Attack category filter: all, ai, api, web, compliance';
COMMENT ON COLUMN blueteam.redteam_schedules.extra_args IS 'Additional CLI arguments passed to run-redteam.sh';
COMMENT ON COLUMN blueteam.redteam_schedules.enabled IS 'Whether this schedule is active in the crontab';
COMMENT ON COLUMN blueteam.redteam_schedules.created_by IS 'User ID who created this schedule';

-- ===========================================================================
-- Seed existing cron entries
-- ===========================================================================

INSERT INTO blueteam.redteam_schedules (name, cron_expr, category, extra_args, enabled)
VALUES
    ('Weekly Full Suite', '0 2 * * 0', 'all', '--all', true),
    ('Daily Compliance', '0 3 * * *', 'compliance', '--category compliance', true)
ON CONFLICT DO NOTHING;

-- ===========================================================================
-- Permissions
-- ===========================================================================

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'blueteam_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON blueteam.redteam_schedules TO blueteam_app;
        GRANT USAGE ON SEQUENCE blueteam.redteam_schedules_schedule_id_seq TO blueteam_app;
    END IF;
END
$$;

-- ===========================================================================
-- Verification
-- ===========================================================================

SELECT schedule_id, name, cron_expr, category, enabled
FROM blueteam.redteam_schedules
ORDER BY schedule_id;

DO $$
BEGIN
    RAISE NOTICE 'Schedule schema created and seeded successfully';
END
$$;
