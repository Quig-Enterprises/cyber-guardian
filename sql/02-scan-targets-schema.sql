-- Cyber-Guardian: Scan Targets & Scan Jobs
-- Run after 00-base-schema.sql
--
-- Tables:
--   blueteam.redteam_targets  - External scan targets (self + user-configured)
--   blueteam.scan_jobs        - Background scan job tracking

-- ===========================================================================
-- redteam_targets
-- ===========================================================================
CREATE TABLE IF NOT EXISTS blueteam.redteam_targets (
    target_id       SERIAL PRIMARY KEY,
    name            TEXT NOT NULL,
    base_url        TEXT NOT NULL,
    target_type     TEXT NOT NULL DEFAULT 'app',   -- app, wordpress, generic
    description     TEXT,
    origin_ip       TEXT,                          -- bypass CDN/Cloudflare
    wp_user         TEXT,
    wp_pass_enc     TEXT,                          -- base64-encoded, not real encryption
    is_self         BOOLEAN NOT NULL DEFAULT FALSE,
    enabled         BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Seed the "self" target (alfred EQMON instance)
INSERT INTO blueteam.redteam_targets (name, base_url, target_type, description, is_self, enabled)
VALUES ('Alfred (self)', 'http://localhost:8081', 'app', 'Local EQMON instance on this server', TRUE, TRUE)
ON CONFLICT DO NOTHING;

GRANT ALL ON blueteam.redteam_targets TO alfred_admin;
GRANT USAGE, SELECT ON SEQUENCE blueteam.redteam_targets_target_id_seq TO alfred_admin;

-- ===========================================================================
-- scan_jobs
-- ===========================================================================
CREATE TABLE IF NOT EXISTS blueteam.scan_jobs (
    job_id          SERIAL PRIMARY KEY,
    started_at      TIMESTAMP NOT NULL DEFAULT NOW(),
    finished_at     TIMESTAMP,
    status          TEXT NOT NULL DEFAULT 'running',   -- running, done, failed
    categories      TEXT NOT NULL DEFAULT 'all',       -- comma-separated or 'all'
    target_id       INTEGER REFERENCES blueteam.redteam_targets(target_id),
    target_url      TEXT,
    pid             INTEGER,
    log_file        TEXT,
    report_json     TEXT,
    exit_code       INTEGER,
    initiated_by    INTEGER                            -- user_id
);

GRANT ALL ON blueteam.scan_jobs TO alfred_admin;
GRANT USAGE, SELECT ON SEQUENCE blueteam.scan_jobs_job_id_seq TO alfred_admin;
