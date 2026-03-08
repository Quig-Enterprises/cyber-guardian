-- Password Audit Schema
-- Tracks password hash quality across all local user databases

CREATE TABLE IF NOT EXISTS blueteam.password_audit_runs (
    run_id          SERIAL PRIMARY KEY,
    run_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    duration_sec    NUMERIC(8,2),
    total_checked   INTEGER NOT NULL DEFAULT 0,
    weak_count      INTEGER NOT NULL DEFAULT 0,
    insecure_count  INTEGER NOT NULL DEFAULT 0,
    ok_count        INTEGER NOT NULL DEFAULT 0,
    status          VARCHAR(20) NOT NULL DEFAULT 'running',  -- running, completed, failed
    error_msg       TEXT
);

CREATE TABLE IF NOT EXISTS blueteam.password_audit_findings (
    finding_id      SERIAL PRIMARY KEY,
    run_id          INTEGER NOT NULL REFERENCES blueteam.password_audit_runs(run_id) ON DELETE CASCADE,
    source_db       VARCHAR(50) NOT NULL,   -- e.g. alfred_admin, wordpress
    source_table    VARCHAR(100) NOT NULL,  -- e.g. public.users, wp_users
    user_id         VARCHAR(100) NOT NULL,  -- user identifier (id or login name)
    user_email      VARCHAR(255),
    hash_algorithm  VARCHAR(50) NOT NULL,   -- bcrypt, md5, sha1, phpass_md5, plaintext, unknown
    hash_cost       INTEGER,                -- bcrypt cost factor, null for non-bcrypt
    severity        VARCHAR(20) NOT NULL,   -- ok, weak, insecure, critical
    finding         TEXT NOT NULL,          -- human-readable description
    resolved_at     TIMESTAMP,
    detected_at     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_pw_findings_run ON blueteam.password_audit_findings(run_id);
CREATE INDEX IF NOT EXISTS idx_pw_findings_severity ON blueteam.password_audit_findings(severity) WHERE resolved_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_pw_runs_at ON blueteam.password_audit_runs(run_at DESC);

-- Mark previous findings as resolved when a new run finds them clean
CREATE OR REPLACE FUNCTION blueteam.resolve_fixed_password_findings(p_run_id INTEGER)
RETURNS INTEGER AS $$
DECLARE
    resolved INTEGER;
BEGIN
    -- Any finding from a prior run whose (source_db, source_table, user_id)
    -- does NOT appear in the current run is considered resolved.
    UPDATE blueteam.password_audit_findings old
    SET resolved_at = CURRENT_TIMESTAMP
    WHERE old.resolved_at IS NULL
      AND old.run_id < p_run_id
      AND NOT EXISTS (
          SELECT 1 FROM blueteam.password_audit_findings new
          WHERE new.run_id = p_run_id
            AND new.source_db    = old.source_db
            AND new.source_table = old.source_table
            AND new.user_id      = old.user_id
      );
    GET DIAGNOSTICS resolved = ROW_COUNT;
    RETURN resolved;
END;
$$ LANGUAGE plpgsql;
