-- Cyber-Guardian Base Schema
-- Creates the blueteam schema and all tables required by the security dashboard
-- Run this BEFORE 01-malware-schema.sql
--
-- Tables:
--   blueteam.posture_scores
--   blueteam.compliance_controls
--   blueteam.security_incidents
--   blueteam.alert_history
--   blueteam.redteam_schedules
--   blueteam.notification_subscriptions
--   blueteam.notification_history
--   blueteam.emergency_rules

-- Create schema
CREATE SCHEMA IF NOT EXISTS blueteam;

-- Grant usage to alfred_admin
GRANT USAGE ON SCHEMA blueteam TO alfred_admin;

-- ===========================================================================
-- posture_scores
-- ===========================================================================
CREATE TABLE IF NOT EXISTS blueteam.posture_scores (
    score_id            SERIAL PRIMARY KEY,
    scored_at           TIMESTAMP NOT NULL DEFAULT NOW(),
    overall_score       NUMERIC(5,2),
    compliance_score    NUMERIC(5,2),
    redteam_score       NUMERIC(5,2),
    monitoring_score    NUMERIC(5,2),
    incident_score      NUMERIC(5,2),
    malware_score       NUMERIC(5,2) DEFAULT 100.0,
    details             JSONB,
    redteam_report_id   TEXT
);
CREATE INDEX IF NOT EXISTS idx_posture_scores_scored_at ON blueteam.posture_scores(scored_at DESC);

-- ===========================================================================
-- compliance_controls
-- ===========================================================================
CREATE TABLE IF NOT EXISTS blueteam.compliance_controls (
    control_id              TEXT NOT NULL,
    family                  TEXT NOT NULL,
    family_id               TEXT NOT NULL,
    requirement             TEXT NOT NULL,
    status                  TEXT NOT NULL DEFAULT 'not_assessed'
                                CHECK (status IN ('implemented','partially_implemented','not_assessed',
                                                  'not_applicable','planned','not_implemented')),
    implementation_notes    TEXT,
    evidence_type           TEXT,
    responsible_party       TEXT,
    last_assessed           TIMESTAMP WITH TIME ZONE,
    next_assessment         TIMESTAMP WITH TIME ZONE,
    assessor_notes          TEXT,
    created_at              TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    cmmc_level              INTEGER,
    framework               TEXT DEFAULT 'nist_800_171',
    PRIMARY KEY (control_id, framework)
);
CREATE INDEX IF NOT EXISTS idx_compliance_controls_family ON blueteam.compliance_controls(family_id);
CREATE INDEX IF NOT EXISTS idx_compliance_controls_status ON blueteam.compliance_controls(status);

-- ===========================================================================
-- security_incidents
-- ===========================================================================
CREATE TABLE IF NOT EXISTS blueteam.security_incidents (
    incident_id         SERIAL PRIMARY KEY,
    title               TEXT NOT NULL,
    description         TEXT,
    severity            TEXT NOT NULL CHECK (severity IN ('critical','high','medium','low')),
    status              TEXT NOT NULL DEFAULT 'open'
                            CHECK (status IN ('open','contained','eradicated','recovered','closed')),
    detected_at         TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    detected_by         TEXT,
    assigned_to         TEXT,
    cui_involved        BOOLEAN NOT NULL DEFAULT FALSE,
    dfars_reportable    BOOLEAN NOT NULL DEFAULT FALSE,
    dfars_reported_at   TIMESTAMP WITH TIME ZONE,
    contained_at        TIMESTAMP WITH TIME ZONE,
    eradicated_at       TIMESTAMP WITH TIME ZONE,
    recovered_at        TIMESTAMP WITH TIME ZONE,
    closed_at           TIMESTAMP WITH TIME ZONE,
    root_cause          TEXT,
    created_at          TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_incidents_status ON blueteam.security_incidents(status);
CREATE INDEX IF NOT EXISTS idx_incidents_severity ON blueteam.security_incidents(severity) WHERE status != 'closed';
CREATE INDEX IF NOT EXISTS idx_incidents_detected_at ON blueteam.security_incidents(detected_at DESC);

-- ===========================================================================
-- alert_history
-- ===========================================================================
CREATE TABLE IF NOT EXISTS blueteam.alert_history (
    alert_id            SERIAL PRIMARY KEY,
    rule_id             TEXT,
    severity            TEXT NOT NULL CHECK (severity IN ('critical','high','medium','low','info')),
    title               TEXT NOT NULL,
    description         TEXT,
    incident_id         INTEGER REFERENCES blueteam.security_incidents(incident_id) ON DELETE SET NULL,
    acknowledged        BOOLEAN NOT NULL DEFAULT FALSE,
    acknowledged_by     TEXT,
    acknowledged_at     TIMESTAMP WITH TIME ZONE,
    created_at          TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_alert_history_created_at ON blueteam.alert_history(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_alert_history_unacked ON blueteam.alert_history(created_at DESC) WHERE acknowledged = FALSE;

-- ===========================================================================
-- redteam_schedules
-- ===========================================================================
CREATE TABLE IF NOT EXISTS blueteam.redteam_schedules (
    schedule_id     SERIAL PRIMARY KEY,
    name            TEXT NOT NULL,
    cron_expr       TEXT NOT NULL,
    category        TEXT,
    extra_args      TEXT,
    enabled         BOOLEAN NOT NULL DEFAULT TRUE,
    created_by      INTEGER,
    created_at      TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    last_run_at     TIMESTAMP WITH TIME ZONE,
    next_run_at     TIMESTAMP WITH TIME ZONE
);

-- ===========================================================================
-- notification_subscriptions
-- ===========================================================================
CREATE TABLE IF NOT EXISTS blueteam.notification_subscriptions (
    subscription_id     SERIAL PRIMARY KEY,
    user_id             INTEGER NOT NULL UNIQUE,
    user_email          TEXT NOT NULL,
    user_name           TEXT,
    enabled             BOOLEAN NOT NULL DEFAULT TRUE,
    cat_ai              BOOLEAN NOT NULL DEFAULT TRUE,
    cat_api             BOOLEAN NOT NULL DEFAULT TRUE,
    cat_web             BOOLEAN NOT NULL DEFAULT TRUE,
    cat_compliance      BOOLEAN NOT NULL DEFAULT TRUE,
    min_severity        TEXT NOT NULL DEFAULT 'medium'
                            CHECK (min_severity IN ('info','low','medium','high','critical')),
    dedup_mode          TEXT NOT NULL DEFAULT 'first_only'
                            CHECK (dedup_mode IN ('first_only','every_scan')),
    notify_vulnerable   BOOLEAN NOT NULL DEFAULT TRUE,
    notify_partial      BOOLEAN NOT NULL DEFAULT TRUE,
    notify_defended     BOOLEAN NOT NULL DEFAULT FALSE,
    notify_error        BOOLEAN NOT NULL DEFAULT FALSE,
    emergency_alerts    BOOLEAN NOT NULL DEFAULT TRUE,
    created_at          TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- ===========================================================================
-- notification_history
-- ===========================================================================
CREATE TABLE IF NOT EXISTS blueteam.notification_history (
    notification_id         SERIAL PRIMARY KEY,
    user_id                 INTEGER NOT NULL REFERENCES blueteam.notification_subscriptions(user_id) ON DELETE CASCADE,
    scan_timestamp          TIMESTAMP WITH TIME ZONE,
    finding_fingerprint     TEXT,
    finding_severity        TEXT,
    finding_status          TEXT,
    finding_category        TEXT,
    finding_attack          TEXT,
    finding_variant         TEXT,
    email_subject           TEXT,
    is_emergency            BOOLEAN NOT NULL DEFAULT FALSE,
    delivery_status         TEXT DEFAULT 'sent',
    sent_at                 TIMESTAMP WITH TIME ZONE,
    created_at              TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_notification_history_user ON blueteam.notification_history(user_id, created_at DESC);

-- ===========================================================================
-- emergency_rules
-- ===========================================================================
CREATE TABLE IF NOT EXISTS blueteam.emergency_rules (
    rule_id             SERIAL PRIMARY KEY,
    name                TEXT NOT NULL,
    description         TEXT,
    enabled             BOOLEAN NOT NULL DEFAULT TRUE,
    is_default          BOOLEAN NOT NULL DEFAULT FALSE,
    match_severity      TEXT,
    match_status        TEXT,
    match_category      TEXT,
    match_attack        TEXT,
    override_dedup      BOOLEAN NOT NULL DEFAULT TRUE,
    created_by          INTEGER,
    created_at          TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Default emergency rules
INSERT INTO blueteam.emergency_rules (name, description, enabled, is_default, match_severity, override_dedup)
VALUES
    ('Critical Findings', 'Immediately notify on any critical severity finding', TRUE, TRUE, 'critical', TRUE),
    ('High Severity Alerts', 'Notify on high severity findings regardless of dedup setting', TRUE, TRUE, 'high', TRUE)
ON CONFLICT DO NOTHING;

-- ===========================================================================
-- Permissions
-- ===========================================================================
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA blueteam TO alfred_admin;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA blueteam TO alfred_admin;

-- ===========================================================================
-- Done
-- ===========================================================================
DO $$
BEGIN
    RAISE NOTICE 'blueteam base schema created successfully';
    RAISE NOTICE 'Tables: posture_scores, compliance_controls, security_incidents,';
    RAISE NOTICE '        alert_history, redteam_schedules, notification_subscriptions,';
    RAISE NOTICE '        notification_history, emergency_rules';
END
$$;
