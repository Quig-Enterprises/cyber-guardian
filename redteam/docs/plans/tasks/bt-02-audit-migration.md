# BT-02: Audit Events Database Migration

**Goal:** Create the `audit_events` table and `blueteam` schema in PostgreSQL for the centralized audit logging system.

**Files:**
- Create: `/var/www/html/eqmon/migrations/030_audit_events.sql`

**Depends on:** BT-01

---

## Step 1: Create the migration file

```sql
-- Migration 030: Audit Events & Blue Team Schema
-- NIST SP 800-171: 3.3.1 (create audit logs), 3.3.2 (user traceability),
--                  3.3.7 (timestamps), 3.3.8 (protect audit info)

BEGIN;

-- ============================================================
-- Audit Events table (public schema — written by PHP app)
-- ============================================================
CREATE TABLE IF NOT EXISTS audit_events (
    event_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    category TEXT NOT NULL CHECK (category IN ('auth', 'access', 'admin', 'data', 'ai', 'system')),
    action TEXT NOT NULL,
    result TEXT NOT NULL CHECK (result IN ('success', 'failure', 'denied')),
    user_id UUID,
    session_id TEXT,
    ip_address INET,
    user_agent VARCHAR(500),
    resource_type TEXT,
    resource_id TEXT,
    instance_id UUID,
    cui_accessed BOOLEAN DEFAULT FALSE,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE audit_events IS 'Centralized audit log for NIST 800-171 compliance (3.3.1, 3.3.2)';

-- Performance indexes
CREATE INDEX idx_audit_ts ON audit_events (timestamp DESC);
CREATE INDEX idx_audit_user_ts ON audit_events (user_id, timestamp DESC);
CREATE INDEX idx_audit_ip_ts ON audit_events (ip_address, timestamp DESC);
CREATE INDEX idx_audit_cat_ts ON audit_events (category, timestamp DESC);
CREATE INDEX idx_audit_cui ON audit_events (timestamp DESC) WHERE cui_accessed = TRUE;

-- ============================================================
-- Blue Team schema (for Python analysis engine)
-- ============================================================
CREATE SCHEMA IF NOT EXISTS blueteam;

-- Security incidents (NIST 3.6.1, 3.6.2)
CREATE TABLE blueteam.security_incidents (
    incident_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    title TEXT NOT NULL,
    description TEXT,
    severity TEXT NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low')),
    status TEXT NOT NULL DEFAULT 'detected' CHECK (status IN ('detected', 'analyzing', 'contained', 'eradicated', 'recovered', 'closed')),
    detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    detected_by TEXT NOT NULL,
    correlation_rule TEXT,
    assigned_to TEXT,
    nist_controls TEXT[],
    cui_involved BOOLEAN DEFAULT FALSE,
    dfars_reportable BOOLEAN DEFAULT FALSE,
    dfars_reported_at TIMESTAMPTZ,
    contained_at TIMESTAMPTZ,
    eradicated_at TIMESTAMPTZ,
    recovered_at TIMESTAMPTZ,
    closed_at TIMESTAMPTZ,
    root_cause TEXT,
    lessons_learned TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_incidents_status ON blueteam.security_incidents (status) WHERE status != 'closed';
CREATE INDEX idx_incidents_severity ON blueteam.security_incidents (severity, detected_at DESC);

-- Incident evidence chain (NIST 3.6.2)
CREATE TABLE blueteam.incident_evidence (
    evidence_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id UUID NOT NULL REFERENCES blueteam.security_incidents(incident_id) ON DELETE CASCADE,
    evidence_type TEXT NOT NULL CHECK (evidence_type IN ('log_excerpt', 'screenshot', 'config', 'timeline', 'network_capture', 'file', 'note')),
    description TEXT NOT NULL,
    content TEXT,
    file_path TEXT,
    collected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    collected_by TEXT NOT NULL,
    hash_sha256 TEXT
);

CREATE INDEX idx_evidence_incident ON blueteam.incident_evidence (incident_id);

-- Compliance controls (NIST 3.12.1-3.12.4)
CREATE TABLE blueteam.compliance_controls (
    control_id TEXT PRIMARY KEY,
    family TEXT NOT NULL,
    family_id TEXT NOT NULL,
    requirement TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'not_assessed' CHECK (status IN ('implemented', 'partially_implemented', 'planned', 'not_implemented', 'not_applicable', 'not_assessed')),
    implementation_notes TEXT,
    evidence_type TEXT CHECK (evidence_type IN ('automated', 'manual', 'hybrid')),
    responsible_party TEXT,
    last_assessed TIMESTAMPTZ,
    next_assessment TIMESTAMPTZ,
    assessor_notes TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Compliance evidence (NIST 3.12.1)
CREATE TABLE blueteam.compliance_evidence (
    evidence_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    control_id TEXT NOT NULL REFERENCES blueteam.compliance_controls(control_id),
    evidence_type TEXT NOT NULL CHECK (evidence_type IN ('log_sample', 'config_screenshot', 'test_result', 'policy_doc', 'scan_result', 'automated_check')),
    description TEXT NOT NULL,
    content TEXT,
    file_path TEXT,
    collected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    automated BOOLEAN DEFAULT FALSE,
    valid_until TIMESTAMPTZ
);

CREATE INDEX idx_compliance_evidence_control ON blueteam.compliance_evidence (control_id);

-- POA&M items (NIST 3.12.2)
CREATE TABLE blueteam.poam_items (
    poam_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    control_id TEXT NOT NULL REFERENCES blueteam.compliance_controls(control_id),
    weakness_description TEXT NOT NULL,
    risk_level TEXT NOT NULL CHECK (risk_level IN ('very_high', 'high', 'moderate', 'low')),
    remediation_plan TEXT NOT NULL,
    milestone TEXT,
    scheduled_completion TIMESTAMPTZ,
    actual_completion TIMESTAMPTZ,
    status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'in_progress', 'completed', 'accepted_risk')),
    resources_required TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_poam_status ON blueteam.poam_items (status) WHERE status != 'completed';

-- Alert rules and history (NIST 3.3.4, 3.14.3)
CREATE TABLE blueteam.alert_rules (
    rule_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    severity TEXT NOT NULL,
    nist_controls TEXT[],
    enabled BOOLEAN DEFAULT TRUE,
    config JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE blueteam.alert_history (
    alert_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    rule_id TEXT REFERENCES blueteam.alert_rules(rule_id),
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    event_ids UUID[],
    incident_id UUID REFERENCES blueteam.security_incidents(incident_id),
    acknowledged BOOLEAN DEFAULT FALSE,
    acknowledged_by TEXT,
    acknowledged_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_alerts_unacked ON blueteam.alert_history (created_at DESC) WHERE acknowledged = FALSE;

-- Posture scores (for trend tracking)
CREATE TABLE blueteam.posture_scores (
    score_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scored_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    overall_score NUMERIC(5,2),
    compliance_score NUMERIC(5,2),
    redteam_score NUMERIC(5,2),
    monitoring_score NUMERIC(5,2),
    incident_score NUMERIC(5,2),
    details JSONB DEFAULT '{}',
    redteam_report_id TEXT
);

CREATE INDEX idx_posture_ts ON blueteam.posture_scores (scored_at DESC);

-- ============================================================
-- Database roles for audit protection (NIST 3.3.8, 3.3.9)
-- ============================================================
-- Append-only role for PHP app
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'eqmon_audit_writer') THEN
        CREATE ROLE eqmon_audit_writer;
    END IF;
END $$;

GRANT INSERT ON audit_events TO eqmon_audit_writer;
-- No UPDATE, DELETE, or TRUNCATE — append-only

-- Read-only role for blue team analysis
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'blueteam_reader') THEN
        CREATE ROLE blueteam_reader;
    END IF;
END $$;

GRANT USAGE ON SCHEMA blueteam TO blueteam_reader;
GRANT SELECT ON ALL TABLES IN SCHEMA blueteam TO blueteam_reader;
GRANT SELECT ON audit_events TO blueteam_reader;

-- Admin role for blue team management
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'blueteam_admin') THEN
        CREATE ROLE blueteam_admin;
    END IF;
END $$;

GRANT USAGE ON SCHEMA blueteam TO blueteam_admin;
GRANT ALL ON ALL TABLES IN SCHEMA blueteam TO blueteam_admin;
GRANT SELECT ON audit_events TO blueteam_admin;
-- blueteam_admin still cannot modify audit_events — only SELECT

COMMIT;
```

---

## Step 2: Run the migration

```bash
cd /var/www/html/eqmon
sudo -u postgres psql -d eqmon -f migrations/030_audit_events.sql
```

**Verify:**
```bash
sudo -u postgres psql -d eqmon -c "\dt audit_events"
sudo -u postgres psql -d eqmon -c "\dt blueteam.*"
```

Expected: `audit_events` in public schema, 8 tables in `blueteam` schema.

---

## Step 3: Grant roles to application users

```bash
sudo -u postgres psql -d eqmon -c "GRANT eqmon_audit_writer TO eqmon;"
sudo -u postgres psql -d eqmon -c "GRANT blueteam_reader TO eqmon;"
```

---

## Step 4: Commit

```bash
cd /var/www/html/eqmon
git add migrations/030_audit_events.sql
git commit -m "feat: add audit_events table and blueteam schema (NIST 3.3.1, 3.3.8)"
```
