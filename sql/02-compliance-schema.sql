-- ============================================================================
-- Cyber-Guardian: Compliance Scanning Schema
-- ============================================================================
-- Version: 1.0.0
-- Date: 2026-03-10
-- Purpose: Infrastructure compliance and security configuration auditing
-- Schema: blueteam
--
-- This schema stores compliance scan results for:
-- - AWS security configuration (IMDSv2, EBS encryption, security groups)
-- - OS-level security (patches, SSH hardening, firewall)
-- - Service-specific checks (Docker, WordPress, MailCow)
-- ============================================================================

-- ============================================================================
-- 1. COMPLIANCE SCANS TABLE
-- ============================================================================
-- Stores metadata about each compliance scan execution

CREATE TABLE IF NOT EXISTS blueteam.compliance_scans (
    scan_id SERIAL PRIMARY KEY,
    server_name VARCHAR(100) NOT NULL,
    server_type VARCHAR(50) NOT NULL,  -- 'aws-ec2', 'local', 'remote-ssh'
    scan_date TIMESTAMP NOT NULL DEFAULT NOW(),
    scan_duration_seconds INTEGER,
    overall_score NUMERIC(5,2),  -- Calculated score 0-100
    findings_critical INTEGER DEFAULT 0,
    findings_high INTEGER DEFAULT 0,
    findings_medium INTEGER DEFAULT 0,
    findings_low INTEGER DEFAULT 0,
    findings_pass INTEGER DEFAULT 0,
    checks_total INTEGER DEFAULT 0,
    checks_run INTEGER DEFAULT 0,
    checks_skipped INTEGER DEFAULT 0,
    scan_config JSONB,  -- Configuration used for this scan
    metadata JSONB,     -- Flexible metadata (AWS region, instance ID, etc.)
    created_at TIMESTAMP DEFAULT NOW()
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_compliance_scans_server ON blueteam.compliance_scans(server_name);
CREATE INDEX IF NOT EXISTS idx_compliance_scans_date ON blueteam.compliance_scans(scan_date DESC);
CREATE INDEX IF NOT EXISTS idx_compliance_scans_server_date ON blueteam.compliance_scans(server_name, scan_date DESC);
CREATE INDEX IF NOT EXISTS idx_compliance_scans_type ON blueteam.compliance_scans(server_type);

COMMENT ON TABLE blueteam.compliance_scans IS 'Compliance scan execution metadata';
COMMENT ON COLUMN blueteam.compliance_scans.server_type IS 'Server platform: aws-ec2, local, remote-ssh';
COMMENT ON COLUMN blueteam.compliance_scans.overall_score IS 'Calculated compliance score 0-100';
COMMENT ON COLUMN blueteam.compliance_scans.scan_config IS 'JSON configuration used for scan (checks enabled, thresholds)';

-- ============================================================================
-- 2. COMPLIANCE FINDINGS TABLE
-- ============================================================================
-- Stores individual compliance check results

CREATE TABLE IF NOT EXISTS blueteam.compliance_findings (
    finding_id SERIAL PRIMARY KEY,
    scan_id INTEGER NOT NULL REFERENCES blueteam.compliance_scans(scan_id) ON DELETE CASCADE,
    check_category VARCHAR(50) NOT NULL,  -- 'aws', 'os', 'ssh', 'docker', 'wordpress', etc.
    check_name VARCHAR(100) NOT NULL,     -- Human-readable check name
    check_id VARCHAR(100) NOT NULL,       -- Unique identifier (e.g., 'aws-imdsv2', 'ssh-root-login')
    status VARCHAR(20) NOT NULL,          -- 'pass', 'fail', 'warning', 'info', 'skip'
    severity VARCHAR(20),                 -- 'critical', 'high', 'medium', 'low' (NULL for pass)
    finding_summary TEXT,                 -- Brief description of finding
    finding_details TEXT,                 -- Detailed finding information
    remediation_steps TEXT,               -- How to fix this issue

    -- Resource identifiers
    aws_resource_id VARCHAR(255),         -- AWS resource ID (instance, volume, etc.)
    aws_resource_type VARCHAR(100),       -- AWS resource type (ec2, ebs, sg, etc.)
    file_path TEXT,                       -- File path for file-based checks
    service_name VARCHAR(100),            -- Service/daemon name

    -- Compliance framework mapping
    cis_benchmark VARCHAR(50),            -- CIS benchmark reference (e.g., '5.2.1')
    aws_foundational_security VARCHAR(50), -- AWS FSB control ID (e.g., 'EC2.8')
    nist_csf VARCHAR(50),                 -- NIST CSF reference

    -- Resolution tracking
    detected_at TIMESTAMP DEFAULT NOW(),
    resolved_at TIMESTAMP,
    resolved_by VARCHAR(100),
    resolution_notes TEXT,

    -- Additional metadata
    check_output TEXT,                    -- Raw output from check (for debugging)
    metadata JSONB,                       -- Flexible additional data
    created_at TIMESTAMP DEFAULT NOW()
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_compliance_findings_scan ON blueteam.compliance_findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_compliance_findings_status ON blueteam.compliance_findings(status);
CREATE INDEX IF NOT EXISTS idx_compliance_findings_severity ON blueteam.compliance_findings(severity);
CREATE INDEX IF NOT EXISTS idx_compliance_findings_category ON blueteam.compliance_findings(check_category);
CREATE INDEX IF NOT EXISTS idx_compliance_findings_unresolved ON blueteam.compliance_findings(resolved_at) WHERE resolved_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_compliance_findings_check_id ON blueteam.compliance_findings(check_id);

COMMENT ON TABLE blueteam.compliance_findings IS 'Individual compliance check results and findings';
COMMENT ON COLUMN blueteam.compliance_findings.check_category IS 'Category: aws, os, ssh, docker, wordpress, mailcow, etc.';
COMMENT ON COLUMN blueteam.compliance_findings.status IS 'Result: pass, fail, warning, info, skip';
COMMENT ON COLUMN blueteam.compliance_findings.severity IS 'Severity for failures: critical, high, medium, low';

-- ============================================================================
-- 3. VIEWS
-- ============================================================================

-- View: Latest compliance scan per server
CREATE OR REPLACE VIEW blueteam.v_latest_compliance_scans AS
SELECT DISTINCT ON (server_name)
    scan_id,
    server_name,
    server_type,
    scan_date,
    overall_score,
    findings_critical,
    findings_high,
    findings_medium,
    findings_low,
    findings_pass,
    checks_total,
    checks_run,
    metadata
FROM blueteam.compliance_scans
ORDER BY server_name, scan_date DESC;

COMMENT ON VIEW blueteam.v_latest_compliance_scans IS 'Most recent compliance scan for each server';

-- View: Active (unresolved) compliance findings
CREATE OR REPLACE VIEW blueteam.v_active_compliance_findings AS
SELECT
    f.finding_id,
    s.server_name,
    s.server_type,
    f.check_category,
    f.check_name,
    f.check_id,
    f.severity,
    f.finding_summary,
    f.remediation_steps,
    f.detected_at,
    f.cis_benchmark,
    f.aws_foundational_security,
    s.scan_date
FROM blueteam.compliance_findings f
JOIN blueteam.compliance_scans s ON f.scan_id = s.scan_id
WHERE f.status = 'fail'
  AND f.resolved_at IS NULL
ORDER BY
    CASE f.severity
        WHEN 'critical' THEN 1
        WHEN 'high' THEN 2
        WHEN 'medium' THEN 3
        WHEN 'low' THEN 4
        ELSE 5
    END,
    f.detected_at DESC;

COMMENT ON VIEW blueteam.v_active_compliance_findings IS 'Unresolved compliance failures ordered by severity';

-- View: Compliance findings summary by server
CREATE OR REPLACE VIEW blueteam.v_compliance_summary_by_server AS
SELECT
    s.server_name,
    s.server_type,
    COUNT(*) FILTER (WHERE f.status = 'fail' AND f.severity = 'critical') as critical_findings,
    COUNT(*) FILTER (WHERE f.status = 'fail' AND f.severity = 'high') as high_findings,
    COUNT(*) FILTER (WHERE f.status = 'fail' AND f.severity = 'medium') as medium_findings,
    COUNT(*) FILTER (WHERE f.status = 'fail' AND f.severity = 'low') as low_findings,
    COUNT(*) FILTER (WHERE f.status = 'pass') as passing_checks,
    MAX(s.scan_date) as last_scan_date,
    MAX(s.overall_score) as latest_score
FROM blueteam.compliance_scans s
LEFT JOIN blueteam.compliance_findings f ON s.scan_id = f.scan_id
WHERE s.scan_id IN (
    SELECT DISTINCT ON (server_name) scan_id
    FROM blueteam.compliance_scans
    ORDER BY server_name, scan_date DESC
)
GROUP BY s.server_name, s.server_type;

COMMENT ON VIEW blueteam.v_compliance_summary_by_server IS 'Compliance status summary for each server';

-- View: Compliance findings by category
CREATE OR REPLACE VIEW blueteam.v_compliance_by_category AS
SELECT
    s.server_name,
    f.check_category,
    COUNT(*) FILTER (WHERE f.status = 'fail' AND f.severity = 'critical') as critical,
    COUNT(*) FILTER (WHERE f.status = 'fail' AND f.severity = 'high') as high,
    COUNT(*) FILTER (WHERE f.status = 'fail' AND f.severity = 'medium') as medium,
    COUNT(*) FILTER (WHERE f.status = 'fail' AND f.severity = 'low') as low,
    COUNT(*) FILTER (WHERE f.status = 'pass') as pass,
    COUNT(*) as total_checks
FROM blueteam.compliance_scans s
JOIN blueteam.compliance_findings f ON s.scan_id = f.scan_id
WHERE s.scan_id IN (
    SELECT DISTINCT ON (server_name) scan_id
    FROM blueteam.compliance_scans
    ORDER BY server_name, scan_date DESC
)
GROUP BY s.server_name, f.check_category
ORDER BY s.server_name, f.check_category;

COMMENT ON VIEW blueteam.v_compliance_by_category IS 'Compliance findings grouped by check category';

-- ============================================================================
-- 4. FUNCTIONS
-- ============================================================================

-- Function: Calculate compliance score
CREATE OR REPLACE FUNCTION blueteam.calculate_compliance_score(
    p_scan_id INTEGER DEFAULT NULL
)
RETURNS NUMERIC AS $$
DECLARE
    v_score NUMERIC;
    v_critical INTEGER;
    v_high INTEGER;
    v_medium INTEGER;
    v_low INTEGER;
    v_pass INTEGER;
    v_total INTEGER;
BEGIN
    -- If scan_id provided, calculate for that scan
    -- Otherwise, calculate across all latest scans

    IF p_scan_id IS NOT NULL THEN
        SELECT
            COUNT(*) FILTER (WHERE status = 'fail' AND severity = 'critical'),
            COUNT(*) FILTER (WHERE status = 'fail' AND severity = 'high'),
            COUNT(*) FILTER (WHERE status = 'fail' AND severity = 'medium'),
            COUNT(*) FILTER (WHERE status = 'fail' AND severity = 'low'),
            COUNT(*) FILTER (WHERE status = 'pass'),
            COUNT(*)
        INTO v_critical, v_high, v_medium, v_low, v_pass, v_total
        FROM blueteam.compliance_findings
        WHERE scan_id = p_scan_id;
    ELSE
        SELECT
            COUNT(*) FILTER (WHERE f.status = 'fail' AND f.severity = 'critical'),
            COUNT(*) FILTER (WHERE f.status = 'fail' AND f.severity = 'high'),
            COUNT(*) FILTER (WHERE f.status = 'fail' AND f.severity = 'medium'),
            COUNT(*) FILTER (WHERE f.status = 'fail' AND f.severity = 'low'),
            COUNT(*) FILTER (WHERE f.status = 'pass'),
            COUNT(*)
        INTO v_critical, v_high, v_medium, v_low, v_pass, v_total
        FROM blueteam.compliance_findings f
        JOIN blueteam.compliance_scans s ON f.scan_id = s.scan_id
        WHERE s.scan_id IN (
            SELECT DISTINCT ON (server_name) scan_id
            FROM blueteam.compliance_scans
            ORDER BY server_name, scan_date DESC
        );
    END IF;

    -- If no checks run, return NULL
    IF v_total = 0 THEN
        RETURN NULL;
    END IF;

    -- Calculate score: Start at 100, deduct points for failures
    -- Critical: -20 points each
    -- High: -10 points each
    -- Medium: -5 points each
    -- Low: -2 points each
    v_score := 100.0 - (
        (v_critical * 20) +
        (v_high * 10) +
        (v_medium * 5) +
        (v_low * 2)
    );

    -- Ensure score is between 0 and 100
    v_score := GREATEST(0, LEAST(100, v_score));

    RETURN ROUND(v_score, 2);
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION blueteam.calculate_compliance_score IS 'Calculate compliance score 0-100 based on findings severity';

-- Function: Get compliance statistics for date range
CREATE OR REPLACE FUNCTION blueteam.get_compliance_stats(
    p_server_name VARCHAR DEFAULT NULL,
    p_start_date TIMESTAMP DEFAULT NOW() - INTERVAL '30 days',
    p_end_date TIMESTAMP DEFAULT NOW()
)
RETURNS TABLE(
    server_name VARCHAR,
    total_scans BIGINT,
    avg_score NUMERIC,
    min_score NUMERIC,
    max_score NUMERIC,
    total_findings BIGINT,
    critical_findings BIGINT,
    high_findings BIGINT,
    medium_findings BIGINT,
    low_findings BIGINT,
    last_scan_date TIMESTAMP
) AS $$
BEGIN
    RETURN QUERY
    SELECT
        s.server_name,
        COUNT(DISTINCT s.scan_id)::BIGINT as total_scans,
        ROUND(AVG(s.overall_score), 2) as avg_score,
        MIN(s.overall_score) as min_score,
        MAX(s.overall_score) as max_score,
        COUNT(f.finding_id)::BIGINT as total_findings,
        COUNT(*) FILTER (WHERE f.status = 'fail' AND f.severity = 'critical')::BIGINT as critical_findings,
        COUNT(*) FILTER (WHERE f.status = 'fail' AND f.severity = 'high')::BIGINT as high_findings,
        COUNT(*) FILTER (WHERE f.status = 'fail' AND f.severity = 'medium')::BIGINT as medium_findings,
        COUNT(*) FILTER (WHERE f.status = 'fail' AND f.severity = 'low')::BIGINT as low_findings,
        MAX(s.scan_date) as last_scan_date
    FROM blueteam.compliance_scans s
    LEFT JOIN blueteam.compliance_findings f ON s.scan_id = f.scan_id
    WHERE s.scan_date BETWEEN p_start_date AND p_end_date
        AND (p_server_name IS NULL OR s.server_name = p_server_name)
    GROUP BY s.server_name;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION blueteam.get_compliance_stats IS 'Get compliance statistics for servers over a date range';

-- ============================================================================
-- 5. SAMPLE DATA (for testing)
-- ============================================================================

-- Insert sample compliance scan
INSERT INTO blueteam.compliance_scans (
    server_name,
    server_type,
    scan_date,
    scan_duration_seconds,
    overall_score,
    findings_critical,
    findings_high,
    findings_medium,
    findings_low,
    findings_pass,
    checks_total,
    checks_run,
    metadata
) VALUES (
    'willie',
    'aws-ec2',
    NOW(),
    45,
    85.5,
    0,
    2,
    3,
    1,
    15,
    21,
    21,
    '{"region": "us-east-2", "instance_id": "i-xxxxxxxxx", "scanner_version": "1.0.0"}'::jsonb
) RETURNING scan_id \gset

-- Insert sample findings
INSERT INTO blueteam.compliance_findings (
    scan_id,
    check_category,
    check_name,
    check_id,
    status,
    severity,
    finding_summary,
    finding_details,
    remediation_steps,
    aws_foundational_security,
    cis_benchmark
) VALUES
(
    :scan_id,
    'aws',
    'IMDSv2 Enforcement',
    'aws-imdsv2',
    'pass',
    NULL,
    'EC2 instance requires IMDSv2',
    'Instance i-xxxxxxxxx has HttpTokens set to required',
    NULL,
    'EC2.8',
    NULL
),
(
    :scan_id,
    'aws',
    'EBS Volume Encryption',
    'aws-ebs-encryption',
    'fail',
    'high',
    'EBS volume is not encrypted',
    'Volume vol-xxxxxxxxx attached to instance is not encrypted at rest',
    'Create encrypted snapshot, create volume from snapshot, attach to instance',
    'EC2.7',
    NULL
),
(
    :scan_id,
    'ssh',
    'Root Login Disabled',
    'ssh-root-login',
    'pass',
    NULL,
    'SSH root login is disabled',
    'PermitRootLogin is set to no in /etc/ssh/sshd_config',
    NULL,
    NULL,
    '5.2.10'
),
(
    :scan_id,
    'ssh',
    'Password Authentication',
    'ssh-password-auth',
    'fail',
    'medium',
    'SSH password authentication is enabled',
    'PasswordAuthentication is set to yes in /etc/ssh/sshd_config',
    'Set PasswordAuthentication no in /etc/ssh/sshd_config and restart sshd',
    NULL,
    '5.2.11'
);

-- ============================================================================
-- 6. VERIFICATION QUERIES
-- ============================================================================

-- Verify tables created
SELECT schemaname, tablename
FROM pg_tables
WHERE schemaname = 'blueteam'
  AND tablename LIKE 'compliance%'
ORDER BY tablename;

-- Verify views created
SELECT schemaname, viewname
FROM pg_views
WHERE schemaname = 'blueteam'
  AND viewname LIKE '%compliance%'
ORDER BY viewname;

-- Verify functions created
SELECT routine_name, routine_type
FROM information_schema.routines
WHERE routine_schema = 'blueteam'
  AND routine_name LIKE '%compliance%'
ORDER BY routine_name;

-- Test compliance score calculation
SELECT blueteam.calculate_compliance_score(:scan_id) as compliance_score;

-- Test latest scans view
SELECT * FROM blueteam.v_latest_compliance_scans;

-- Test active findings view
SELECT * FROM blueteam.v_active_compliance_findings;

-- Test compliance summary
SELECT * FROM blueteam.v_compliance_summary_by_server;

-- Note: get_compliance_stats() function can be tested after scanner runs:
-- SELECT * FROM blueteam.get_compliance_stats('willie', NOW() - INTERVAL '30 days', NOW());

-- ============================================================================
-- END OF SCHEMA
-- ============================================================================
