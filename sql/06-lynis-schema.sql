-- Lynis CIS Audit Database Schema
-- Version: 1.0.0
-- Purpose: Store Lynis security audit results for tracking over time
-- Integration: blueteam schema (same as compliance scanner and malware scanner)

-- ============================================================================
-- TABLES
-- ============================================================================

-- Lynis audit records
CREATE TABLE IF NOT EXISTS blueteam.lynis_audits (
    audit_id SERIAL PRIMARY KEY,
    server_name VARCHAR(255) NOT NULL,
    audit_date TIMESTAMP NOT NULL DEFAULT NOW(),
    hardening_index INTEGER NOT NULL DEFAULT 0,
    tests_performed INTEGER NOT NULL DEFAULT 0,
    warnings_count INTEGER NOT NULL DEFAULT 0,
    suggestions_count INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_lynis_audits_server ON blueteam.lynis_audits(server_name);
CREATE INDEX idx_lynis_audits_date ON blueteam.lynis_audits(audit_date DESC);

COMMENT ON TABLE blueteam.lynis_audits IS 'Lynis security audit summary records';
COMMENT ON COLUMN blueteam.lynis_audits.hardening_index IS 'Lynis hardening index score (0-100)';
COMMENT ON COLUMN blueteam.lynis_audits.tests_performed IS 'Number of security tests performed';

-- Lynis findings
CREATE TABLE IF NOT EXISTS blueteam.lynis_findings (
    finding_id SERIAL PRIMARY KEY,
    audit_id INTEGER NOT NULL REFERENCES blueteam.lynis_audits(audit_id) ON DELETE CASCADE,
    test_id VARCHAR(255) NOT NULL,
    finding_type VARCHAR(50) NOT NULL, -- 'warning', 'suggestion'
    severity VARCHAR(20) NOT NULL DEFAULT 'low', -- 'high', 'medium', 'low'
    description TEXT NOT NULL,
    resolved BOOLEAN NOT NULL DEFAULT FALSE,
    resolved_date TIMESTAMP,
    resolution_notes TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_lynis_findings_audit ON blueteam.lynis_findings(audit_id);
CREATE INDEX idx_lynis_findings_type ON blueteam.lynis_findings(finding_type);
CREATE INDEX idx_lynis_findings_severity ON blueteam.lynis_findings(severity);
CREATE INDEX idx_lynis_findings_resolved ON blueteam.lynis_findings(resolved);

COMMENT ON TABLE blueteam.lynis_findings IS 'Individual Lynis security findings and recommendations';
COMMENT ON COLUMN blueteam.lynis_findings.test_id IS 'Lynis test identifier';
COMMENT ON COLUMN blueteam.lynis_findings.resolved IS 'Whether this finding has been addressed';

-- ============================================================================
-- VIEWS
-- ============================================================================

-- Latest audit for each server
CREATE OR REPLACE VIEW blueteam.v_latest_lynis_audits AS
SELECT
    la.audit_id,
    la.server_name,
    la.audit_date,
    la.hardening_index,
    la.tests_performed,
    la.warnings_count,
    la.suggestions_count,
    COUNT(lf.finding_id) FILTER (WHERE NOT lf.resolved) as unresolved_findings
FROM blueteam.lynis_audits la
LEFT JOIN blueteam.lynis_findings lf ON la.audit_id = lf.audit_id
WHERE la.audit_id IN (
    SELECT MAX(audit_id)
    FROM blueteam.lynis_audits
    GROUP BY server_name
)
GROUP BY la.audit_id, la.server_name, la.audit_date, la.hardening_index,
         la.tests_performed, la.warnings_count, la.suggestions_count
ORDER BY la.server_name;

COMMENT ON VIEW blueteam.v_latest_lynis_audits IS 'Most recent Lynis audit for each server';

-- Unresolved findings across all servers
CREATE OR REPLACE VIEW blueteam.v_unresolved_lynis_findings AS
SELECT
    la.server_name,
    la.audit_date,
    lf.test_id,
    lf.finding_type,
    lf.severity,
    lf.description,
    lf.finding_id,
    lf.audit_id
FROM blueteam.lynis_findings lf
JOIN blueteam.lynis_audits la ON lf.audit_id = la.audit_id
WHERE NOT lf.resolved
  AND la.audit_id IN (
      SELECT MAX(audit_id)
      FROM blueteam.lynis_audits
      GROUP BY server_name
  )
ORDER BY
    CASE lf.severity
        WHEN 'high' THEN 1
        WHEN 'medium' THEN 2
        WHEN 'low' THEN 3
    END,
    la.server_name,
    lf.test_id;

COMMENT ON VIEW blueteam.v_unresolved_lynis_findings IS 'All unresolved Lynis findings from latest audits';

-- Hardening index trend over time
CREATE OR REPLACE VIEW blueteam.v_lynis_hardening_trend AS
SELECT
    server_name,
    audit_date,
    hardening_index,
    warnings_count,
    suggestions_count,
    LAG(hardening_index) OVER (PARTITION BY server_name ORDER BY audit_date) as prev_hardening_index,
    hardening_index - LAG(hardening_index) OVER (PARTITION BY server_name ORDER BY audit_date) as hardening_change
FROM blueteam.lynis_audits
ORDER BY server_name, audit_date DESC;

COMMENT ON VIEW blueteam.v_lynis_hardening_trend IS 'Hardening index changes over time per server';

-- Combined security posture (compliance + lynis)
CREATE OR REPLACE VIEW blueteam.v_security_posture AS
SELECT
    COALESCE(cs.server_name, la.server_name) as server_name,
    cs.overall_score as compliance_score,
    cs.scan_date as compliance_date,
    cs.findings_critical + cs.findings_high + cs.findings_medium as compliance_issues,
    la.hardening_index as lynis_hardening,
    la.audit_date as lynis_date,
    la.warnings_count + la.suggestions_count as lynis_issues,
    ROUND((COALESCE(cs.overall_score, 0) + COALESCE(la.hardening_index, 0)) / 2, 2) as combined_score
FROM blueteam.v_latest_compliance_scans cs
FULL OUTER JOIN blueteam.v_latest_lynis_audits la
    ON cs.server_name = la.server_name
ORDER BY combined_score DESC;

COMMENT ON VIEW blueteam.v_security_posture IS 'Combined view of compliance scanning and Lynis hardening scores';

-- ============================================================================
-- FUNCTIONS
-- ============================================================================

-- Get Lynis statistics for a server
CREATE OR REPLACE FUNCTION blueteam.get_lynis_stats(p_server_name VARCHAR)
RETURNS TABLE (
    latest_audit_date TIMESTAMP,
    current_hardening_index INTEGER,
    previous_hardening_index INTEGER,
    hardening_change INTEGER,
    total_warnings INTEGER,
    total_suggestions INTEGER,
    unresolved_findings INTEGER
) AS $$
BEGIN
    RETURN QUERY
    SELECT
        la.audit_date,
        la.hardening_index,
        prev.hardening_index,
        la.hardening_index - prev.hardening_index,
        la.warnings_count,
        la.suggestions_count,
        COUNT(lf.finding_id) FILTER (WHERE NOT lf.resolved)::INTEGER
    FROM blueteam.lynis_audits la
    LEFT JOIN blueteam.lynis_findings lf ON la.audit_id = lf.audit_id
    LEFT JOIN LATERAL (
        SELECT hardening_index
        FROM blueteam.lynis_audits
        WHERE server_name = p_server_name
          AND audit_id < la.audit_id
        ORDER BY audit_id DESC
        LIMIT 1
    ) prev ON TRUE
    WHERE la.server_name = p_server_name
      AND la.audit_id = (
          SELECT MAX(audit_id)
          FROM blueteam.lynis_audits
          WHERE server_name = p_server_name
      )
    GROUP BY la.audit_date, la.hardening_index, prev.hardening_index,
             la.warnings_count, la.suggestions_count;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION blueteam.get_lynis_stats IS 'Get comprehensive Lynis statistics for a specific server';

-- Mark finding as resolved
CREATE OR REPLACE FUNCTION blueteam.resolve_lynis_finding(
    p_finding_id INTEGER,
    p_resolution_notes TEXT
) RETURNS BOOLEAN AS $$
BEGIN
    UPDATE blueteam.lynis_findings
    SET resolved = TRUE,
        resolved_date = NOW(),
        resolution_notes = p_resolution_notes
    WHERE finding_id = p_finding_id;

    RETURN FOUND;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION blueteam.resolve_lynis_finding IS 'Mark a Lynis finding as resolved with notes';

-- ============================================================================
-- GRANTS
-- ============================================================================

GRANT SELECT ON blueteam.lynis_audits TO blueteam;
GRANT SELECT ON blueteam.lynis_findings TO blueteam;
GRANT SELECT ON blueteam.v_latest_lynis_audits TO blueteam;
GRANT SELECT ON blueteam.v_unresolved_lynis_findings TO blueteam;
GRANT SELECT ON blueteam.v_lynis_hardening_trend TO blueteam;
GRANT SELECT ON blueteam.v_security_posture TO blueteam;

-- ============================================================================
-- SAMPLE QUERIES
-- ============================================================================

/*
-- View latest audit for each server
SELECT * FROM blueteam.v_latest_lynis_audits;

-- View all unresolved findings
SELECT * FROM blueteam.v_unresolved_lynis_findings;

-- View combined security posture
SELECT * FROM blueteam.v_security_posture;

-- View hardening trend for a server
SELECT * FROM blueteam.v_lynis_hardening_trend WHERE server_name = 'alfred';

-- Get comprehensive stats for a server
SELECT * FROM blueteam.get_lynis_stats('alfred');

-- Mark a finding as resolved
SELECT blueteam.resolve_lynis_finding(123, 'Updated SSH configuration as recommended');
*/
