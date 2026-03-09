-- Scan Registry Schema
-- Implements ideal hierarchical structure for red team scan results
-- Version: 1.0
-- Created: 2026-03-08
-- Reference: docs/IDEAL_REPORT_STRUCTURE.md

-- ===========================================================================
-- SCAN REGISTRY
-- ===========================================================================
-- Stores metadata about each security scan execution
CREATE TABLE IF NOT EXISTS blueteam.scans (
    id SERIAL PRIMARY KEY,
    scan_id VARCHAR(64) UNIQUE NOT NULL,
    target_url VARCHAR(512) NOT NULL,
    target_name VARCHAR(255),
    target_type VARCHAR(50), -- app, wordpress, static, cloud
    environment VARCHAR(50), -- production, staging, development
    scanner_version VARCHAR(20),
    config_hash VARCHAR(64),
    execution_mode VARCHAR(20), -- full, aws
    scan_date TIMESTAMP NOT NULL,
    duration_ms DECIMAL(10,2),
    report_path VARCHAR(512),
    status VARCHAR(50) DEFAULT 'completed', -- running, completed, failed
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE blueteam.scans IS 'Registry of all security scans with metadata and execution context';
COMMENT ON COLUMN blueteam.scans.scan_id IS 'Unique identifier for this scan (UUID or timestamp-based)';
COMMENT ON COLUMN blueteam.scans.target_url IS 'URL of the target system being scanned';
COMMENT ON COLUMN blueteam.scans.target_type IS 'Type of target: app, wordpress, static, cloud';
COMMENT ON COLUMN blueteam.scans.environment IS 'Environment: production, staging, development';
COMMENT ON COLUMN blueteam.scans.execution_mode IS 'Scan mode: full (all attacks), aws (cloud-only)';
COMMENT ON COLUMN blueteam.scans.config_hash IS 'Hash of scan configuration for reproducibility';

-- Indexes for scan lookups
CREATE INDEX IF NOT EXISTS idx_scans_scan_id ON blueteam.scans(scan_id);
CREATE INDEX IF NOT EXISTS idx_scans_target_url ON blueteam.scans(target_url);
CREATE INDEX IF NOT EXISTS idx_scans_scan_date ON blueteam.scans(scan_date DESC);
CREATE INDEX IF NOT EXISTS idx_scans_status ON blueteam.scans(status);
CREATE INDEX IF NOT EXISTS idx_scans_target_type ON blueteam.scans(target_type);

-- ===========================================================================
-- ATTACK CATALOG
-- ===========================================================================
-- Central catalog of attack modules (populated from code)
CREATE TABLE IF NOT EXISTS blueteam.attack_catalog (
    id SERIAL PRIMARY KEY,
    attack_id VARCHAR(255) UNIQUE NOT NULL, -- e.g., api.account_lockout_bypass
    name VARCHAR(255) NOT NULL,
    category VARCHAR(100) NOT NULL, -- api, compliance, web, ai, aws, infrastructure
    description TEXT,
    default_severity VARCHAR(20), -- critical, high, medium, low
    target_types VARCHAR[] DEFAULT ARRAY['app']::VARCHAR[], -- app, wordpress, static, cloud
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE blueteam.attack_catalog IS 'Catalog of all available attack modules and their metadata';
COMMENT ON COLUMN blueteam.attack_catalog.attack_id IS 'Unique attack identifier matching module name (e.g., api.auth_bypass)';
COMMENT ON COLUMN blueteam.attack_catalog.target_types IS 'Array of applicable target types: app, wordpress, static, cloud';

CREATE INDEX IF NOT EXISTS idx_attack_catalog_attack_id ON blueteam.attack_catalog(attack_id);
CREATE INDEX IF NOT EXISTS idx_attack_catalog_category ON blueteam.attack_catalog(category);

-- ===========================================================================
-- COMPLIANCE MAPPINGS
-- ===========================================================================
-- Maps attack modules to compliance framework controls
CREATE TABLE IF NOT EXISTS blueteam.attack_compliance (
    id SERIAL PRIMARY KEY,
    attack_id VARCHAR(255) REFERENCES blueteam.attack_catalog(attack_id) ON DELETE CASCADE,
    framework VARCHAR(100) NOT NULL, -- NIST-800-171-Rev2, NIST-CSF, PCI-DSS, etc.
    control_id VARCHAR(100) NOT NULL, -- e.g., 3.1.8
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(attack_id, framework, control_id)
);

COMMENT ON TABLE blueteam.attack_compliance IS 'Maps attack modules to compliance framework controls';
COMMENT ON COLUMN blueteam.attack_compliance.framework IS 'Compliance framework name (e.g., NIST-800-171-Rev2)';
COMMENT ON COLUMN blueteam.attack_compliance.control_id IS 'Control identifier within framework (e.g., 3.1.8)';

CREATE INDEX IF NOT EXISTS idx_attack_compliance_attack ON blueteam.attack_compliance(attack_id);
CREATE INDEX IF NOT EXISTS idx_attack_compliance_framework ON blueteam.attack_compliance(framework);
CREATE INDEX IF NOT EXISTS idx_attack_compliance_control ON blueteam.attack_compliance(control_id);

-- ===========================================================================
-- SCAN ATTACKS (ATTACK-LEVEL RESULTS)
-- ===========================================================================
-- Stores aggregated results for each attack module in a scan
CREATE TABLE IF NOT EXISTS blueteam.scan_attacks (
    id SERIAL PRIMARY KEY,
    scan_id INTEGER REFERENCES blueteam.scans(id) ON DELETE CASCADE,
    attack_id VARCHAR(255) REFERENCES blueteam.attack_catalog(attack_id),
    duration_ms DECIMAL(10,2),
    variants_tested INTEGER DEFAULT 0,
    vulnerable_count INTEGER DEFAULT 0,
    partial_count INTEGER DEFAULT 0,
    defended_count INTEGER DEFAULT 0,
    error_count INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(scan_id, attack_id)
);

COMMENT ON TABLE blueteam.scan_attacks IS 'Attack-level results for each attack executed in a scan';
COMMENT ON COLUMN blueteam.scan_attacks.variants_tested IS 'Number of attack variants tested';
COMMENT ON COLUMN blueteam.scan_attacks.vulnerable_count IS 'Count of vulnerable variant results';
COMMENT ON COLUMN blueteam.scan_attacks.partial_count IS 'Count of partial vulnerability results';
COMMENT ON COLUMN blueteam.scan_attacks.defended_count IS 'Count of successfully defended results';

CREATE INDEX IF NOT EXISTS idx_scan_attacks_scan ON blueteam.scan_attacks(scan_id);
CREATE INDEX IF NOT EXISTS idx_scan_attacks_attack ON blueteam.scan_attacks(attack_id);

-- ===========================================================================
-- FINDINGS (VARIANT-LEVEL RESULTS)
-- ===========================================================================
-- Stores individual attack variant test results
CREATE TABLE IF NOT EXISTS blueteam.findings (
    id SERIAL PRIMARY KEY,
    scan_id INTEGER REFERENCES blueteam.scans(id) ON DELETE CASCADE,
    scan_attack_id INTEGER REFERENCES blueteam.scan_attacks(id) ON DELETE CASCADE,
    attack_id VARCHAR(255) NOT NULL,
    variant_id VARCHAR(255) NOT NULL,
    variant_name VARCHAR(255),
    status VARCHAR(20) NOT NULL, -- vulnerable, partial, defended, error, skipped
    severity VARCHAR(20) NOT NULL, -- critical, high, medium, low
    duration_ms DECIMAL(10,2),

    -- Evidence (structured)
    evidence_summary TEXT,
    evidence_details TEXT,
    evidence_proof JSONB,

    -- Request/Response (structured)
    request_data JSONB,
    response_data JSONB,

    -- Remediation
    recommendation TEXT,
    priority VARCHAR(20), -- critical, high, medium, low
    reference_urls TEXT[], -- Array of reference URLs (renamed from 'references' to avoid keyword)

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    UNIQUE(scan_id, attack_id, variant_id)
);

COMMENT ON TABLE blueteam.findings IS 'Individual attack variant test results (findings)';
COMMENT ON COLUMN blueteam.findings.variant_id IS 'Variant identifier within attack module (e.g., rapid_attempts)';
COMMENT ON COLUMN blueteam.findings.status IS 'Test result: vulnerable, partial, defended, error, skipped';
COMMENT ON COLUMN blueteam.findings.evidence_summary IS 'Human-readable evidence summary';
COMMENT ON COLUMN blueteam.findings.evidence_details IS 'Technical details of the finding';
COMMENT ON COLUMN blueteam.findings.evidence_proof IS 'Machine-readable proof data (JSONB)';
COMMENT ON COLUMN blueteam.findings.request_data IS 'Request details (JSONB)';
COMMENT ON COLUMN blueteam.findings.response_data IS 'Response details (JSONB)';
COMMENT ON COLUMN blueteam.findings.reference_urls IS 'Array of reference URLs for remediation guidance';

CREATE INDEX IF NOT EXISTS idx_findings_scan ON blueteam.findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_scan_attack ON blueteam.findings(scan_attack_id);
CREATE INDEX IF NOT EXISTS idx_findings_attack ON blueteam.findings(attack_id);
CREATE INDEX IF NOT EXISTS idx_findings_status ON blueteam.findings(status);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON blueteam.findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_status_severity ON blueteam.findings(status, severity);

-- ===========================================================================
-- MITIGATION FINDINGS LINK
-- ===========================================================================
-- Links findings to mitigation issues (many-to-many)
CREATE TABLE IF NOT EXISTS blueteam.mitigation_findings (
    id SERIAL PRIMARY KEY,
    finding_id INTEGER REFERENCES blueteam.findings(id) ON DELETE CASCADE,
    mitigation_issue_id INTEGER REFERENCES blueteam.mitigation_issues(id) ON DELETE CASCADE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(finding_id, mitigation_issue_id)
);

COMMENT ON TABLE blueteam.mitigation_findings IS 'Links scan findings to mitigation tracking issues';

CREATE INDEX IF NOT EXISTS idx_mitigation_findings_finding ON blueteam.mitigation_findings(finding_id);
CREATE INDEX IF NOT EXISTS idx_mitigation_findings_issue ON blueteam.mitigation_findings(mitigation_issue_id);

-- ===========================================================================
-- SCAN COMPARISONS (HISTORY TRACKING)
-- ===========================================================================
-- Tracks changes between scan runs for regression detection
CREATE TABLE IF NOT EXISTS blueteam.scan_comparisons (
    id SERIAL PRIMARY KEY,
    baseline_scan_id INTEGER REFERENCES blueteam.scans(id) ON DELETE CASCADE,
    current_scan_id INTEGER REFERENCES blueteam.scans(id) ON DELETE CASCADE,
    new_vulnerabilities INTEGER DEFAULT 0,
    fixed_vulnerabilities INTEGER DEFAULT 0,
    regression_count INTEGER DEFAULT 0, -- fixed → vulnerable again
    improvement_count INTEGER DEFAULT 0, -- vulnerable → defended
    comparison_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(baseline_scan_id, current_scan_id)
);

COMMENT ON TABLE blueteam.scan_comparisons IS 'Tracks changes between scan runs for trend analysis';
COMMENT ON COLUMN blueteam.scan_comparisons.new_vulnerabilities IS 'Count of newly discovered vulnerabilities';
COMMENT ON COLUMN blueteam.scan_comparisons.fixed_vulnerabilities IS 'Count of previously vulnerable findings now defended';
COMMENT ON COLUMN blueteam.scan_comparisons.regression_count IS 'Count of previously fixed issues that are vulnerable again';
COMMENT ON COLUMN blueteam.scan_comparisons.improvement_count IS 'Count of improvements (vulnerable → partial/defended)';

CREATE INDEX IF NOT EXISTS idx_scan_comparisons_baseline ON blueteam.scan_comparisons(baseline_scan_id);
CREATE INDEX IF NOT EXISTS idx_scan_comparisons_current ON blueteam.scan_comparisons(current_scan_id);
CREATE INDEX IF NOT EXISTS idx_scan_comparisons_date ON blueteam.scan_comparisons(comparison_date DESC);

-- ===========================================================================
-- PERMISSIONS
-- ===========================================================================
-- Grant permissions to alfred_admin (Project Keystone)
GRANT SELECT, INSERT, UPDATE, DELETE ON blueteam.scans TO alfred_admin;
GRANT SELECT, INSERT, UPDATE, DELETE ON blueteam.attack_catalog TO alfred_admin;
GRANT SELECT, INSERT, UPDATE, DELETE ON blueteam.attack_compliance TO alfred_admin;
GRANT SELECT, INSERT, UPDATE, DELETE ON blueteam.scan_attacks TO alfred_admin;
GRANT SELECT, INSERT, UPDATE, DELETE ON blueteam.findings TO alfred_admin;
GRANT SELECT, INSERT, UPDATE, DELETE ON blueteam.mitigation_findings TO alfred_admin;
GRANT SELECT, INSERT, UPDATE, DELETE ON blueteam.scan_comparisons TO alfred_admin;

-- Grant sequence usage
GRANT USAGE, SELECT ON SEQUENCE blueteam.scans_id_seq TO alfred_admin;
GRANT USAGE, SELECT ON SEQUENCE blueteam.attack_catalog_id_seq TO alfred_admin;
GRANT USAGE, SELECT ON SEQUENCE blueteam.attack_compliance_id_seq TO alfred_admin;
GRANT USAGE, SELECT ON SEQUENCE blueteam.scan_attacks_id_seq TO alfred_admin;
GRANT USAGE, SELECT ON SEQUENCE blueteam.findings_id_seq TO alfred_admin;
GRANT USAGE, SELECT ON SEQUENCE blueteam.mitigation_findings_id_seq TO alfred_admin;
GRANT USAGE, SELECT ON SEQUENCE blueteam.scan_comparisons_id_seq TO alfred_admin;

-- Grant permissions to keystone_admin (for webhost compatibility)
-- This ensures the schema works on both alfred (alfred_admin) and cp.quigs.com (keystone_admin)
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'keystone_admin') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON blueteam.scans TO keystone_admin;
        GRANT SELECT, INSERT, UPDATE, DELETE ON blueteam.attack_catalog TO keystone_admin;
        GRANT SELECT, INSERT, UPDATE, DELETE ON blueteam.attack_compliance TO keystone_admin;
        GRANT SELECT, INSERT, UPDATE, DELETE ON blueteam.scan_attacks TO keystone_admin;
        GRANT SELECT, INSERT, UPDATE, DELETE ON blueteam.findings TO keystone_admin;
        GRANT SELECT, INSERT, UPDATE, DELETE ON blueteam.mitigation_findings TO keystone_admin;
        GRANT SELECT, INSERT, UPDATE, DELETE ON blueteam.scan_comparisons TO keystone_admin;

        GRANT USAGE, SELECT ON SEQUENCE blueteam.scans_id_seq TO keystone_admin;
        GRANT USAGE, SELECT ON SEQUENCE blueteam.attack_catalog_id_seq TO keystone_admin;
        GRANT USAGE, SELECT ON SEQUENCE blueteam.attack_compliance_id_seq TO keystone_admin;
        GRANT USAGE, SELECT ON SEQUENCE blueteam.scan_attacks_id_seq TO keystone_admin;
        GRANT USAGE, SELECT ON SEQUENCE blueteam.findings_id_seq TO keystone_admin;
        GRANT USAGE, SELECT ON SEQUENCE blueteam.mitigation_findings_id_seq TO keystone_admin;
        GRANT USAGE, SELECT ON SEQUENCE blueteam.scan_comparisons_id_seq TO keystone_admin;
    END IF;
END
$$;

-- ===========================================================================
-- COMPLETION MESSAGE
-- ===========================================================================
DO $$
BEGIN
    RAISE NOTICE 'Scan Registry Schema created successfully';
    RAISE NOTICE '';
    RAISE NOTICE 'Tables created:';
    RAISE NOTICE '  - blueteam.scans (scan metadata and execution context)';
    RAISE NOTICE '  - blueteam.attack_catalog (attack module definitions)';
    RAISE NOTICE '  - blueteam.attack_compliance (compliance framework mappings)';
    RAISE NOTICE '  - blueteam.scan_attacks (attack-level results)';
    RAISE NOTICE '  - blueteam.findings (variant-level findings)';
    RAISE NOTICE '  - blueteam.mitigation_findings (finding → mitigation link)';
    RAISE NOTICE '  - blueteam.scan_comparisons (scan history tracking)';
    RAISE NOTICE '';
    RAISE NOTICE 'Permissions granted to: alfred_admin, keystone_admin (if exists)';
    RAISE NOTICE '';
    RAISE NOTICE 'Next steps:';
    RAISE NOTICE '  1. Populate attack_catalog from attack modules';
    RAISE NOTICE '  2. Populate attack_compliance from module metadata';
    RAISE NOTICE '  3. Import existing scan reports into scans table';
    RAISE NOTICE '  4. Link existing mitigation_issues to findings';
END
$$;
