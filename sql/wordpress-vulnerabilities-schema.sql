-- WordPress Vulnerability Scanner Schema
-- Version: 1.0.0
-- Date: 2026-03-11

-- Scan metadata table
CREATE TABLE IF NOT EXISTS blueteam.wordpress_vulnerability_scans (
    scan_id SERIAL PRIMARY KEY,
    scan_date TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    sites_scanned INTEGER NOT NULL,
    total_vulnerabilities INTEGER NOT NULL DEFAULT 0,
    scan_duration_seconds INTEGER,
    metadata JSONB,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_wp_vuln_scans_date 
    ON blueteam.wordpress_vulnerability_scans(scan_date DESC);

-- Individual vulnerability findings
CREATE TABLE IF NOT EXISTS blueteam.wordpress_vulnerabilities (
    finding_id SERIAL PRIMARY KEY,
    scan_id INTEGER NOT NULL REFERENCES blueteam.wordpress_vulnerability_scans(scan_id),
    domain VARCHAR(255) NOT NULL,
    vulnerability_type VARCHAR(50) NOT NULL, -- wordpress-core, plugin, theme
    component_name VARCHAR(255) NOT NULL, -- plugin slug or 'wordpress-core'
    component_version VARCHAR(50),
    severity VARCHAR(20) NOT NULL, -- CRITICAL, HIGH, MEDIUM, LOW
    title TEXT NOT NULL,
    description TEXT,
    recommendation TEXT,
    cve_id VARCHAR(50), -- CVE identifier if applicable
    cvss_score DECIMAL(3,1), -- 0.0 - 10.0
    fixed_version VARCHAR(50), -- Version that fixes the vulnerability
    detected_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    resolved_at TIMESTAMP,
    resolved_by VARCHAR(100),
    resolution_notes TEXT,
    metadata JSONB,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_wp_vulns_scan_id 
    ON blueteam.wordpress_vulnerabilities(scan_id);
CREATE INDEX IF NOT EXISTS idx_wp_vulns_domain 
    ON blueteam.wordpress_vulnerabilities(domain);
CREATE INDEX IF NOT EXISTS idx_wp_vulns_severity 
    ON blueteam.wordpress_vulnerabilities(severity);
CREATE INDEX IF NOT EXISTS idx_wp_vulns_type 
    ON blueteam.wordpress_vulnerabilities(vulnerability_type);
CREATE INDEX IF NOT EXISTS idx_wp_vulns_resolved 
    ON blueteam.wordpress_vulnerabilities(resolved_at);

-- View for latest vulnerabilities
CREATE OR REPLACE VIEW blueteam.v_wordpress_vulnerabilities AS
SELECT 
    v.finding_id,
    v.domain,
    v.vulnerability_type,
    v.component_name,
    v.component_version,
    v.severity,
    v.title,
    v.description,
    v.recommendation,
    v.cve_id,
    v.cvss_score,
    v.fixed_version,
    v.detected_at,
    v.resolved_at,
    s.scan_date,
    s.scan_id,
    CASE 
        WHEN v.resolved_at IS NULL THEN 'open'
        ELSE 'resolved'
    END as status
FROM blueteam.wordpress_vulnerabilities v
JOIN blueteam.wordpress_vulnerability_scans s ON v.scan_id = s.scan_id
WHERE v.resolved_at IS NULL
ORDER BY 
    CASE v.severity
        WHEN 'CRITICAL' THEN 0
        WHEN 'HIGH' THEN 1
        WHEN 'MEDIUM' THEN 2
        WHEN 'LOW' THEN 3
        ELSE 4
    END,
    v.detected_at DESC;

-- View for scan summary
CREATE OR REPLACE VIEW blueteam.v_wordpress_scan_summary AS
SELECT 
    s.scan_id,
    s.scan_date,
    s.sites_scanned,
    s.total_vulnerabilities,
    COUNT(CASE WHEN v.severity = 'CRITICAL' AND v.resolved_at IS NULL THEN 1 END) as critical_open,
    COUNT(CASE WHEN v.severity = 'HIGH' AND v.resolved_at IS NULL THEN 1 END) as high_open,
    COUNT(CASE WHEN v.severity = 'MEDIUM' AND v.resolved_at IS NULL THEN 1 END) as medium_open,
    COUNT(CASE WHEN v.severity = 'LOW' AND v.resolved_at IS NULL THEN 1 END) as low_open,
    COUNT(CASE WHEN v.resolved_at IS NOT NULL THEN 1 END) as resolved_count
FROM blueteam.wordpress_vulnerability_scans s
LEFT JOIN blueteam.wordpress_vulnerabilities v ON s.scan_id = v.scan_id
GROUP BY s.scan_id, s.scan_date, s.sites_scanned, s.total_vulnerabilities
ORDER BY s.scan_date DESC;

COMMENT ON TABLE blueteam.wordpress_vulnerability_scans IS 
'WordPress vulnerability scan execution records';

COMMENT ON TABLE blueteam.wordpress_vulnerabilities IS 
'Individual WordPress vulnerability findings (core, plugins, themes)';

COMMENT ON VIEW blueteam.v_wordpress_vulnerabilities IS 
'Current open WordPress vulnerabilities across all sites';

COMMENT ON VIEW blueteam.v_wordpress_scan_summary IS 
'Summary statistics for WordPress vulnerability scans';
