-- Container Vulnerability Scanner Schema
-- Version: 1.0.0
-- Date: 2026-03-11

-- Scan metadata table
CREATE TABLE IF NOT EXISTS blueteam.container_vulnerability_scans (
    scan_id SERIAL PRIMARY KEY,
    scan_date TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    server_name VARCHAR(100) NOT NULL,
    images_scanned INTEGER NOT NULL,
    total_vulnerabilities INTEGER NOT NULL DEFAULT 0,
    scan_duration_seconds INTEGER,
    metadata JSONB,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_container_vuln_scans_date 
    ON blueteam.container_vulnerability_scans(scan_date DESC);
CREATE INDEX IF NOT EXISTS idx_container_vuln_scans_server 
    ON blueteam.container_vulnerability_scans(server_name);

-- Individual vulnerability findings
CREATE TABLE IF NOT EXISTS blueteam.container_vulnerabilities (
    finding_id SERIAL PRIMARY KEY,
    scan_id INTEGER NOT NULL REFERENCES blueteam.container_vulnerability_scans(scan_id),
    image_name VARCHAR(500) NOT NULL,
    cve_id VARCHAR(50) NOT NULL,
    package_name VARCHAR(255) NOT NULL,
    installed_version VARCHAR(100),
    fixed_version VARCHAR(100),
    severity VARCHAR(20) NOT NULL,
    title TEXT,
    description TEXT,
    cvss_score DECIMAL(3,1),
    detected_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    resolved_at TIMESTAMP,
    resolved_by VARCHAR(100),
    resolution_notes TEXT,
    metadata JSONB,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_container_vulns_scan_id 
    ON blueteam.container_vulnerabilities(scan_id);
CREATE INDEX IF NOT EXISTS idx_container_vulns_image 
    ON blueteam.container_vulnerabilities(image_name);
CREATE INDEX IF NOT EXISTS idx_container_vulns_cve 
    ON blueteam.container_vulnerabilities(cve_id);
CREATE INDEX IF NOT EXISTS idx_container_vulns_severity 
    ON blueteam.container_vulnerabilities(severity);

-- View for latest vulnerabilities
CREATE OR REPLACE VIEW blueteam.v_container_vulnerabilities AS
SELECT 
    v.finding_id,
    v.image_name,
    v.cve_id,
    v.package_name,
    v.installed_version,
    v.fixed_version,
    v.severity,
    v.title,
    v.cvss_score,
    v.detected_at,
    v.resolved_at,
    s.scan_date,
    s.server_name,
    s.scan_id,
    CASE 
        WHEN v.resolved_at IS NULL THEN 'open'
        ELSE 'resolved'
    END as status
FROM blueteam.container_vulnerabilities v
JOIN blueteam.container_vulnerability_scans s ON v.scan_id = s.scan_id
WHERE v.resolved_at IS NULL
ORDER BY 
    CASE v.severity
        WHEN 'CRITICAL' THEN 0
        WHEN 'HIGH' THEN 1
        WHEN 'MEDIUM' THEN 2
        WHEN 'LOW' THEN 3
        ELSE 4
    END,
    v.cvss_score DESC NULLS LAST,
    v.detected_at DESC;

COMMENT ON TABLE blueteam.container_vulnerability_scans IS 
'Container image vulnerability scan execution records';

COMMENT ON TABLE blueteam.container_vulnerabilities IS 
'Container image CVE findings from Trivy scans';

COMMENT ON VIEW blueteam.v_container_vulnerabilities IS 
'Current open container vulnerabilities across all servers';
