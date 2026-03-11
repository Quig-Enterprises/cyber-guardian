-- Network Security Scanner Schema
-- Version: 1.0.0
-- Date: 2026-03-11

-- Scan metadata table
CREATE TABLE IF NOT EXISTS blueteam.network_security_scans (
    scan_id SERIAL PRIMARY KEY,
    scan_date TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    server_name VARCHAR(100) NOT NULL,
    ports_scanned INTEGER NOT NULL,
    findings_count INTEGER NOT NULL DEFAULT 0,
    scan_duration_seconds INTEGER,
    metadata JSONB,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_network_scans_date 
    ON blueteam.network_security_scans(scan_date DESC);
CREATE INDEX IF NOT EXISTS idx_network_scans_server 
    ON blueteam.network_security_scans(server_name);

-- Discovered ports table
CREATE TABLE IF NOT EXISTS blueteam.network_ports (
    port_id SERIAL PRIMARY KEY,
    scan_id INTEGER NOT NULL REFERENCES blueteam.network_security_scans(scan_id),
    port_number INTEGER NOT NULL,
    bind_address VARCHAR(50),
    process_name VARCHAR(255),
    process_pid INTEGER,
    protocol VARCHAR(10),
    is_approved BOOLEAN DEFAULT FALSE,
    detected_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_network_ports_scan_id 
    ON blueteam.network_ports(scan_id);
CREATE INDEX IF NOT EXISTS idx_network_ports_port 
    ON blueteam.network_ports(port_number);
CREATE INDEX IF NOT EXISTS idx_network_ports_approved 
    ON blueteam.network_ports(is_approved);

-- Security findings table
CREATE TABLE IF NOT EXISTS blueteam.network_security_findings (
    finding_id SERIAL PRIMARY KEY,
    scan_id INTEGER NOT NULL REFERENCES blueteam.network_security_scans(scan_id),
    finding_type VARCHAR(50) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    port_number INTEGER,
    bind_address VARCHAR(50),
    process_name VARCHAR(255),
    title TEXT NOT NULL,
    description TEXT,
    recommendation TEXT,
    detected_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    resolved_at TIMESTAMP,
    resolved_by VARCHAR(100),
    resolution_notes TEXT,
    metadata JSONB,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_network_findings_scan_id 
    ON blueteam.network_security_findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_network_findings_type 
    ON blueteam.network_security_findings(finding_type);
CREATE INDEX IF NOT EXISTS idx_network_findings_severity 
    ON blueteam.network_security_findings(severity);
CREATE INDEX IF NOT EXISTS idx_network_findings_resolved 
    ON blueteam.network_security_findings(resolved_at);

-- View for current open findings
CREATE OR REPLACE VIEW blueteam.v_network_security_findings AS
SELECT 
    f.finding_id,
    f.finding_type,
    f.severity,
    f.port_number,
    f.bind_address,
    f.process_name,
    f.title,
    f.description,
    f.recommendation,
    f.detected_at,
    f.resolved_at,
    s.scan_date,
    s.server_name,
    s.scan_id,
    CASE 
        WHEN f.resolved_at IS NULL THEN 'open'
        ELSE 'resolved'
    END as status
FROM blueteam.network_security_findings f
JOIN blueteam.network_security_scans s ON f.scan_id = s.scan_id
WHERE f.resolved_at IS NULL
ORDER BY 
    CASE f.severity
        WHEN 'CRITICAL' THEN 0
        WHEN 'HIGH' THEN 1
        WHEN 'MEDIUM' THEN 2
        WHEN 'LOW' THEN 3
        ELSE 4
    END,
    f.detected_at DESC;

-- View for port summary
CREATE OR REPLACE VIEW blueteam.v_network_port_summary AS
SELECT 
    s.server_name,
    p.port_number,
    p.bind_address,
    p.process_name,
    p.is_approved,
    COUNT(*) as detection_count,
    MAX(s.scan_date) as last_seen,
    MIN(s.scan_date) as first_seen
FROM blueteam.network_ports p
JOIN blueteam.network_security_scans s ON p.scan_id = s.scan_id
GROUP BY s.server_name, p.port_number, p.bind_address, p.process_name, p.is_approved
ORDER BY s.server_name, p.port_number;

COMMENT ON TABLE blueteam.network_security_scans IS 
'Network security scan execution records';

COMMENT ON TABLE blueteam.network_ports IS 
'Discovered listening ports on scanned servers';

COMMENT ON TABLE blueteam.network_security_findings IS 
'Network security findings (unexpected ports, exposed services, firewall issues)';

COMMENT ON VIEW blueteam.v_network_security_findings IS 
'Current open network security findings across all servers';

COMMENT ON VIEW blueteam.v_network_port_summary IS 
'Historical port activity summary by server';
