-- Mitigation Tracking Schema
-- Tracks vulnerability findings from red team scans and their remediation status
-- Version: 1.0
-- Created: 2026-03-08

-- Mitigation Projects (e.g., "Q1 2026 Red Team Findings")
CREATE TABLE IF NOT EXISTS blueteam.mitigation_projects (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    scan_date DATE NOT NULL,
    scan_report_path VARCHAR(512),
    status VARCHAR(50) DEFAULT 'active', -- active, completed, archived
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Individual vulnerability findings requiring mitigation
CREATE TABLE IF NOT EXISTS blueteam.mitigation_issues (
    id SERIAL PRIMARY KEY,
    project_id INTEGER REFERENCES blueteam.mitigation_projects(id) ON DELETE CASCADE,
    title VARCHAR(512) NOT NULL,
    description TEXT,
    severity VARCHAR(20) NOT NULL, -- critical, high, medium, low
    category VARCHAR(100), -- api, compliance, web, infrastructure, etc.
    attack_name VARCHAR(255), -- e.g., "api.auth_bypass"
    variant VARCHAR(255), -- e.g., "jwt_validation"
    status VARCHAR(50) DEFAULT 'not_started', -- not_started, in_progress, completed, blocked, wont_fix
    priority INTEGER DEFAULT 3, -- 1=highest, 5=lowest
    estimated_hours DECIMAL(5,2),
    actual_hours DECIMAL(5,2),
    assigned_to VARCHAR(255),
    due_date DATE,
    evidence TEXT,
    request_details JSONB,
    response_details JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP
);

-- Remediation steps/tasks for each issue
CREATE TABLE IF NOT EXISTS blueteam.mitigation_tasks (
    id SERIAL PRIMARY KEY,
    issue_id INTEGER REFERENCES blueteam.mitigation_issues(id) ON DELETE CASCADE,
    task_number INTEGER NOT NULL, -- 1, 2, 3, etc.
    description TEXT NOT NULL,
    completed BOOLEAN DEFAULT FALSE,
    completed_at TIMESTAMP,
    completed_by VARCHAR(255),
    notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Activity log for tracking progress
CREATE TABLE IF NOT EXISTS blueteam.mitigation_activity (
    id SERIAL PRIMARY KEY,
    issue_id INTEGER REFERENCES blueteam.mitigation_issues(id) ON DELETE CASCADE,
    activity_type VARCHAR(50) NOT NULL, -- status_change, comment, assignment, verification, etc.
    old_value VARCHAR(255),
    new_value VARCHAR(255),
    comment TEXT,
    user_name VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Re-scan verification results
CREATE TABLE IF NOT EXISTS blueteam.mitigation_verifications (
    id SERIAL PRIMARY KEY,
    issue_id INTEGER REFERENCES blueteam.mitigation_issues(id) ON DELETE CASCADE,
    scan_date TIMESTAMP NOT NULL,
    scan_report_path VARCHAR(512),
    verified BOOLEAN NOT NULL, -- TRUE if vulnerability no longer present
    notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_mitigation_issues_project ON blueteam.mitigation_issues(project_id);
CREATE INDEX IF NOT EXISTS idx_mitigation_issues_status ON blueteam.mitigation_issues(status);
CREATE INDEX IF NOT EXISTS idx_mitigation_issues_severity ON blueteam.mitigation_issues(severity);
CREATE INDEX IF NOT EXISTS idx_mitigation_issues_assigned ON blueteam.mitigation_issues(assigned_to);
CREATE INDEX IF NOT EXISTS idx_mitigation_tasks_issue ON blueteam.mitigation_tasks(issue_id);
CREATE INDEX IF NOT EXISTS idx_mitigation_activity_issue ON blueteam.mitigation_activity(issue_id);
CREATE INDEX IF NOT EXISTS idx_mitigation_verifications_issue ON blueteam.mitigation_verifications(issue_id);

-- Grant permissions
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA blueteam TO alfred_admin;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA blueteam TO alfred_admin;

COMMENT ON TABLE blueteam.mitigation_projects IS 'Tracks groups of related vulnerability findings (e.g., from a single red team scan)';
COMMENT ON TABLE blueteam.mitigation_issues IS 'Individual vulnerabilities requiring remediation';
COMMENT ON TABLE blueteam.mitigation_tasks IS 'Specific remediation steps for each issue';
COMMENT ON TABLE blueteam.mitigation_activity IS 'Audit log of all changes to mitigation issues';
COMMENT ON TABLE blueteam.mitigation_verifications IS 'Re-scan results verifying vulnerability fixes';
