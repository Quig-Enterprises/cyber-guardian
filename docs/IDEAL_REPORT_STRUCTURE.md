# Ideal Attack/Scan Report Structure Analysis

**Version:** 1.0
**Created:** 2026-03-08
**Purpose:** Define the most logical organization for red team scan reports and data structures

---

## Current Architecture Assessment

### Current Structure

**Attack Execution Hierarchy:**
```
Attack Module (e.g., AccountLockoutBypassAttack)
├── name: "api.account_lockout_bypass"
├── category: "api"
├── severity: Severity.MEDIUM
└── execute() → list[AttackResult]
    └── Multiple variants tested:
        ├── "ip_rotation" → AttackResult
        ├── "rapid_attempts" → AttackResult
        └── "rate_limit_header_check" → AttackResult
```

**Current JSON Report Format:**
```json
{
  "generated": "2026-03-08T18:45:40.017192",
  "total_attacks": 83,
  "total_variants": 323,
  "total_vulnerable": 44,

  // Summary by category
  "by_category": {
    "api": { "attacks": 22, "vulnerable": 17, ... },
    "compliance": { "attacks": 22, "vulnerable": 13, ... }
  },

  // Attack-level summaries (rollup stats)
  "attacks": [
    {
      "name": "api.account_lockout_bypass",
      "category": "api",
      "vulnerable": 2,
      "partial": 1,
      "defended": 0
    }
  ],

  // Individual findings (flat array)
  "findings": [
    {
      "attack": "api.account_lockout_bypass",
      "variant": "rapid_attempts",
      "status": "vulnerable",
      "severity": "medium",
      "evidence": "...",
      "details": "...",
      "request": {...},
      "response": {...}
    }
  ]
}
```

**Current Database Schema:**
```
mitigation_projects (scan-level metadata)
├── id, name, scan_date, target_url, scan_report_path
└── mitigation_issues (findings)
    ├── attack_name, variant, severity, category
    ├── evidence (TEXT), request_details (JSONB), response_details (JSONB)
    └── mitigation_tasks (remediation steps)
        └── task_number, description, completed
```

---

## Problems with Current Structure

### 1. **Missing Scan Context**

**Problem:** Reports lack critical metadata about what was scanned.

**Current:**
- No `target` field (hardcoded in import script)
- No `scan_date` field (derived from `generated` timestamp)
- No scan configuration captured
- No target type classification (app/wordpress/static/cloud)

**Impact:**
- Cannot distinguish scans of different targets in same report directory
- Impossible to identify which target/environment was tested
- No historical tracking of what was tested when
- Import scripts must hardcode target URLs

### 2. **Disconnected Attack Metadata**

**Problem:** Attack-level information exists in code but not in report.

**Missing from JSON:**
- Attack description (only in Python docstrings)
- NIST/compliance control mappings (only in Python comments)
- Target type applicability (app/wordpress/static/cloud)
- Attack configuration used (rate limits, throttles, etc.)

**Impact:**
- Cannot understand what an attack does without reading source code
- No compliance traceability in reports
- Cannot filter attacks by target type
- Difficult to reproduce scans with same parameters

### 3. **Flat Findings Array Loses Hierarchy**

**Problem:** The `findings` array is flat, losing the attack→variant relationship.

**Current:**
```json
"findings": [
  {"attack": "api.account_lockout_bypass", "variant": "rapid_attempts"},
  {"attack": "api.account_lockout_bypass", "variant": "ip_rotation"},
  {"attack": "api.auth_bypass", "variant": "jwt_none_alg"}
]
```

**Issues:**
- Must reconstruct attack groupings via string matching
- Duplicate attack metadata across every finding
- Cannot easily query "all variants of this attack"
- Rollup statistics in `attacks` array are redundant

### 4. **Evidence Storage Ambiguity**

**Problem:** Evidence can be stored as TEXT or JSONB, with unclear structure.

**Current Database:**
- `evidence` column: TEXT (storing serialized JSON)
- `request_details`: JSONB
- `response_details`: JSONB

**Report:**
- `evidence`: string (human-readable summary)
- `details`: string (technical explanation)
- `request`: dict
- `response`: dict

**Issues:**
- Inconsistent storage (TEXT vs JSONB)
- Human-readable vs machine-readable data mixed
- Cannot query evidence fields efficiently
- Import script creates nested JSON in TEXT field

### 5. **No Scan Versioning or Comparison**

**Problem:** Cannot compare scan results over time.

**Missing:**
- Scan versioning/numbering
- Baseline vs. current comparison
- Trend tracking (getting better/worse)
- Regression detection (fixed→vulnerable again)

### 6. **Report Location Confusion**

**Current:**
- Summary reports: `reports/redteam-report-*.json`
- Detailed reports: `redteam/reports/redteam-report-*.json`
- Database expects: Configurable path

**Issues:**
- Two different report directories with same naming pattern
- Summary reports lack `findings` array (older format?)
- Import script must know which directory to scan
- File paths are absolute, breaking portability

---

## Ideal Structure (Without Implementation Constraints)

### 1. **Hierarchical Report Schema**

```json
{
  // === SCAN METADATA ===
  "scan_metadata": {
    "scan_id": "scan-20260308-184540-a8f3d2",
    "generated": "2026-03-08T18:45:40.017192",
    "scanner_version": "1.0.0",
    "config_hash": "sha256:abc123...",
    "target": {
      "url": "https://keystone.quigs.com",
      "name": "Project Keystone",
      "environment": "production",
      "type": "app",
      "origin_ip": null
    },
    "execution": {
      "mode": "full",
      "duration_ms": 127456.2,
      "start_time": "2026-03-08T18:43:15.000000",
      "end_time": "2026-03-08T18:45:40.017192",
      "operator": "automated-cron"
    }
  },

  // === SUMMARY STATISTICS ===
  "summary": {
    "attacks_executed": 83,
    "variants_tested": 323,
    "findings": {
      "vulnerable": 44,
      "partial": 74,
      "defended": 154,
      "errors": 20,
      "skipped": 31,
      "not_assessed": 0
    },
    "severity": {
      "critical": 9,
      "high": 17,
      "medium": 16,
      "low": 2
    },
    "by_category": {
      "api": {
        "attacks": 22,
        "vulnerable": 17,
        "partial": 29,
        "defended": 42,
        "errors": 3
      }
      // ... other categories
    }
  },

  // === ATTACK RESULTS (HIERARCHICAL) ===
  "attacks": [
    {
      "attack_id": "api.account_lockout_bypass",
      "name": "Account Lockout Bypass",
      "category": "api",
      "description": "NIST 3.1.8 — Verify account lockout after failed login attempts and resistance to IP rotation bypass",
      "compliance": [
        {"framework": "NIST-800-171-Rev2", "control": "3.1.8"},
        {"framework": "NIST-CSF", "control": "PR.AC-7"}
      ],
      "target_types": ["app"],
      "default_severity": "medium",
      "duration_ms": 70.0,

      // Rollup statistics
      "results_summary": {
        "variants_tested": 3,
        "vulnerable": 2,
        "partial": 1,
        "defended": 0,
        "errors": 0
      },

      // Individual variant results (nested)
      "variants": [
        {
          "variant_id": "rapid_attempts",
          "name": "Rapid Authentication Attempts",
          "status": "vulnerable",
          "severity": "medium",
          "duration_ms": 20.0,

          "evidence": {
            "summary": "All 10 rapid login failures completed in 0.0s without lockout",
            "technical_details": "No rate limiting detected. Brute-force attacks possible.",
            "proof": {
              "requests_sent": 10,
              "elapsed_seconds": 0.02,
              "lockout_triggered": false
            }
          },

          "request": {
            "endpoint": "/api/auth/login.php",
            "method": "POST",
            "attempts": 10,
            "target_email": "redteam-sysadmin@example.com"
          },

          "response": {
            "status_codes": [404, 404, 404, 404, 404, 404, 404, 404, 404, 404],
            "lockout_headers": null,
            "rate_limit_headers": null
          },

          "recommendation": {
            "priority": "high",
            "remediation": "Implement account lockout after 5 failed attempts within 15 minutes",
            "references": [
              "https://pages.nist.gov/800-63-3/sp800-63b.html#memsecretver",
              "https://owasp.org/www-community/controls/Blocking_Brute_Force_Attacks"
            ]
          }
        },
        {
          "variant_id": "ip_rotation",
          "status": "partial",
          // ...
        }
      ]
    }
    // ... other attacks
  ],

  // === CONFIGURATION SNAPSHOT ===
  "scan_config": {
    "execution_mode": "full",
    "rate_limit_testing": true,
    "rate_limit_test_ip": "203.0.113.99",
    "cleanup_enabled": true,
    "ai_attacker_enabled": true,
    "models": {
      "attacker": "claude-sonnet-4-6",
      "judge": "claude-haiku-4-5-20251001"
    },
    "throttles": {},
    "skip_attacks": []
  }
}
```

### 2. **Database Schema Improvements**

```sql
-- === SCAN REGISTRY ===
CREATE TABLE blueteam.scans (
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
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_scans_target_url ON blueteam.scans(target_url);
CREATE INDEX idx_scans_scan_date ON blueteam.scans(scan_date);
CREATE INDEX idx_scans_status ON blueteam.scans(status);

-- === ATTACK DEFINITIONS (CATALOG) ===
-- Stores metadata about attack modules (populated from code)
CREATE TABLE blueteam.attack_catalog (
    id SERIAL PRIMARY KEY,
    attack_id VARCHAR(255) UNIQUE NOT NULL, -- api.account_lockout_bypass
    name VARCHAR(255) NOT NULL,
    category VARCHAR(100),
    description TEXT,
    default_severity VARCHAR(20),
    target_types VARCHAR[] DEFAULT '{"app"}',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- === COMPLIANCE MAPPINGS ===
CREATE TABLE blueteam.attack_compliance (
    id SERIAL PRIMARY KEY,
    attack_id VARCHAR(255) REFERENCES blueteam.attack_catalog(attack_id),
    framework VARCHAR(100) NOT NULL, -- NIST-800-171-Rev2
    control_id VARCHAR(100) NOT NULL, -- 3.1.8
    description TEXT,
    UNIQUE(attack_id, framework, control_id)
);

-- === SCAN RESULTS (ATTACK LEVEL) ===
CREATE TABLE blueteam.scan_attacks (
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

CREATE INDEX idx_scan_attacks_scan ON blueteam.scan_attacks(scan_id);
CREATE INDEX idx_scan_attacks_attack ON blueteam.scan_attacks(attack_id);

-- === FINDINGS (VARIANT LEVEL) ===
CREATE TABLE blueteam.findings (
    id SERIAL PRIMARY KEY,
    scan_id INTEGER REFERENCES blueteam.scans(id) ON DELETE CASCADE,
    scan_attack_id INTEGER REFERENCES blueteam.scan_attacks(id) ON DELETE CASCADE,
    attack_id VARCHAR(255) NOT NULL,
    variant_id VARCHAR(255) NOT NULL,
    variant_name VARCHAR(255),
    status VARCHAR(20) NOT NULL, -- vulnerable, partial, defended, error
    severity VARCHAR(20) NOT NULL,
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
    priority VARCHAR(20),
    references TEXT[],

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    UNIQUE(scan_id, attack_id, variant_id)
);

CREATE INDEX idx_findings_scan ON blueteam.findings(scan_id);
CREATE INDEX idx_findings_attack ON blueteam.findings(attack_id);
CREATE INDEX idx_findings_status ON blueteam.findings(status);
CREATE INDEX idx_findings_severity ON blueteam.findings(severity);

-- === MITIGATION TRACKING ===
-- Links findings to mitigation projects
CREATE TABLE blueteam.mitigation_findings (
    id SERIAL PRIMARY KEY,
    finding_id INTEGER REFERENCES blueteam.findings(id) ON DELETE CASCADE,
    mitigation_issue_id INTEGER REFERENCES blueteam.mitigation_issues(id) ON DELETE CASCADE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(finding_id, mitigation_issue_id)
);

-- === SCAN COMPARISONS (HISTORY) ===
CREATE TABLE blueteam.scan_comparisons (
    id SERIAL PRIMARY KEY,
    baseline_scan_id INTEGER REFERENCES blueteam.scans(id),
    current_scan_id INTEGER REFERENCES blueteam.scans(id),
    new_vulnerabilities INTEGER DEFAULT 0,
    fixed_vulnerabilities INTEGER DEFAULT 0,
    regression_count INTEGER DEFAULT 0, -- fixed → vulnerable again
    improvement_count INTEGER DEFAULT 0, -- vulnerable → defended
    comparison_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(baseline_scan_id, current_scan_id)
);
```

---

## Key Improvements in Ideal Structure

### 1. **Complete Scan Context**
- Explicit `scan_id` for unique identification
- Target metadata (URL, name, environment, type)
- Execution metadata (mode, duration, operator)
- Configuration snapshot for reproducibility

### 2. **Attack Catalog Separation**
- Attack definitions stored separately from scan results
- Compliance mappings queryable
- Target type filtering possible
- Reusable across multiple scans

### 3. **Hierarchical Data Model**
- Scans → Attacks → Variants (proper parent-child)
- No redundant data in findings
- Easy rollup queries
- Preserves attack→variant relationship

### 4. **Structured Evidence**
- `evidence_summary`: Human-readable summary
- `evidence_details`: Technical explanation
- `evidence_proof`: Machine-readable JSONB data
- Clear separation of concerns

### 5. **Scan History & Comparison**
- Track scans over time
- Compare baseline vs. current
- Detect regressions automatically
- Trend analysis possible

### 6. **Proper Mitigation Linking**
- Many-to-many relationship (findings ↔ mitigation issues)
- Track which scan finding led to which mitigation work
- Re-scan verification links to original finding
- Historical tracking preserved

---

## Migration Path (Conceptual)

### Phase 1: Add Scan Metadata to Reports
1. Update `JsonReporter` to capture:
   - Target URL, name, environment
   - Scan ID (UUID or timestamp-based)
   - Execution metadata
   - Config snapshot
2. Update config.yaml to include target metadata
3. Maintain backward compatibility with flat `findings` array

### Phase 2: Add Attack Catalog
1. Create `attack_catalog` table
2. Add script to populate from Python attack modules
3. Add compliance mapping table
4. Link findings to catalog via `attack_id`

### Phase 3: Hierarchical Report Format
1. Update JSON reporter to nest variants under attacks
2. Add `variants` array to each attack
3. Keep flat `findings` array for backward compatibility
4. Phase out flat array in v2.0

### Phase 4: Scan History & Comparison
1. Add `scans` table
2. Import historical reports into scans table
3. Build comparison queries
4. Add regression detection to dashboard

### Phase 5: Deprecate Old Format
1. Remove flat `findings` array
2. Remove `mitigation_projects` in favor of `scans`
3. Migrate existing mitigation projects to scan-based model

---

## Benefits Summary

**For Operators:**
- Know exactly what was scanned and when
- Compare scan results over time
- Track improvement/regression trends
- Understand compliance mappings

**For Developers:**
- Clear attack→variant hierarchy
- No redundant data
- Easy to query and analyze
- Structured evidence for automation

**For Mitigation Teams:**
- Link findings to remediation work
- Verify fixes with re-scan
- Track historical context
- Prioritize based on trends

**For Compliance:**
- Map findings to framework controls
- Generate compliance reports
- Track control effectiveness
- Audit trail preserved

---

## Conclusion

The **ideal structure** is:

1. **Scan-centric**: Scans are first-class entities with full context
2. **Hierarchical**: Scan → Attack → Variant (not flat findings)
3. **Catalog-based**: Attack definitions separated from results
4. **Structured evidence**: Clear separation of human/machine data
5. **History-aware**: Comparison and trend tracking built-in
6. **Compliance-linked**: Framework mappings queryable
7. **Mitigation-integrated**: Findings link to remediation work

This structure eliminates all current problems while enabling:
- Automated regression testing
- Compliance reporting
- Trend analysis
- Historical tracking
- Better dashboards
- API-driven workflows

**Implementation complexity:** Moderate-to-high, but provides substantial long-term value.
