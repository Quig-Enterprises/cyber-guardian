# EQMON Blue Team — Defensive Security Monitoring System

## Design Document

**Date:** 2026-03-05
**Context:** NIST SP 800-171 Rev 2 / CMMC Level 2 compliance for NAVSEA/DoD maritime predictive maintenance platform handling CUI
**Companion:** Red team framework at `/opt/security-red-team/` (31 attack modules, 156 variants)

---

## 1. Problem Statement

EQMON (Apollo) is a bearing expert AI chat platform that processes Controlled Unclassified Information (CUI) for NAVSEA/DoD maritime predictive maintenance. CMMC Level 2 certification requires compliance with all 110 NIST SP 800-171 Rev 2 security requirements.

Current state analysis reveals **6 CMMC blockers** and multiple high-severity gaps:

| Gap | NIST Control | Status |
|-----|-------------|--------|
| No MFA | 3.5.3 | **Blocker** |
| No general API audit logging | 3.3.1, 3.3.2 | **Blocker** |
| No centralized/protected log store | 3.3.8 | **Blocker** |
| No encryption at rest for CUI | 3.13.16 | **Blocker** |
| No incident response capability | 3.6.1-3.6.3 | **Blocker** |
| No real-time security monitoring | 3.14.6 | **Blocker** |
| No compliance tracking/SSP | 3.12.1-3.12.4 | Required |
| JWT secret hardcoded in source | 3.13.10 | High |
| api/admin/settings.php unauthenticated | 3.1.1 | High |
| logApiAccess() is TODO stub | 3.3.1 | High |
| No audit log failure alerting | 3.3.4 | Medium |
| No session timeout enforcement | 3.1.10, 3.1.11 | Medium |

The red team framework tests offensive security. The blue team complements it with detection, monitoring, alerting, incident response, and compliance tracking — providing the defensive evidence CMMC assessors require.

---

## 2. Architecture: Hybrid PHP Audit Layer + Python Analysis Engine

### Design Decision

**Approach:** Thin PHP audit middleware in EQMON captures events at source → Python analysis engine at `/opt/security-blue-team/` reads, correlates, alerts, tracks compliance, and generates assessor-ready reports.

**Rationale:**
- Audit logging MUST happen where data originates (PHP) — can't miss events
- Analysis, correlation, ML, and reporting are Python strengths
- Clean separation: EQMON stays focused on its domain; blue team is independent
- Mirrors red team architecture for team familiarity
- Blue team engine can monitor multiple services (EQMON, Artemis, MQTT processor)

### System Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        EQMON PHP Application                        │
│                                                                     │
│  ┌─────────────────┐  ┌──────────────────┐  ┌──────────────────┐  │
│  │ AuditLogger.php │  │ middleware.php    │  │ Existing Auth    │  │
│  │ (NEW middleware) │  │ (add audit calls)│  │ (login/logout)   │  │
│  └────────┬────────┘  └────────┬─────────┘  └────────┬─────────┘  │
│           │                    │                      │             │
│           └────────────────────┴──────────────────────┘             │
│                                │                                    │
│                    PostgreSQL: audit_events table                    │
└────────────────────────────────┬────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────────┐
│                  Blue Team Engine (Python)                           │
│                  /opt/security-blue-team/                            │
│                                                                     │
│  ┌──────────────┐  ┌──────────────┐  ┌─────────────────────────┐  │
│  │  Collectors   │  │  Correlator   │  │  Alert Engine            │  │
│  │  - DB reader  │  │  - Rule-based │  │  - Email notifications   │  │
│  │  - Syslog     │  │  - Pattern    │  │  - Syslog forwarding     │  │
│  │  - Nginx logs │  │    matching   │  │  - Severity thresholds   │  │
│  │  - Red team   │  │  - Anomaly    │  │  - Escalation rules      │  │
│  │    reports    │  │    detection  │  │  - Audit failure alerts   │  │
│  └──────┬───────┘  └──────┬───────┘  └───────────┬─────────────┘  │
│         │                  │                       │                 │
│  ┌──────┴──────────────────┴───────────────────────┴─────────────┐  │
│  │                    PostgreSQL: blueteam schema                  │  │
│  │  security_incidents | compliance_controls | alert_rules        │  │
│  │  incident_evidence  | compliance_evidence | alert_history      │  │
│  │  poam_items         | ssp_sections        | posture_scores     │  │
│  └────────────────────────────────────────────────────────────────┘  │
│                                                                     │
│  ┌──────────────────┐  ┌──────────────────┐  ┌─────────────────┐  │
│  │ Compliance        │  │ Incident Manager  │  │ CLI / Reports   │  │
│  │ Tracker           │  │ - PICERL workflow │  │ - Assessor PDF  │  │
│  │ - 110 controls    │  │ - 72-hr DFARS    │  │ - SSP export    │  │
│  │ - Evidence links  │  │ - Forensic chain │  │ - POA&M export  │  │
│  │ - SSP generation  │  │ - Tabletop tests │  │ - Posture score │  │
│  │ - POA&M tracking  │  │                  │  │ - Red/blue dash │  │
│  └──────────────────┘  └──────────────────┘  └─────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 3. Component Specifications

### 3.1 PHP Audit Layer (in EQMON)

**File: `/var/www/html/eqmon/lib/AuditLogger.php`**

Thin middleware class (~200 lines) that logs structured events to PostgreSQL.

```php
class AuditLogger {
    // Event categories matching NIST control families
    const CAT_AUTH = 'auth';           // 3.3.1, 3.5.x
    const CAT_ACCESS = 'access';       // 3.1.x, 3.3.2
    const CAT_ADMIN = 'admin';         // 3.1.7, 3.3.2
    const CAT_DATA = 'data';           // 3.1.3 (CUI flow)
    const CAT_AI = 'ai';              // AI-specific events
    const CAT_SYSTEM = 'system';       // 3.14.x

    public static function log(
        string $category,
        string $action,
        string $result,      // 'success' | 'failure' | 'denied'
        ?string $userId,
        array $metadata = [],
        bool $cuiAccessed = false
    ): void;
}
```

**Database table: `audit_events`**

| Column | Type | Purpose | NIST |
|--------|------|---------|------|
| event_id | uuid PK | Unique event identifier | 3.3.1 |
| timestamp | timestamptz | UTC timestamp (NTP-synced) | 3.3.7 |
| category | text | auth/access/admin/data/ai/system | 3.3.1 |
| action | text | login, view_bearing, export_data, etc. | 3.3.1 |
| result | text | success/failure/denied | 3.3.1 |
| user_id | uuid FK | Who performed the action | 3.3.2 |
| session_id | text | JWT session identifier | 3.3.2 |
| ip_address | inet | Source IP | 3.3.1 |
| user_agent | text | Browser/client identifier | 3.3.1 |
| resource_type | text | API endpoint, page, file | 3.3.1 |
| resource_id | text | Specific resource accessed | 3.3.1 |
| instance_id | uuid | Tenant context | 3.1.3 |
| cui_accessed | boolean | Whether CUI was involved | 3.1.3 |
| metadata | jsonb | Additional context | 3.3.1 |
| created_at | timestamptz | Write timestamp | 3.3.1 |

**Index:** `(timestamp, category)`, `(user_id, timestamp)`, `(ip_address, timestamp)`

**Events to capture:**

| Category | Events | NIST |
|----------|--------|------|
| auth | login, logout, login_failed, password_change, password_reset, mfa_challenge, impersonation_start, impersonation_end | 3.3.1, 3.5.x |
| access | api_request (all endpoints), page_view, data_query, file_download, file_upload | 3.3.1, 3.3.2 |
| admin | user_create, user_delete, user_deactivate, role_change, settings_change, affiliation_change | 3.1.7, 3.3.2 |
| data | bearing_view, chat_message, chat_response, export_data, report_generate | 3.1.3 |
| ai | chat_request, chat_response_filtered, guardrail_triggered, jailbreak_detected | 3.14.6 |
| system | rate_limit_hit, validation_failure, error_500, session_expired, audit_failure | 3.3.4, 3.14.1 |

**Integration points in EQMON:**
- `middleware.php` — add `AuditLogger::log()` call in `requireApiAuth()` (covers all authenticated API calls)
- `login.php` — replace inline `logLoginAttempt()` with `AuditLogger::log('auth', ...)`
- `forgot-password.php`, `reset-password.php` — add audit calls
- `api/admin/users.php` — audit user CRUD
- `api/ai_chat.php` — audit AI interactions and guardrail triggers
- `api/stream.php` — audit SSE connections
- Admin pages — audit via admin-header.php

### 3.2 Python Blue Team Engine

**Location:** `/opt/security-blue-team/`

**Tech stack:** Python 3.13, PostgreSQL (psycopg2), same venv pattern as red team

#### 3.2.1 Collectors (`blueteam/collectors/`)

| Collector | Source | What It Reads |
|-----------|--------|---------------|
| `db_audit.py` | PostgreSQL audit_events | New events since last poll (5-sec interval) |
| `syslog_parser.py` | /var/log/syslog | Auth facility events (LOG_AUTH) |
| `nginx_log.py` | /var/log/nginx/access.log | HTTP requests, status codes, response times |
| `php_error.py` | /var/www/html/eqmon/logs/ | PHP errors, exceptions, fatals |
| `redteam_report.py` | /opt/security-red-team/reports/ | Red team results for posture scoring |

Each collector normalizes events into a common `SecurityEvent` dataclass:

```python
@dataclass
class SecurityEvent:
    timestamp: datetime
    source: str          # 'audit_db', 'syslog', 'nginx', 'php_error', 'redteam'
    category: str        # auth, access, admin, data, ai, system, network
    severity: str        # critical, high, medium, low, info
    action: str
    user_id: Optional[str]
    ip_address: Optional[str]
    details: dict
    nist_controls: list[str]   # e.g., ['3.3.1', '3.5.2']
    cui_involved: bool
```

#### 3.2.2 Correlator (`blueteam/correlator/`)

Rule-based event correlation engine. Each rule is a Python class:

```python
class CorrelationRule(ABC):
    name: str
    description: str
    nist_controls: list[str]
    severity: str

    @abstractmethod
    def evaluate(self, events: list[SecurityEvent], window: timedelta) -> Optional[SecurityIncident]:
        ...
```

**Built-in rules:**

| Rule | Detection | NIST | Severity |
|------|-----------|------|----------|
| `BruteForceDetection` | >5 failed logins from same IP in 5 min | 3.1.8, 3.14.6 | High |
| `CredentialStuffing` | >10 failed logins to different accounts from same IP | 3.1.8, 3.14.6 | Critical |
| `PrivilegeEscalation` | Non-admin user accessing admin endpoints | 3.1.7, 3.14.7 | Critical |
| `AnomalousAccess` | Access from new IP/UA for existing user | 3.14.7 | Medium |
| `DataExfiltration` | Unusual volume of data exports/downloads | 3.1.3, 3.14.6 | High |
| `AIAbusePattern` | Repeated guardrail triggers from same user | 3.14.6 | High |
| `AfterHoursAccess` | CUI access outside business hours | 3.14.7 | Medium |
| `AccountTakeover` | Password change + immediate data access from new IP | 3.5.x, 3.14.6 | Critical |
| `SessionAnomaly` | Multiple concurrent sessions or session replay | 3.13.15 | High |
| `AuditLogGap` | Missing expected audit events (logging failure) | 3.3.4 | Critical |
| `RateLimitSurge` | >50 rate limit hits in 1 minute | 3.14.6 | Medium |
| `CrossTenantAccess` | User accessing data outside their opco/vessel | 3.1.3 | Critical |

#### 3.2.3 Alert Engine (`blueteam/alerting/`)

Multi-channel alerting with severity-based routing:

| Severity | Channels | Response Time |
|----------|----------|---------------|
| Critical | Email + syslog + console | Immediate |
| High | Email + syslog | 15 minutes |
| Medium | Syslog + daily digest | 1 hour |
| Low | Daily digest only | 24 hours |
| Info | Log only | N/A |

**Alert destinations:**
- `EmailAlerter` — SMTP via EqmonMailer (reuse existing config)
- `SyslogAlerter` — LOG_SECURITY facility
- `ConsoleAlerter` — stdout for daemon mode
- `WebhookAlerter` — extensible for Slack/Teams/PagerDuty

**Audit failure alerting (3.3.4):**
- Dedicated monitor checks audit_events table for gaps
- If no events received for >5 minutes during business hours → Critical alert
- If PHP error log shows AuditLogger exceptions → Critical alert
- Named personnel list in config

#### 3.2.4 Compliance Tracker (`blueteam/compliance/`)

Maps all 110 NIST SP 800-171 Rev 2 controls to implementation status and evidence.

**Database: `compliance_controls`**

| Column | Type | Purpose |
|--------|------|---------|
| control_id | text PK | e.g., '3.3.1' |
| family | text | e.g., 'Audit and Accountability' |
| requirement | text | Full requirement text |
| status | text | implemented / partially / planned / not_applicable |
| implementation_notes | text | How it's implemented |
| evidence_type | text | automated / manual / hybrid |
| last_assessed | timestamptz | When last verified |
| assessor_notes | text | For C3PAO assessor |

**Database: `compliance_evidence`**

| Column | Type | Purpose |
|--------|------|---------|
| evidence_id | uuid PK | Unique ID |
| control_id | text FK | Which control |
| evidence_type | text | log_sample, config_screenshot, test_result, policy_doc |
| description | text | What this proves |
| file_path | text | Path to evidence artifact |
| collected_at | timestamptz | When collected |
| automated | boolean | Collected automatically? |

**Automated evidence collection:**
- 3.3.1: Sample audit log entries showing required fields
- 3.3.2: Sample showing user traceability (user_id → action chain)
- 3.3.7: NTP sync status check
- 3.3.8: Audit table permission verification
- 3.1.8: Account lockout configuration + sample lockout events
- 3.5.10: Password hash algorithm verification (ARGON2ID)
- 3.13.8: TLS configuration check
- 3.14.6: Sample correlation alerts

**SSP (System Security Plan) generation:**
- Template following NIST SP 800-171A assessment format
- Auto-populated with system boundary description, control implementations, evidence references
- Exportable as markdown, PDF, or OSCAL JSON

**POA&M (Plan of Action & Milestones):**
- Track unimplemented/partial controls with target dates
- Auto-generate from compliance gap analysis
- Link to specific remediation tasks

#### 3.2.5 Incident Manager (`blueteam/incidents/`)

Full PICERL lifecycle tracking:

**Database: `security_incidents`**

| Column | Type | Purpose |
|--------|------|---------|
| incident_id | uuid PK | Unique ID |
| title | text | Brief description |
| severity | text | critical/high/medium/low |
| status | text | detected/analyzing/contained/eradicated/recovered/closed |
| detected_at | timestamptz | When first detected |
| detected_by | text | correlation_rule / manual / redteam |
| assigned_to | text | Responder |
| nist_controls | text[] | Related controls |
| cui_involved | boolean | CUI breach? |
| dfars_reportable | boolean | Requires 72-hr DFARS reporting? |
| dfars_reported_at | timestamptz | When reported to DC3 |
| closed_at | timestamptz | Resolution time |
| root_cause | text | Post-mortem |
| lessons_learned | text | Improvements |

**Database: `incident_evidence`**

| Column | Type | Purpose |
|--------|------|---------|
| evidence_id | uuid PK | Unique ID |
| incident_id | uuid FK | Parent incident |
| evidence_type | text | log_excerpt, screenshot, pcap, config, timeline |
| description | text | What this shows |
| content | text | Actual evidence content |
| collected_at | timestamptz | When collected |
| collected_by | text | Who collected |
| hash_sha256 | text | Integrity verification |

**DFARS 252.204-7012 reporting workflow:**
1. Incident detected → auto-classify if CUI involved
2. If CUI breach → flag dfars_reportable, start 72-hour timer
3. Generate DC3 report template with required fields
4. Track submission and follow-up

**Tabletop exercise framework (3.6.3):**
- Pre-built scenarios based on red team attack categories
- Exercise template with roles, injects, expected responses
- Post-exercise scoring and improvement tracking

#### 3.2.6 CLI Interface (`blueteam/cli.py`)

```bash
# Monitoring
blueteam monitor              # Start real-time monitoring daemon
blueteam status               # Current security posture summary

# Compliance
blueteam compliance status    # Show all 110 controls with status
blueteam compliance gaps      # Show only unimplemented/partial controls
blueteam compliance evidence  # Collect automated evidence
blueteam compliance ssp       # Generate System Security Plan
blueteam compliance poam      # Generate POA&M

# Incidents
blueteam incidents list       # Active incidents
blueteam incidents create     # Manual incident creation
blueteam incidents update ID  # Update incident status
blueteam incidents report ID  # Generate incident report

# Alerts
blueteam alerts list          # Recent alerts
blueteam alerts rules         # Show correlation rules
blueteam alerts test          # Test alert delivery

# Reports
blueteam report posture       # Overall security posture
blueteam report assessor      # Assessor-ready compliance report
blueteam report executive     # Executive summary
blueteam report redblue       # Combined red/blue team results

# Integration
blueteam redteam import       # Import latest red team results
blueteam redteam compare      # Compare posture over time
```

---

## 4. NIST Control Coverage Matrix

### Controls Fully Addressed by Blue Team

| Control | Requirement | Blue Team Component |
|---------|-------------|-------------------|
| 3.3.1 | Create/retain audit logs | AuditLogger + DB storage |
| 3.3.2 | User action traceability | AuditLogger (user_id on every event) |
| 3.3.3 | Review/update logged events | Compliance tracker + event review workflow |
| 3.3.4 | Audit failure alerting | Alert engine (AuditLogGap rule) |
| 3.3.5 | Correlate audit records | Correlator (12 built-in rules) |
| 3.3.6 | Audit reduction/reporting | CLI reports + dashboard |
| 3.3.7 | Authoritative time source | AuditLogger uses UTC timestamps + NTP check |
| 3.3.8 | Protect audit information | Separate DB role, append-only design |
| 3.3.9 | Limit audit management | Separate privileged role for audit access |
| 3.6.1 | Incident handling capability | Incident manager (PICERL) |
| 3.6.2 | Track/report incidents | Incident DB + DFARS reporting |
| 3.6.3 | Test IR capability | Tabletop exercise framework |
| 3.12.1 | Assess security controls | Compliance tracker (110 controls) |
| 3.12.2 | POA&M for deficiencies | POA&M tracking |
| 3.12.3 | Monitor controls ongoing | Automated evidence collection |
| 3.12.4 | System security plan | SSP generation |
| 3.14.3 | Security alert response | Alert engine + advisory tracking |
| 3.14.6 | Monitor for attacks | Correlator + collectors |
| 3.14.7 | Identify unauthorized use | Correlator rules (AfterHours, CrossTenant, etc.) |

### Controls Partially Addressed (Blue Team + EQMON Changes Needed)

| Control | Gap | Required Change |
|---------|-----|-----------------|
| 3.1.7 | Privileged function audit logging | AuditLogger captures admin actions |
| 3.1.8 | Unsuccessful logon limits | Already exists (RateLimiter) — blue team monitors it |
| 3.5.3 | MFA for all network access | **EQMON must implement MFA** — blue team tracks compliance |
| 3.13.16 | Encryption at rest | **EQMON/PostgreSQL must enable pgcrypto or TDE** — blue team verifies |
| 3.1.10 | Session lock | **EQMON must implement inactivity timeout** — blue team monitors |

### Controls Out of Scope (Not Software — Policy/Physical/Network)

| Control | Why Out of Scope |
|---------|-----------------|
| 3.2.x | Awareness/training — organizational policy |
| 3.7.x | Maintenance — physical/operational |
| 3.8.x | Media protection — physical controls |
| 3.9.x | Personnel security — HR policy |
| 3.10.x | Physical protection — facility controls |
| 3.13.5 | DMZ/network segmentation — network infrastructure |
| 3.13.6 | Default deny firewall — network infrastructure |
| 3.13.7 | Split tunneling — VPN/endpoint config |

---

## 5. Red Team Additions

CMMC gap analysis identified 10 new attack modules for the red team:

| Module | Target | NIST Control | Priority |
|--------|--------|-------------|----------|
| `compliance.mfa_absence` | Verify no MFA challenge on login | 3.5.3 | Critical |
| `api.unauth_admin_settings` | settings.php has ZERO authentication | 3.1.1 | Critical |
| `api.jwt_secret_extraction` | Hardcoded secret in source code | 3.13.10 | Critical |
| `compliance.encryption_at_rest` | Test if DB CUI is encrypted | 3.13.16 | High |
| `api.session_timeout` | JWT valid for 24h, no inactivity lock | 3.1.10, 3.1.11 | High |
| `api.privilege_escalation_v2` | Non-privileged → admin function execution | 3.1.7 | High |
| `api.password_policy` | Test reuse, complexity, history enforcement | 3.5.7, 3.5.8 | Medium |
| `compliance.audit_log_tamper` | Can attacker modify/delete audit logs? | 3.3.8 | Medium |
| `api.account_lockout_bypass` | Rate limiter edge cases and reset timing | 3.1.8 | Medium |
| `compliance.cui_data_flow` | CUI leaking to unauthorized locations | 3.1.3 | Medium |

---

## 6. Database Schema

All blue team tables live in the `eqmon` database under a `blueteam` schema to maintain separation while sharing the PostgreSQL instance.

```sql
CREATE SCHEMA IF NOT EXISTS blueteam;

-- Core audit table (written by PHP AuditLogger)
-- Lives in public schema for PHP access simplicity
CREATE TABLE audit_events (
    event_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    category TEXT NOT NULL,
    action TEXT NOT NULL,
    result TEXT NOT NULL CHECK (result IN ('success', 'failure', 'denied')),
    user_id UUID,
    session_id TEXT,
    ip_address INET,
    user_agent TEXT,
    resource_type TEXT,
    resource_id TEXT,
    instance_id UUID,
    cui_accessed BOOLEAN DEFAULT FALSE,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_audit_events_timestamp ON audit_events (timestamp DESC);
CREATE INDEX idx_audit_events_user ON audit_events (user_id, timestamp DESC);
CREATE INDEX idx_audit_events_ip ON audit_events (ip_address, timestamp DESC);
CREATE INDEX idx_audit_events_category ON audit_events (category, timestamp DESC);
CREATE INDEX idx_audit_events_cui ON audit_events (timestamp DESC) WHERE cui_accessed = TRUE;

-- Blue team schema tables
CREATE TABLE blueteam.security_incidents (...);
CREATE TABLE blueteam.incident_evidence (...);
CREATE TABLE blueteam.compliance_controls (...);
CREATE TABLE blueteam.compliance_evidence (...);
CREATE TABLE blueteam.poam_items (...);
CREATE TABLE blueteam.alert_rules (...);
CREATE TABLE blueteam.alert_history (...);
CREATE TABLE blueteam.posture_scores (...);
```

---

## 7. Implementation Phases

### Phase 1: Audit Foundation (PHP + DB)
- Create `audit_events` table migration
- Implement `AuditLogger.php` (~200 lines)
- Integrate into `middleware.php`, `login.php`, `forgot-password.php`, `reset-password.php`
- Integrate into `api/admin/users.php`, `api/ai_chat.php`
- **Fix critical bugs:** auth on settings.php, JWT secret to .env
- Verify audit events flowing

### Phase 2: Blue Team Scaffolding (Python)
- Project scaffolding at `/opt/security-blue-team/`
- `SecurityEvent` dataclass and collector base class
- `db_audit.py` collector (reads audit_events)
- `syslog_parser.py` collector
- Basic CLI framework
- Database migrations for blueteam schema

### Phase 3: Correlation & Alerting
- Correlation rule base class
- Implement 12 built-in correlation rules
- Alert engine with email + syslog channels
- `blueteam monitor` daemon command
- `blueteam alerts` CLI commands

### Phase 4: Compliance Tracker
- Load all 110 NIST SP 800-171r2 controls into DB
- Automated evidence collectors
- SSP template and generator
- POA&M tracking
- `blueteam compliance` CLI commands

### Phase 5: Incident Management
- Incident PICERL lifecycle tracking
- Evidence chain with SHA-256 integrity
- DFARS 72-hour reporting workflow
- Tabletop exercise templates
- `blueteam incidents` CLI commands

### Phase 6: Reporting & Red Team Integration
- Import red team results
- Combined posture scoring
- Assessor-ready PDF/markdown reports
- Executive summary generation
- Historical trend tracking

---

## 8. Security of the Blue Team System Itself

Per CMMC scoping guidance, the blue team monitoring system is a **Security Protection Asset (SPA)** and its data is **Security Protection Data (SPD)**. Therefore:

| Requirement | Implementation |
|-------------|---------------|
| 3.3.8 — Protect audit info | Separate PostgreSQL role `blueteam_reader` (read-only for analysis), `eqmon_audit_writer` (append-only for PHP) |
| 3.3.9 — Limit audit management | Only `blueteam_admin` role can modify/delete audit data; separate from eqmon app role |
| 3.1.1 — Authorized access | Blue team CLI requires local system authentication |
| 3.13.8 — Encrypt in transit | PostgreSQL SSL connections |
| 3.13.16 — Encrypt at rest | Follow same encryption-at-rest strategy as EQMON CUI data |

---

## 9. Success Criteria

1. **Every API call and auth event** generates an audit record with user traceability
2. **12 correlation rules** detect attack patterns in real time
3. **All 110 NIST controls** tracked with status and evidence
4. **SSP and POA&M** auto-generated from compliance data
5. **Incidents tracked** through full PICERL lifecycle
6. **DFARS 72-hour** reporting workflow operational
7. **Red team results** integrated into posture scoring
8. **Assessor-ready reports** exportable on demand
9. **10 new red team modules** added for CMMC gap coverage
