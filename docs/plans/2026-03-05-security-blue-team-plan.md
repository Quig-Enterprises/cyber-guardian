# Security Blue Team - Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a defensive security monitoring system that provides NIST SP 800-171 / CMMC Level 2 compliance evidence through centralized audit logging, real-time event correlation, automated alerting, incident management, and compliance tracking for the EQMON AI chat platform handling CUI.

**Architecture:** Hybrid PHP audit middleware (in EQMON) + standalone Python analysis engine. PHP layer captures events at source; Python engine correlates, alerts, tracks compliance, and generates assessor-ready reports. Complements the red team framework at `/opt/security-red-team/`.

**Tech Stack:** PHP 8.4 (audit middleware), Python 3.13, PostgreSQL 17, psycopg2, Rich, Jinja2, click

**Blue Team Location:** `/opt/security-blue-team/`
**EQMON Location:** `/var/www/html/eqmon/`

---

## Dependency Graph

```
Phase 1 — Audit Foundation (PHP side):
  bt-01-critical-fixes
    └─> bt-02-audit-migration
         └─> bt-03-audit-logger-php
              └─> bt-04-audit-integration

Phase 2 — Blue Team Engine (Python side):
  bt-05-scaffolding (can start parallel with Phase 1)
    └─> bt-06-collectors
         └─> bt-07-correlator
              └─> bt-08-alerting
                   └─> bt-09-monitor-daemon

Phase 3 — Compliance & Incidents:
  bt-05 ready:
    └─> bt-10-compliance-tracker (can parallel with bt-07+)
    └─> bt-11-incident-manager (can parallel with bt-07+)

Phase 4 — Reporting & Integration:
  All above done:
    └─> bt-12-reports-integration

Phase 5 — New Red Team Modules:
  bt-01 done (fixes inform attack targets):
    └─> bt-13-new-redteam-modules (can parallel with Phase 2+)
```

---

## Task Index

| # | Task File | Description | Depends On | Est. Steps |
|---|-----------|-------------|------------|------------|
| 01 | tasks/bt-01-critical-fixes.md | Fix settings.php auth, JWT secret to .env | None | 6 |
| 02 | tasks/bt-02-audit-migration.md | Create audit_events table + blueteam schema | 01 | 5 |
| 03 | tasks/bt-03-audit-logger-php.md | AuditLogger.php class implementation | 02 | 8 |
| 04 | tasks/bt-04-audit-integration.md | Integrate AuditLogger into all EQMON endpoints | 03 | 12 |
| 05 | tasks/bt-05-scaffolding.md | Python project setup, pyproject.toml, dirs | None | 5 |
| 06 | tasks/bt-06-collectors.md | SecurityEvent dataclass, DB/syslog/nginx collectors | 05 | 10 |
| 07 | tasks/bt-07-correlator.md | Rule engine + 12 built-in correlation rules | 06 | 14 |
| 08 | tasks/bt-08-alerting.md | Alert engine with email, syslog, webhook channels | 07 | 8 |
| 09 | tasks/bt-09-monitor-daemon.md | Real-time monitoring daemon + CLI commands | 08 | 8 |
| 10 | tasks/bt-10-compliance-tracker.md | 110 NIST controls, evidence collection, SSP, POA&M | 05 | 14 |
| 11 | tasks/bt-11-incident-manager.md | PICERL lifecycle, DFARS reporting, evidence chain | 05 | 10 |
| 12 | tasks/bt-12-reports-integration.md | Red team import, posture scoring, assessor reports | 09, 10, 11 | 10 |
| 13 | tasks/bt-13-new-redteam-modules.md | 10 new CMMC-gap attack modules for red team | 01 | 16 |

---

## Target System Summary

- **Base URL:** `http://localhost:8081/eqmon`
- **AI Chat:** `/api/ai_chat.php` (general + analysis modes, SSE streaming)
- **Auth:** JWT in httpOnly cookie via `/api/auth/login.php` (dual-source: Artemis Admin + EQMON DB)
- **DB:** PostgreSQL `eqmon` on localhost
- **Model:** Ollama qwq:32b (temperature 0.4, 4096 max tokens)
- **Existing Security:** RateLimiter (token bucket), InputValidator, ResponseGuardrail (AI output), 5-tier RBAC, ARGON2ID passwords, nginx security headers
- **Known Gaps:** No MFA, no API audit logging, no encryption at rest, no SIEM, hardcoded JWT secret, unauthenticated settings endpoint

---

## Quick Start

Once built, use the blue team as follows:

```bash
# Start monitoring
cd /opt/security-blue-team
source venv/bin/activate
blueteam monitor

# Check compliance
blueteam compliance status
blueteam compliance gaps

# Generate assessor report
blueteam report assessor --output /tmp/cmmc-report.md

# Manage incidents
blueteam incidents list
blueteam incidents create --title "Brute force detected" --severity high

# Import red team results
blueteam redteam import /opt/security-red-team/reports/latest.json
blueteam report posture
```

---

*Each task file in `tasks/` contains full implementation details, file lists, and step-by-step instructions.*
