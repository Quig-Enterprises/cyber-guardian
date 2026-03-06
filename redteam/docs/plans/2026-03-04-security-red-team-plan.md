# Security Red Team - Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build an automated security testing framework that runs categorized attack batteries against the EQMON AI chat system, scores vulnerabilities by severity, and generates reports.

**Architecture:** Modular Python framework with pluggable attack modules (ai/api/web), pytest integration, async HTTP client with SSE support, and HTML/JSON/console reporting. Phase 2 AI-powered attack stubs pre-wired.

**Tech Stack:** Python 3.11+, aiohttp, pytest, pytest-asyncio, PyJWT, psycopg2, Rich, Jinja2

**Project Location:** `/opt/security-red-team/`

---

## Dependency Graph

```
01-scaffolding
  └─> 02-core-abstractions
       └─> 03-http-client
            └─> 04-registry-runner
       └─> 05-evaluators
  └─> 06-reporters (depends on 02)
  └─> 10-test-users-cleanup (independent, can parallel with 02-06)
04 + 05 + 06 ready:
  └─> 07-ai-attacks
  └─> 08-api-attacks
  └─> 09-web-attacks
All attacks done:
  └─> 11-pytest-integration
  └─> 12-phase2-stubs
```

---

## Task Index

| # | Task File | Description | Depends On | Est. Steps |
|---|-----------|-------------|------------|------------|
| 01 | tasks/01-scaffolding.md | Project setup, pyproject.toml, dirs, git | None | 5 |
| 02 | tasks/02-core-abstractions.md | Base Attack, AttackResult, Score, Severity | 01 | 8 |
| 03 | tasks/03-http-client.md | Auth client, SSE parser, request logging | 02 | 10 |
| 04 | tasks/04-registry-runner.md | Attack discovery, CLI runner, orchestration | 03 | 10 |
| 05 | tasks/05-evaluators.md | Keyword, behavior, leakage evaluators | 02 | 8 |
| 06 | tasks/06-reporters.md | Console, JSON, HTML report generators | 02 | 10 |
| 07 | tasks/07-ai-attacks.md | Jailbreak, injection, extraction, off-topic, leakage, hallucination, manipulation | 04, 05 | 20 |
| 08 | tasks/08-api-attacks.md | Auth bypass, IDOR, authz boundaries, SQL injection, input validation, rate limiting, error leakage | 04, 05 | 18 |
| 09 | tasks/09-web-attacks.md | XSS, CSRF, CORS, session security | 04, 05 | 12 |
| 10 | tasks/10-test-users-cleanup.md | Create test users in DB, cleanup scripts | 01 | 6 |
| 11 | tasks/11-pytest-integration.md | pytest wrappers, conftest, fixtures | 07, 08, 09 | 8 |
| 12 | tasks/12-phase2-stubs.md | AI-powered attack base, AI judge evaluator | 02 | 4 |

---

## Target System Summary

- **Base URL:** `http://localhost:8081/eqmon`
- **AI Chat:** `/api/ai_chat.php` (general + analysis modes, SSE streaming)
- **Auth:** JWT in httpOnly cookie via `/api/auth/login.php`
- **DB:** PostgreSQL `eqmon` on localhost
- **Model:** Ollama qwq:32b
- **Known weaknesses:** No input filtering, no rate limiting, CORS `*`, error leakage, no jailbreak defenses

---

## Quick Start

Once built, run the framework as follows:

```bash
cd /opt/security-red-team
python -m venv venv && source venv/bin/activate
pip install -e .
python runner.py --all --report html
```

---

*Each task file in `tasks/` contains full implementation details, file lists, and step-by-step instructions.*
