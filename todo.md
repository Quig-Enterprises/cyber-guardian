# Cyber Guardian Red Team Scanner — Improvement TODO

*Generated from scan session 2026-03-07/08*
*Updated 2026-03-08 — all items implemented*

## HIGH: Session Resilience

### 1. Handle account deactivation mid-scan
- **Status:** DONE
- **Changes:** Added `_check_auth_response()` to client.py that detects 401/403 with auth keywords and redirects to login. Called after every `get()`/`post()`/`delete()`. On failure: stores credentials from login, calls `reauth()` once, retries request.
- **Files:** `redteam/client.py`

### 2. Distinguish login failure reasons
- **Status:** DONE
- **Changes:** Added `LoginResult` enum with 6 values (SUCCESS, WRONG_CREDENTIALS, ACCOUNT_LOCKED, RATE_LIMITED, ACCOUNT_INACTIVE, NETWORK_ERROR). `login()` now returns `LoginResult` instead of `bool`. Runner handles graceful fallback (already did from v7421436, now uses enum).
- **Files:** `redteam/client.py`, `redteam/runner.py`

### 3. Pre-scan account health check (--preflight)
- **Status:** DONE
- **Changes:** Added `--preflight` CLI flag. Tests connectivity (GET /), authentication (login with LoginResult), session verification, and JWT token expiry check. Can run standalone or before a full scan.
- **Files:** `redteam/runner.py`

## HIGH: False Positive Reduction

### 4. Improve hardcoded credential detection (2-pass)
- **Status:** DONE
- **Changes:** Added 2-pass analysis per file. Pass 1 builds `env_sourced_vars` set by scanning for `os.environ.get()`, `os.environ[]`, `os.getenv()` assignments. Pass 2 skips credential matches that reference env-sourced variables. Also fixed 50-finding cap bug — removed nested breaks, scan runs to completion, truncates at 200 for reporting.
- **Files:** `redteam/attacks/compliance/pci_auth_controls.py`

### 5. IDOR test seeding
- **Status:** DONE
- **Changes:** Added `_setup_other_user_note()` that logs in as viewer user via fresh aiohttp session and creates a real test note. Uses real note ID for variant 4 (delete_other_user_note), falls back to 999999. Improved classification: parses JSON `success` field, 404 = DEFENDED, 200+success=false = DEFENDED. Cleanup removes created note.
- **Files:** `redteam/attacks/api/idor.py`

### 6. Dead code cleanup
- **Status:** DONE
- **Changes:** Removed unused `SELF_SCAN_DIRS` constant and its comment. `SKIP_PATTERNS` already includes "cyber-guardian".
- **Files:** `redteam/attacks/compliance/pci_auth_controls.py`

## MEDIUM: FQDN / Multi-Target Support

### 7. FQDN-aware scanning
- **Status:** DONE
- **Changes:** Added `--fqdn` CLI flag and `target.fqdn` config field. DNS modules (dnssec, email_auth, subdomain_takeover) and certificate module updated to prefer `target.fqdn` over parsing `base_url`. Web/API attacks still use `base_url`.
- **Files:** `redteam/runner.py`, `redteam/attacks/dns/dnssec.py`, `redteam/attacks/dns/email_auth.py`, `redteam/attacks/dns/subdomain_takeover.py`, `redteam/attacks/web/certificate.py`

### 8. Origin-IP auth flow
- **Status:** ADDRESSED (v7421436)
- **What changed:** `client.py` handles `origin_ip` with URL rewriting and Host header. SSL verification now configurable (item #10).

## MEDIUM: Scan Quality

### 9. Session expiry detection
- **Status:** DONE
- **Changes:** Added `_parse_jwt_expiry()` that decodes JWT payload to extract `exp` claim. `session_expires_soon(threshold_seconds=300)` checks if token expires within threshold. Expiry parsed automatically after login. Preflight check reports token status.
- **Files:** `redteam/client.py`

### 10. SSL verification option
- **Status:** DONE
- **Changes:** Added `verify_ssl` parameter to `RedTeamClient.__init__()` (default True). When `origin_ip` is set, forced to False. `--no-verify-ssl` CLI flag added. Connector uses `ssl=None` (system default) when verify_ssl=True, `ssl=False` when disabled.
- **Files:** `redteam/client.py`, `redteam/runner.py`

### 11. Per-module credential override
- **Status:** DONE
- **Changes:** App/AI target auth now checks `REDTEAM_SYSADMIN_USER` / `REDTEAM_SYSADMIN_PASS` env vars with priority over config values, matching WordPress `WP_ADMIN_USER`/`WP_ADMIN_PASS` pattern.
- **Files:** `redteam/runner.py`

## LOW: Reporting

### 12. Differentiate NOT_ASSESSED from DEFENDED
- **Status:** DONE
- **Changes:** Added `NOT_ASSESSED` to `Status` enum. Added `skipped` and `not_assessed` counters to `Score` dataclass. `pass_rate` now excludes skipped/not_assessed from denominator. `aggregate_scores()` tracks totals. Added cyan color for NOT_ASSESSED in console output.
- **Files:** `redteam/base.py`, `redteam/scoring.py`

### 13. Before/after comparison reports
- **Status:** DONE
- **Changes:** Added `--compare previous-report.json` flag. `_compare_reports()` extracts findings from both reports and categorizes as new/resolved/regressed/unchanged. Saves `comparison-{timestamp}.json` report. Logs summary to console.
- **Files:** `redteam/runner.py`

---

## New in v7421436 (not previously tracked)

### Compliance bridge module (DONE)
- 1170-line `redteam/compliance_bridge.py` with ~65 attack-to-control mappings
- `--compliance` and `--compliance-framework` CLI flags

### Heartbeat logging for long attacks (DONE)
- `_heartbeat()` async function logs "still running" every 30s

### Client timeout parameter (DONE)
- `RedTeamClient` accepts `timeout` parameter (default 30s for runner)

### test.com → example.com domain fix (DONE)
- All attack modules use RFC 2606 `example.com`

### Graceful unauthenticated fallback (DONE)
- All target types warn and continue unauthenticated instead of hard-exiting
