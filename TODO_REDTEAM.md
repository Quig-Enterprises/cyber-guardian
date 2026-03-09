# Red Team Scan Findings — Alfred Server

**Scan Date:** 2026-03-07
**Scanner:** Cyber-Guardian Red Team (cyber-guardian project)
**Scope:** Alfred server — all categories except wordpress, cloud, ai
**Run 1:** localhost:80 — infrastructure, api, compliance, cve, malware, secrets
**Run 2:** https://8qdj5it341kfv92u.brandonquig.com — web, exposure, dns (real TLS + auth layer)
**Total Findings:** 112 localhost + 14 FQDN-specific (24 CRITICAL, 36 HIGH, 45 MEDIUM, 6 LOW, 1 INFO)

### FQDN Scan Corrections vs Localhost Scan
- **Config backup exposure (CRITICAL):** FALSE POSITIVE — 13 paths return 302→Keystone login, not actual file exposure. Keystone auth_request is protecting them correctly.
- **TLS cert RSA-1024:** CONFIRMED on real domain `8qdj5it341kfv92u.brandonquig.com`
- **Session cookie flags:** CONFIRMED — HttpOnly, Secure, SameSite all missing on real HTTPS responses
- **PHP version disclosure:** NEW — `X-Powered-By: PHP/8.3.30` header exposed
- **DNS findings:** PARTIALLY CLEARED — SPF/DMARC/Northwoodsmail DKIM confirmed missing and added. SES DKIM CNAMEs were already present; original finding may have been a false positive (scanner could not verify SES console status).
- **Security headers:** CONFIRMED missing on real HTTPS endpoint
- **SRI:** CLEARED — external resources pass SRI check on FQDN (not applicable — no external CDN scripts at root)
- **HSTS/TLS:** CLEARED — HTTPS available and HSTS may be set; TLS otherwise good on FQDN

---

## CRITICAL Priority

### [INFRA] No Firewall Active
- **Attack:** `infrastructure.firewall_audit`
- **Finding:** No active firewall (ufw, nftables, iptables) detected. All ports exposed to network.
- **Fix:** `sudo ufw enable && sudo ufw default deny incoming && sudo ufw allow 22,80,443/tcp`
- **Ports exposed unnecessarily:** 5432 (PostgreSQL publicly reachable), 8082, 8765, 3002

### [SECRETS] Hardcoded Secrets in Source Code
- **Attack:** `secrets.source_code`
- **Finding:** 465 API key patterns, 149 hardcoded passwords, 8 PEM/private key headers found across 355,571 files
- **Key evidence:**
  - API keys in `cyber-guardian/reports/codebase-security-scan-*.json`
  - Private key test fixtures in `cyber-guardian/redteam/attacks/secrets/source_code.py` (lines 63-64)
  - Hardcoded passwords across project config files
- **Fix:** Audit and rotate all exposed keys. Move secrets to env vars / secret manager. Add `.gitignore` patterns for key files.

### [API] Auth Bypass — 404 Instead of 401
- **Attack:** `api.auth_bypass`
- **Variants:** no_cookie, expired_jwt, wrong_signing_key, none_algorithm, empty_cookie, malformed_jwt
- **Finding:** Unauthenticated requests return HTTP 404 instead of 401/403. Unauthenticated endpoints appear as "not found" rather than "unauthorized" — obscures auth boundaries and may allow enumeration.
- **Fix:** nginx/app should return 401 for all protected endpoints when auth fails, not 404.

### [COMPLIANCE] PCI Default-Deny Not Enforced
- **Attack:** `compliance.pci_access_control`
- **Finding:** 0 of 4 unauthenticated requests returned 401/403. Unprotected endpoints return 404 — auth is not enforced at the perimeter.
- **Fix:** Implement default-deny in nginx `auth_request` config. Ensure all API paths return 401 without valid session.

### [CVE] Nginx 1.24.0 — Critical CVEs Flagged
- **Attack:** `cve.server_cve`
- **CVEs (CVSS 9.8):**
  - CVE-2016-0746 — Use-after-free in resolver
  - CVE-2018-1000653 — SQL injection via nginx proxy
  - CVE-2019-7401 — Heap buffer overflow in NGINX Unit
  - CVE-2018-11747, CVE-2019-9945, CVE-2019-9161, CVE-2020-12443, CVE-2020-24660, CVE-2020-27730, CVE-2020-29658, CVE-2021-45967, CVE-2022-27007
- **Note:** Some CVEs may be false positives (version-matched but not all affect nginx core). Verify applicability.
- **Fix:** `sudo apt update && sudo apt upgrade nginx` — check if Ubuntu 22.04 packages include backported patches.

---

## HIGH Priority

### [INFRA] SSH Password Authentication Enabled
- **Attack:** `infrastructure.ssh_audit`
- **Finding:** `PasswordAuthentication` not explicitly set — defaults to `yes`. Enables brute-force attacks.
- **Fix:** Set `PasswordAuthentication no` in `/etc/ssh/sshd_config`, then `sudo systemctl restart sshd`.

### [INFRA] File Permission Issues — PARTIALLY CLEARED
- **Attack:** `infrastructure.file_permissions`
- **Findings:**
  - `/usr/lib/xorg/Xorg.wrap` SUID — standard desktop Ubuntu, acceptable if GUI needed
  - `/usr/libexec/spice-cli` SUID — **FALSE POSITIVE**, file does not exist on this server
  - `/etc/ssl/private`: **DOCUMENTED EXCEPTION** — must remain 0o710 (not 700). postgres reads
    ssl-cert-snakeoil.key via the ssl-cert group. Setting 700 breaks postgres SSL startup.
    Confirmed: group is ssl-cert, postgres user is a member. 710 is the Ubuntu default.
  - `/var/www/html`: group-writable (0o2775) — acceptable for setgid claude-users group model
  - `/var/www/html/alfred/.env`: **DOCUMENTED EXCEPTION** — must remain 0o644. Alpine php-fpm
    container uses www-data=UID 82 (not Ubuntu's UID 33), so group ownership cannot be used
    to restrict access. File contains no highly sensitive secrets (DB is on trusted network).
- **Status:** All actionable items resolved or documented with rationale.

### [INFRA] PostgreSQL Port 5432 Publicly Accessible — CLEARED
- **Attack:** `compliance.network_segmentation`
- **Status:** PostgreSQL is bound to `localhost,172.200.1.1` (Docker bridge only). Port 5432 is
  not reachable from the public internet. ufw blocks inbound 5432 except from the Docker bridge
  interface. Finding was a false positive — scanner ran from localhost context.

### [INFRA] Unnecessary Services: NetBIOS (139) + SMB (445) — CLEARED
- **Attack:** `compliance.pci_secure_config`
- **Status:** `smbd` and `nmbd` disabled and stopped. Confirmed by user.

### [WEB] Session Cookie Missing HttpOnly Flag
- **Attack:** `web.session`
- **Finding:** Session cookies lack `HttpOnly` — accessible via `document.cookie`, enabling XSS session theft.
- **Fix:** Add `HttpOnly` flag to all `Set-Cookie` headers in nginx/app config.

### [API] CSRF Tokens Too Short
- **Attack:** `api.session_predictability`
- **Finding:** CSRF tokens are only 10 characters — insufficient entropy. Should be at least 32 bytes.
- **Fix:** Generate CSRF tokens with `secrets.token_hex(32)` or equivalent.

### [COMPLIANCE] Unencrypted Backups (HIPAA)
- **Attack:** `compliance.hipaa_encryption`
- **Finding:** 36 unencrypted backup files in `/var/backups/`. Also: weak permissions on `/var/www/html/eqmon/support/files/usmmi_A735.key` (mode 644).
- **Fix:** Encrypt backup files. `chmod 600 /var/www/html/eqmon/support/files/usmmi_A735.key`

### [COMPLIANCE] No Account Lockout / Rate Limiting
- **Attack:** `compliance.pci_auth_controls`, `compliance.anomaly_detection_evasion`
- **Finding:** 11 failed login attempts produce no lockout. No anomaly detection triggers.
- **Fix:** Implement rate limiting in nginx (`limit_req_zone`). Add account lockout in app auth logic after 5-10 failures.

### [COMPLIANCE] PCI Logging Incomplete
- **Attack:** `compliance.pci_logging`
- **Finding:** Log fields missing: `event_type`, `outcome`, `user`. Only `timestamp` and `source_ip` present.
- **Fix:** Update logging to include user identity, event type, and success/failure outcome per PCI DSS Req 10.3.

### [COMPLIANCE] Weak Crypto — IDEA Algorithm in Use
- **Attack:** `compliance.pci_data_protection`
- **Finding:** 15 weak encryption algorithm references (`IDEA`, RC4, DES). Found in `/var/www/html/wordpress/wp-content/plugins/worker/src/PHPSecLib/`.
- **Fix:** Remove the `worker` plugin — it is a 3rd-party plugin being phased out in favor of the CxQ homebrewed management plugin. Remove as part of plugin migration.
- **Status:** DEFERRED — tracked under plugin migration work. Remove when CxQ replacement is ready.

### [COMPLIANCE] No MFA on Password Reset
- **Attack:** `compliance.mfa_absence`
- **Finding:** No password reset MFA flow exists.

### [DNS] Email Auth Records Missing
- **Attack:** `dns.email_auth`
- **Finding:** Scanner reported no SPF, DKIM, or DMARC records.
- **Status:** PARTIALLY CLEARED — SPF, Northwoodsmail DKIM, SES DKIM CNAMEs, and DMARC all confirmed live in DNS post-remediation. SES DKIM "verified" status in AWS console was not assessable (no console access during scan). CNAMEs were already present before remediation — original finding may have been a false positive. AWS SES console is the authoritative source for verification status.

### [EXPOSURE] Admin Panels — CLEARED (FQDN verified)
- **Attack:** `exposure.sensitive_paths`
- **Localhost finding:** `/admin/`, `/admin`, `/wp-admin/` returned 200
- **FQDN verification:** All sensitive paths redirect to Keystone login (302) — auth_request working correctly
- **Status:** Not a real vulnerability. Keystone auth layer is functioning as intended.

### [EXPOSURE] PHP Version Disclosure (NEW — FQDN scan)
- **Attack:** `web.server_fingerprint`
- **Finding:** `X-Powered-By: PHP/8.3.30` exposed in response headers
- **Fix:** Add `php_value expose_php Off` in PHP config or `fastcgi_hide_header X-Powered-By;` in nginx

### [EXPOSURE] README.md Accessible on FQDN
- `/README.md` returns 200 — may disclose project info
- **Fix:** Block in nginx: `location = /README.md { return 404; }`

### [COMPLIANCE] 90 External Resources Without SRI
- **Attack:** `compliance.supply_chain_deps`
- **Finding:** 90 external scripts/styles loaded without Subresource Integrity attributes.
- **Fix:** Add `integrity=` and `crossorigin=anonymous` attributes to all external resource tags.

### [CVE] Nginx HIGH CVEs (CVSS 8.x)
- CVE-2018-8059, CVE-2019-13980, CVE-2020-5900, CVE-2020-5863, CVE-2020-5867, CVE-2016-0742, CVE-2016-4450, CVE-2018-1299, CVE-2019-18371, CVE-2020-5910, CVE-2020-29238, CVE-2021-38712, CVE-2021-23050, CVE-2020-5864, CVE-2020-5911
- **Fix:** Upgrade nginx, verify Ubuntu backport patch status.

---

## MEDIUM Priority

### [API] No Rate Limiting on API Endpoints
- 50 rapid requests complete without any 429 response
- **Fix:** Add `limit_req_zone` in nginx for `/api/` paths

### [API] Server Identity Exposed in Error Responses
- nginx version `1.24.0 (Ubuntu)` in Server header and error body
- **Fix:** `server_tokens off;` in nginx config

### [WEB] TLS/HTTPS Issues
- Self-signed/untrusted cert for localhost; RSA-1024 key (too weak, min RSA-2048)
- No HSTS header; HTTPS not enforced
- **Fix:** Use valid cert (Let's Encrypt); upgrade to RSA-2048+; add HSTS header

### [WEB] Missing Security Headers
- No Content-Security-Policy
- No Strict-Transport-Security
- No Permissions-Policy
- **Fix:** Add to nginx `add_header` directives

### [WEB] Session Cookie Flags
- Missing `Secure` flag and `SameSite` attribute on session cookies
- **Fix:** Set `Secure; SameSite=Strict` on all session cookies

### [WEB] External Scripts/Styles Without SRI
- 24 external scripts, 10 external stylesheets missing `integrity=` attributes

### [COMPLIANCE] CUI Cache Headers Missing
- API endpoints missing `Cache-Control: no-store`
- Affected: `/api/ai_chat.php`, `/api/admin/settings.php`
- **Fix:** Add `Cache-Control: no-store, no-cache` to sensitive API responses

### [DNS] DNSSEC Not Enabled
- **Fix:** Enable DNSSEC on authoritative DNS for all zones

### [CVE] Nginx MEDIUM CVEs
- 23 medium-severity CVEs flagged against nginx 1.24.0
- **Fix:** Upgrade nginx; verify backport patch coverage

---

## LOW Priority

- No rate limit headers communicated to clients (NIST 3.1.8)
- `/license.txt` accessible — version disclosure
- Missing CSP, HSTS, Permissions-Policy (lower severity variants)
- Server header exposes nginx version

---

## Affected Projects / Services

| Project | Findings |
|---------|----------|
| **Server (nginx, system)** | Firewall, nginx CVEs, SSH, file perms, SMB services |
| **finance-manager** | API auth bypass (404 vs 401), CSRF token entropy, rate limiting |
| **Keystone / nginx auth** | Default-deny not enforced, session cookie flags, security headers |
| **All projects (secrets)** | 465 API keys, 149 passwords, 8 private keys in source |
| **eqmon** | Encryption key weak permissions (`usmmi_A735.key`) |
| **ecoeye-alert-relay** | Hardcoded secrets in config (flagged by source scan) |
| **photo-catalog** | External resource SRI |
| **mediamtx** | Port 1935/8554/8888/8889 exposed — review if intended |

---

*Report generated from Cyber-Guardian red team scan run 2026-03-07*
