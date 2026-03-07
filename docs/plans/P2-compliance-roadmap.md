# P2 Compliance Roadmap — Implementation Plans

Generated: 2026-03-07 from red team scan findings.
Updated: 2026-03-07 — MFA backend integration complete.

---

## 1. Multi-Factor Authentication (MFA) — COMPLETE

**Findings:** `compliance.hipaa_session_auth/mfa_ephi_access`, `compliance.pci_auth_controls/mfa_all_cde_access`
**Severity:** CRITICAL (PCI DSS 4.0 Req 8.4.2) / HIGH (HIPAA 164.312(d))
**Status:** COMPLETE. Backend + Frontend implemented.

### Approach: Reuse existing Artemis MFA infrastructure

Instead of building a new MFA system, eqmon integrates with the existing Artemis MFA stack
(TOTP + WebAuthn + recovery codes + enforcement + grace periods) since eqmon already
authenticates against `artemis_admin`.

**Phase 1: Backend — COMPLETE**
- Added `spomky-labs/otphp` to eqmon composer (same library as Artemis)
- Modified `api/auth/login.php`:
  - After password verification, checks `mfa_totp_enabled` and `webauthn_credentials` in artemis_admin
  - If MFA enabled: returns `{"mfa_required": true, "mfa_methods": [...], "mfa_token": "..."}`
  - Challenge stored in `artemis_admin.mfa_challenges` (shared with Artemis, 5-min expiry)
  - Supports trusted device cookie (`eqmon_trusted_device`) to skip MFA for 7 days
- Created `api/auth/mfa-verify.php`:
  - Validates challenge token + TOTP code (or recovery code) against artemis_admin
  - On success: creates eqmon session (JWT cookie) with full user context
  - Supports "remember this device" with trusted_devices table
  - Full audit logging via AuditLogger
- No new database tables needed — uses existing artemis_admin schema

**Phase 2: Frontend — COMPLETE**
- Login page: added conditional MFA step after email/password returns `mfa_required`
  - TOTP code input field (6-digit, centered, spaced)
  - "Use recovery code instead" link with toggle
  - "Remember this device for 7 days" checkbox
  - "Back to login" link to return to email/password form
- Account settings: link to Artemis MFA setup page for enrollment/management (existing)

**Phase 3: Enforcement (already available via Artemis)**
- Grace period enforcement already exists in `artemis_admin` (MfaEnforcement class)
- Admin can set grace periods per-user via Artemis admin panel
- Audit logging integrated in both login and mfa-verify endpoints

**Files modified:**
- `composer.json` — added `spomky-labs/otphp`
- `api/auth/login.php` — MFA check after password verification
- `api/auth/mfa-verify.php` — NEW (TOTP + recovery code verification)

**Estimated remaining effort:** 0 days — COMPLETE

---

## 2. Encryption at Rest

**Findings:** `compliance.hipaa_encryption/ephi_encryption_at_rest`, `compliance.encryption_at_rest/chat_history_encryption`, `compliance.encryption_at_rest/backup_encryption`, `compliance.hipaa_encryption/backup_encryption`
**Severity:** CRITICAL (HIPAA 164.312(a)(2)(iv))

### Approach: Layered encryption

**Layer 1: Database Column Encryption (1-2 days)**
- Install `pgcrypto` extension: `CREATE EXTENSION pgcrypto;`
- Encrypt sensitive columns using `pgp_sym_encrypt()`:
  - `ai_chat_messages.content` — chat history containing CUI
  - `notes.content` — user-entered analysis notes
  - `audit_events.metadata` — may contain sensitive context
- Key management: encryption key stored in `/etc/eqmon/encryption.key` (640, root:www-data)
- Migration script: encrypt existing plaintext data in-place
- Application changes: decrypt on read via `pgp_sym_decrypt()` in query layer

**Layer 2: Backup Encryption (0.5 days)**
- Modify backup script at `/var/backups/eqmon/`:
  ```bash
  pg_dump -d eqmon | gpg --batch --yes --symmetric \
    --passphrase-file /etc/eqmon/backup.key \
    -o /var/backups/eqmon/eqmon-$(date +%Y%m%d).sql.gpg
  ```
- Add restore script with decryption step
- Rotate backup encryption key quarterly

**Layer 3: Disk Encryption (evaluation)**
- Evaluate LUKS on the PostgreSQL data partition (`/var/lib/postgresql/`)
- This provides transparent encryption but requires key management at boot
- Recommended for new deployments; retrofit on running system requires maintenance window

**Files to modify:**
- `lib/db.php` — add encrypt/decrypt helper functions
- `api/ai_chat.php` — use encrypted reads/writes for chat content
- `api/notes.php` — encrypt note content
- `migrations/` — pgcrypto extension + column migration
- Backup scripts

---

## 3. Dual Authorization for Bulk Operations

**Finding:** `compliance.dual_authorization_bypass/single_admin_bulk_export`
**Severity:** HIGH (NIST SP 800-172 3.1.1e)

### Approach: Approval workflow for sensitive operations

**Phase 1: Approval Queue (2-3 days)**
- Add `pending_approvals` table:
  - `id`, `requester_id`, `approver_id`, `operation_type`, `parameters` (jsonb)
  - `status` (pending/approved/rejected/expired), `created_at`, `resolved_at`, `expires_at`
- Operations requiring dual auth:
  - Bulk user export (>10 records)
  - Bulk data export (sensor readings, audit logs)
  - User role escalation to system-admin
  - System configuration changes (JWT secret, API keys)

**Phase 2: API + UI (1-2 days)**
- API: `/api/admin/approvals.php` — list pending, approve, reject
- When triggering a dual-auth operation:
  1. Create pending_approval record
  2. Return `{"approval_required": true, "approval_id": "..."}`
  3. Notify eligible approvers (websocket or email)
  4. Second admin approves → operation executes
- Auto-expire after 24 hours

**Phase 3: Admin UI (1 day)**
- Approval queue in admin panel with approve/reject buttons
- Email notifications to admins when approval requested
- Audit log all approval actions

**Files to modify:**
- `api/admin/` — wrap bulk operations with approval check
- `api/admin/approvals.php` — NEW
- `admin/approvals.php` — NEW (UI page)
- `migrations/` — pending_approvals table

---

## 4. Emergency Access (Break-Glass) Procedure

**Finding:** `compliance.hipaa_session_auth/emergency_access_procedure`
**Severity:** MEDIUM (HIPAA 164.312(a)(2)(ii))

### Approach: Documented break-glass account with audit trail

**Phase 1: Emergency Account (1 day)**
- Create dedicated `emergency-access` user in database with system-admin role
- Account is disabled by default (`status: locked`)
- Break-glass activation:
  1. Run CLI command: `php artisan eqmon:break-glass --reason "description"`
  2. Generates one-time password, logs activation to audit_events
  3. Password expires after 4 hours
  4. All actions during emergency session are tagged `emergency: true` in audit

**Phase 2: Documentation (0.5 days)**
- Document procedure in `/docs/emergency-access-procedure.md`
- Include: when to use, who can authorize, how to activate, post-incident review steps
- Add to admin panel as "Emergency Access" section under Security page

**Phase 3: Post-Incident (0.5 days)**
- Auto-lock emergency account after TTL expires
- Generate incident report from audit_events where `emergency = true`
- Require post-incident review within 48 hours

**Files to modify:**
- `scripts/break-glass.php` — NEW CLI tool
- `lib/session.php` — emergency session flag
- `admin/security.php` — emergency access status display
- `migrations/` — emergency_access_log table

---

## 5. CUI Data Flow Marking

**Finding:** `compliance.cui_data_flow/export_no_marking`
**Severity:** MEDIUM (NIST SP 800-172 3.1.3e)

### Approach: CUI marking headers and banners

**Phase 1: API Response Headers (0.5 days)**
- Add middleware that appends CUI marking headers to API responses containing sensitive data:
  ```
  X-CUI-Category: CTI
  X-CUI-Handling: CUI//SP-CTI
  X-Data-Classification: CONTROLLED
  ```
- Apply to endpoints that return: sensor readings, analysis results, chat history, user data

**Phase 2: Export Marking (0.5 days)**
- When data is exported (CSV, PDF, JSON download):
  - Prepend CUI banner: `"CUI//SP-CTI - Controlled Technical Information"`
  - Add footer: `"Distribution limited to authorized personnel"`
  - Include export metadata: who exported, when, what scope

**Phase 3: UI Banners (0.5 days)**
- Add CUI classification banner at top of pages displaying sensitive data
- Color-coded: green (public), yellow (CUI), red (restricted)
- Configurable per data type in admin settings

**Files to modify:**
- `lib/middleware.php` or `lib/response.php` — CUI header injection
- Export functions in API endpoints
- `includes/header.php` — CUI banner component
- `admin/settings.php` — CUI marking configuration

---

## Implementation Priority & Timeline

| Item | Effort | Priority | Status | Dependencies |
|------|--------|----------|--------|-------------|
| **MFA** | COMPLETE | P2a (highest) | DONE | None |
| **Encryption at Rest** | 3-4 days | P2b | Planned | None |
| **CUI Marking** | 1.5 days | P2c | Planned | None |
| **Dual Authorization** | 4-6 days | P2d | Planned | MFA (approvers should have MFA) |
| **Break-Glass** | 2 days | P2e | Planned | MFA, Dual Auth |

**Recommended order:** ~~MFA~~ (COMPLETE) → Encryption → CUI Marking → Dual Auth → Break-Glass

Total estimated remaining effort: **11-14.5 days** (was 15-20, MFA backend saved 3-5 days by reusing Artemis).
