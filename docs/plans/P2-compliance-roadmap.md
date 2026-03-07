# P2 Compliance Roadmap — Implementation Plans

Generated: 2026-03-07 from red team scan findings.

---

## 1. Multi-Factor Authentication (MFA)

**Findings:** `compliance.hipaa_session_auth/mfa_ephi_access`, `compliance.pci_auth_controls/mfa_all_cde_access`
**Severity:** CRITICAL (PCI DSS 4.0 Req 8.4.2) / HIGH (HIPAA 164.312(d))

### Approach: TOTP-based MFA

**Phase 1: Backend (2-3 days)**
- Add `user_mfa` table: `user_id`, `totp_secret` (encrypted), `backup_codes`, `enabled_at`, `verified`
- Integrate PHP TOTP library (`robthree/twofactorauth` via Composer)
- Add MFA enrollment API: `/api/auth/mfa-setup.php` (generate secret, return QR code URI)
- Add MFA verification API: `/api/auth/mfa-verify.php` (validate 6-digit code)
- Modify login flow in `/api/auth/login.php`:
  - If MFA enabled: return `{"mfa_required": true, "mfa_token": "..."}` instead of JWT
  - Client must POST to `/api/auth/mfa-verify.php` with `mfa_token` + `code` to get JWT
- Add backup codes (10 one-time codes) generated at enrollment

**Phase 2: Frontend (1-2 days)**
- MFA setup page in admin: QR code display, manual key entry, verify first code
- Login page: conditional MFA step after email/password
- Account settings: enable/disable MFA, regenerate backup codes

**Phase 3: Enforcement (1 day)**
- Add `mfa_required` flag to roles (system-admin, company-admin = mandatory)
- Grace period: 7 days for existing users to enroll after enforcement enabled
- Audit log all MFA events (setup, verify, backup code use, disable)

**Files to modify:**
- `lib/session.php` — MFA state in JWT claims
- `api/auth/login.php` — MFA challenge flow
- `api/auth/mfa-setup.php` — NEW
- `api/auth/mfa-verify.php` — NEW
- `admin/settings.php` — MFA policy config
- `migrations/` — user_mfa table

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

| Item | Effort | Priority | Dependencies |
|------|--------|----------|-------------|
| **MFA** | 4-6 days | P2a (highest) | None |
| **Encryption at Rest** | 3-4 days | P2b | None |
| **CUI Marking** | 1.5 days | P2c | None |
| **Dual Authorization** | 4-6 days | P2d | MFA (approvers should have MFA) |
| **Break-Glass** | 2 days | P2e | MFA, Dual Auth |

**Recommended order:** MFA → Encryption → CUI Marking → Dual Auth → Break-Glass

Total estimated effort: **15-20 days** of development work.
