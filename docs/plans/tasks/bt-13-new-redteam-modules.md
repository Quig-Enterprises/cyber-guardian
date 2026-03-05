# BT-13: New Red Team Attack Modules (CMMC Gap Coverage)

**Goal:** Add 10 new attack modules to the red team framework targeting CMMC/NIST compliance gaps discovered during blue team design analysis.

**Files:**
- Create: `/opt/security-red-team/redteam/attacks/compliance/mfa_absence.py`
- Create: `/opt/security-red-team/redteam/attacks/api/unauth_admin_settings.py`
- Create: `/opt/security-red-team/redteam/attacks/api/jwt_secret_extraction.py`
- Create: `/opt/security-red-team/redteam/attacks/compliance/encryption_at_rest.py`
- Create: `/opt/security-red-team/redteam/attacks/api/session_timeout.py`
- Create: `/opt/security-red-team/redteam/attacks/api/privilege_escalation_v2.py`
- Create: `/opt/security-red-team/redteam/attacks/api/password_policy.py`
- Create: `/opt/security-red-team/redteam/attacks/compliance/audit_log_tamper.py`
- Create: `/opt/security-red-team/redteam/attacks/api/account_lockout_bypass.py`
- Create: `/opt/security-red-team/redteam/attacks/compliance/cui_data_flow.py`
- Create: `/opt/security-red-team/redteam/attacks/compliance/__init__.py`

**Depends on:** BT-01 (critical fixes inform attack targets)

---

## New Attack Modules

### 1. compliance.mfa_absence (CRITICAL — NIST 3.5.3)

```python
"""Test that MFA is NOT required — this is a compliance failure."""
# Variants:
# - login_no_mfa: Login with just email+password, verify no MFA challenge
# - privileged_no_mfa: Admin login without MFA
# - password_reset_no_mfa: Password reset flow without MFA
#
# Expected: All should be VULNERABLE (MFA not implemented yet)
# This documents the compliance gap for POA&M tracking
```

### 2. api.unauth_admin_settings (CRITICAL — NIST 3.1.1)

```python
"""Test unauthenticated access to admin settings endpoint."""
# Variants:
# - read_settings_no_auth: GET /api/admin/settings.php without cookie
# - write_settings_no_auth: POST to update settings without cookie
# - read_settings_wrong_role: Access with viewer role
#
# Note: BT-01 should fix this. This module validates the fix.
```

### 3. api.jwt_secret_extraction (CRITICAL — NIST 3.13.10)

```python
"""Test for JWT secret exposure and weak JWT configuration."""
# Variants:
# - known_secret_forge: Try forging JWT with known hardcoded secret
# - jwt_none_algorithm: Try JWT with alg=none
# - jwt_weak_hmac: Try JWT with common weak secrets
# - source_code_exposure: Check if lib/jwt-config.php is accessible via web
#
# Note: BT-01 moves secret to .env. This validates the fix.
```

### 4. compliance.encryption_at_rest (HIGH — NIST 3.13.16)

```python
"""Test whether CUI data is encrypted at rest in the database."""
# Variants:
# - db_column_encryption: Check if bearing data columns are encrypted
# - chat_history_encryption: Check if AI chat messages are encrypted
# - file_upload_encryption: Check if uploaded files are encrypted
# - backup_encryption: Check if DB backups are encrypted
#
# Method: Connect to DB and check for pgcrypto usage, column types,
# tablespace encryption settings
```

### 5. api.session_timeout (HIGH — NIST 3.1.10, 3.1.11)

```python
"""Test session timeout and inactivity lock enforcement."""
# Variants:
# - no_inactivity_timeout: Use token after 30min inactivity — should be locked
# - 24h_token_validity: JWT valid for full 24 hours with no renewal
# - no_session_lock: No pattern-hiding display on inactivity
# - concurrent_sessions: Same user active from multiple locations
```

### 6. api.privilege_escalation_v2 (HIGH — NIST 3.1.7)

```python
"""Advanced privilege escalation beyond basic IDOR testing."""
# Variants:
# - viewer_admin_endpoints: Viewer role accessing /api/admin/* endpoints
# - viewer_user_management: Viewer attempting user CRUD
# - vessel_officer_cross_opco: Officer accessing other opco's data
# - company_admin_system_admin: Company admin escalating to system-admin
# - role_parameter_tampering: Inject role in request body
# - direct_db_function_call: Attempt to call admin DB functions
```

### 7. api.password_policy (MEDIUM — NIST 3.5.7, 3.5.8)

```python
"""Test password policy enforcement."""
# Variants:
# - short_password: Try setting password < 15 chars
# - common_password: Try setting a common/blocked password
# - password_reuse: Change password then change back to original
# - no_complexity: Try all-lowercase password
# - sequential_chars: Try "abcdefghijklmnop"
# - repeated_chars: Try "aaaaaaaaaaaaaaa"
```

### 8. compliance.audit_log_tamper (MEDIUM — NIST 3.3.8)

```python
"""Test whether audit logs can be tampered with."""
# Variants:
# - delete_audit_events: Try DELETE on audit_events as app user
# - update_audit_events: Try UPDATE on audit_events as app user
# - truncate_audit_events: Try TRUNCATE
# - drop_audit_table: Try DROP TABLE
# - modify_via_api: Check if any API endpoint can modify audit data
#
# Method: Use the app's DB credentials (from .env) to attempt modifications
# Expected after BT-02: All should fail (append-only role)
```

### 9. api.account_lockout_bypass (MEDIUM — NIST 3.1.8)

```python
"""Test rate limiter edge cases and bypass techniques."""
# Variants:
# - ip_rotation: Same account, rotating X-Forwarded-For headers
# - timing_attack: Rapid requests just under threshold, wait, repeat
# - distributed_attack: Multiple accounts from same IP vs per-account limiting
# - rate_limit_reset: Test if successful login resets failed count
# - file_based_race: Concurrent requests to race the file-based state
```

### 10. compliance.cui_data_flow (MEDIUM — NIST 3.1.3)

```python
"""Test whether CUI flows to unauthorized locations."""
# Variants:
# - ai_chat_cui_in_logs: Check if AI responses containing CUI are in PHP error logs
# - cui_in_browser_cache: Check cache headers for CUI endpoints
# - cui_in_url_params: Check if any CUI appears in URL query strings
# - export_without_marking: Export bearing data — does it include CUI markings?
# - cross_instance_leakage: Query bearing data across instance boundaries
```

---

## Implementation Pattern

Each module follows the existing red team attack pattern:

```python
from redteam.base import Attack, AttackResult, Variant
from redteam.scoring import Severity

class MFAAbsence(Attack):
    name = "compliance.mfa_absence"
    category = "compliance"
    description = "Verify MFA is required for all network access (NIST 3.5.3)"

    def get_variants(self) -> list[Variant]:
        return [
            Variant("login_no_mfa", "Login without MFA challenge", Severity.CRITICAL),
            Variant("privileged_no_mfa", "Admin login without MFA", Severity.CRITICAL),
        ]

    async def execute_variant(self, variant: Variant, client) -> AttackResult:
        # Implementation...
```

---

## Step: Create compliance subdirectory

```bash
mkdir -p /opt/security-red-team/redteam/attacks/compliance
touch /opt/security-red-team/redteam/attacks/compliance/__init__.py
```

---

## Step: Implement all 10 modules, register in attack registry

Each module: write, test with `python runner.py --attack <name>`, verify results.

---

## Step: Run full suite with new modules

```bash
cd /opt/security-red-team
source venv/bin/activate
python runner.py --all --report html --report json
```

---

## Step: Commit

```bash
cd /opt/security-red-team
git add -A
git commit -m "feat: add 10 CMMC compliance attack modules (MFA, encryption, audit, session)"
```
