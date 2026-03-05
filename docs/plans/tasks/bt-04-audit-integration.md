# BT-04: Integrate AuditLogger into EQMON Endpoints

**Goal:** Add AuditLogger calls to all security-relevant EQMON endpoints so every action is captured in the audit trail.

**Files:**
- Modify: `/var/www/html/eqmon/lib/middleware.php` — add logApiAccess() call
- Modify: `/var/www/html/eqmon/api/auth/login.php` — audit login events
- Modify: `/var/www/html/eqmon/api/auth/logout.php` — audit logout
- Modify: `/var/www/html/eqmon/api/auth/forgot-password.php` — audit password reset requests
- Modify: `/var/www/html/eqmon/api/auth/reset-password.php` — audit password resets
- Modify: `/var/www/html/eqmon/api/auth/impersonate.php` — audit impersonation
- Modify: `/var/www/html/eqmon/api/admin/users.php` — audit user CRUD
- Modify: `/var/www/html/eqmon/api/admin/reset-password.php` — audit admin password reset
- Modify: `/var/www/html/eqmon/api/ai_chat.php` — audit AI interactions
- Modify: `/var/www/html/eqmon/api/stream.php` — audit SSE connections

**Depends on:** BT-03

---

## Step 1: Add AuditLogger to middleware.php

In `requireApiAuth()`, after successful auth validation, add:

```php
require_once __DIR__ . '/AuditLogger.php';

// Inside requireApiAuth(), after $session is validated:
AuditLogger::logApiAccess($session);
```

On auth failure (401 response), add before the exit:

```php
AuditLogger::log(AuditLogger::CAT_ACCESS, 'api_request', AuditLogger::RESULT_DENIED);
```

This single integration point captures ALL authenticated API requests.

---

## Step 2: Add audit to login.php

Replace the existing `logLoginAttempt()` calls with AuditLogger equivalents:

**On successful login (before response):**
```php
AuditLogger::logAuth('login', AuditLogger::RESULT_SUCCESS, $user['user_id'], $email, $authSource);
```

**On failed login (each failure path):**
```php
AuditLogger::logAuth('login', AuditLogger::RESULT_FAILURE, null, $email, null, 'invalid_credentials');
```

**On rate limited:**
```php
AuditLogger::logAuth('login', AuditLogger::RESULT_DENIED, null, $email, null, 'rate_limited');
```

**On inactive account:**
```php
AuditLogger::logAuth('login', AuditLogger::RESULT_FAILURE, $eqmonUser['user_id'], $email, 'eqmon', 'account_inactive');
```

Keep the existing `logLoginAttempt()` for backward compatibility — it writes to `login_attempts` table which is fine as a secondary record.

---

## Step 3: Add audit to logout.php

```php
require_once __DIR__ . '/../../lib/AuditLogger.php';
AuditLogger::logAuth('logout', AuditLogger::RESULT_SUCCESS, $session['user_id']);
```

---

## Step 4: Add audit to forgot-password.php and reset-password.php

**forgot-password.php:**
```php
require_once __DIR__ . '/../../lib/AuditLogger.php';

// After successful token generation and email send:
AuditLogger::logAuth('password_reset_request', AuditLogger::RESULT_SUCCESS, $user['user_id'], $email);

// For non-existent users (still log for anomaly detection, but no user_id):
AuditLogger::logAuth('password_reset_request', AuditLogger::RESULT_SUCCESS, null, $email);
```

**reset-password.php:**
```php
require_once __DIR__ . '/../../lib/AuditLogger.php';

// After successful password change:
AuditLogger::logAuth('password_reset', AuditLogger::RESULT_SUCCESS, $user['user_id'], $user['email']);

// On invalid/expired token:
AuditLogger::logAuth('password_reset', AuditLogger::RESULT_FAILURE, null, null, null, 'invalid_token');
```

---

## Step 5: Add audit to impersonate.php

```php
require_once __DIR__ . '/../../lib/AuditLogger.php';

// On impersonation start:
AuditLogger::logAdmin('impersonation_start', AuditLogger::RESULT_SUCCESS, $session['user_id'], $targetUserId, [
    'admin_email' => $session['email'],
    'target_email' => $targetUser['email'],
]);

// On impersonation denied:
AuditLogger::logAdmin('impersonation_start', AuditLogger::RESULT_DENIED, $session['user_id'], $targetUserId);
```

---

## Step 6: Add audit to api/admin/users.php

**User creation:**
```php
AuditLogger::logAdmin('user_create', AuditLogger::RESULT_SUCCESS, $session['user_id'], $newUserId, [
    'email' => $input['email'],
    'role' => $input['role'],
]);
```

**User deactivation:**
```php
AuditLogger::logAdmin('user_deactivate', AuditLogger::RESULT_SUCCESS, $session['user_id'], $targetUserId);
```

**User deletion:**
```php
AuditLogger::logAdmin('user_delete', AuditLogger::RESULT_SUCCESS, $session['user_id'], $targetUserId, [
    'email' => $targetUser['email'],
]);
```

**Role change:**
```php
AuditLogger::logAdmin('role_change', AuditLogger::RESULT_SUCCESS, $session['user_id'], $targetUserId, [
    'old_role' => $oldRole,
    'new_role' => $newRole,
]);
```

---

## Step 7: Add audit to api/admin/reset-password.php

```php
AuditLogger::logAdmin('admin_password_reset', AuditLogger::RESULT_SUCCESS, $session['user_id'], $targetUserId);
```

---

## Step 8: Add audit to api/ai_chat.php

```php
require_once __DIR__ . '/../lib/AuditLogger.php';

// On chat request (before processing):
AuditLogger::logAI('chat_request', AuditLogger::RESULT_SUCCESS, $session['user_id'], [
    'mode' => $mode, // 'general' or 'analysis'
    'message_length' => strlen($userMessage),
]);

// If guardrail triggers:
AuditLogger::logAI('guardrail_triggered', AuditLogger::RESULT_DENIED, $session['user_id'], [
    'reason' => $guardrailReason,
    'pattern' => $matchedPattern,
]);
```

---

## Step 9: Verify audit trail

```bash
# Login as test user
curl -s -X POST http://localhost:8081/eqmon/api/auth/login.php \
  -H 'Content-Type: application/json' \
  -d '{"email":"redteam-sysadmin@test.com","password":"RedTeam$ysAdmin2026!"}'

# Check audit events
sudo -u postgres psql -d eqmon -c "SELECT timestamp, category, action, result, ip_address FROM audit_events ORDER BY timestamp DESC LIMIT 10;"
```

Expected: auth/login success event + any api_request events.

---

## Step 10: Commit

```bash
cd /var/www/html/eqmon
git add -A
git commit -m "feat: integrate AuditLogger into all endpoints (NIST 3.3.1, 3.3.2, 3.1.7)"
```
