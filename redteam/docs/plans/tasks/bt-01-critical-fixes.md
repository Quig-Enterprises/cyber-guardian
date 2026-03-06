# BT-01: Critical Security Fixes

**Goal:** Fix two critical security vulnerabilities discovered during CMMC gap analysis before building the monitoring system.

**Files:**
- Modify: `/var/www/html/eqmon/api/admin/settings.php` — add authentication
- Modify: `/var/www/html/eqmon/lib/jwt-config.php` — move secret to .env
- Modify: `/var/www/html/eqmon/.env` — add JWT_SECRET
- Modify: `/var/www/html/eqmon/.env.example` — document JWT_SECRET

---

## Step 1: Fix unauthenticated settings.php

The endpoint `api/admin/settings.php` uses `api/pg_config.php` directly with NO authentication check. Any unauthenticated request can read and update `app_settings`.

**Read the current file:**
```bash
cat /var/www/html/eqmon/api/admin/settings.php
```

**Add authentication at the top (after opening PHP tag):**
```php
require_once __DIR__ . '/../../lib/middleware.php';
$session = requireApiAuth();
requireRole($session, 'system-admin');
```

**Verify:** `curl -s http://localhost:8081/eqmon/api/admin/settings.php` should return 401.

---

## Step 2: Move JWT secret to .env

**Current state** (`lib/jwt-config.php` line ~9):
```php
$jwtSecret = "eqmon_jwt_secret_2026_artemis_integration";
```

**Fix `lib/jwt-config.php`:**
```php
$jwtSecret = $_ENV['JWT_SECRET'] ?? getenv('JWT_SECRET') ?: null;
if (!$jwtSecret) {
    error_log('CRITICAL: JWT_SECRET not configured in .env');
    throw new RuntimeException('JWT configuration error');
}
$jwtExpiration = 86400; // 24 hours
```

**Add to `.env`:**
```
JWT_SECRET=eqmon_jwt_secret_2026_artemis_integration
```

**Add to `.env.example`:**
```
JWT_SECRET=change_me_to_a_random_64_char_string
```

**Verify:** Login still works after the change.

---

## Step 3: Verify both fixes

```bash
# Test settings.php requires auth
curl -s -o /dev/null -w '%{http_code}' http://localhost:8081/eqmon/api/admin/settings.php
# Expected: 401

# Test login still works
curl -s -X POST http://localhost:8081/eqmon/api/auth/login.php \
  -H 'Content-Type: application/json' \
  -d '{"email":"redteam-sysadmin@test.com","password":"RedTeam$ysAdmin2026!"}' | python3 -m json.tool
# Expected: {"success": true, ...}
```

---

## Step 4: Commit

```bash
cd /var/www/html/eqmon
git add api/admin/settings.php lib/jwt-config.php .env.example
git commit -m "fix: add auth to settings.php, move JWT secret to .env

SECURITY: settings.php was accessible without authentication (NIST 3.1.1)
SECURITY: JWT secret was hardcoded in source code (NIST 3.13.10)"
```
