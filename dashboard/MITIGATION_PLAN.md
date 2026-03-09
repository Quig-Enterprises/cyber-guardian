# Security Mitigation Plan - Project Keystone

**Scan Date:** 2026-03-08
**Scan Type:** AWS-Compliant Red Team Scan
**Total Vulnerabilities:** 44 vulnerable findings
**Status:** IN PROGRESS
**Priority:** HIGH

---

## Executive Summary

Red team security scan identified 44 vulnerable findings across multiple security domains. This document provides a prioritized mitigation plan with specific remediation steps for each vulnerability category.

**Severity Breakdown:**
- **CRITICAL:** 8 findings (immediate attention required)
- **HIGH:** 0 findings
- **MEDIUM:** 36 findings (address within 30 days)
- **LOW:** 0 findings

**Categories Affected:**
- API Security (17 vulnerable)
- Compliance (13 vulnerable)
- DNS Security (4 vulnerable)
- Infrastructure (4 vulnerable)
- Web Security (5 vulnerable)
- Secrets Management (1 vulnerable)

---

## CRITICAL Priority (Immediate Action Required)

### 1. API Authentication Bypass Vulnerabilities

**Severity:** CRITICAL
**Category:** API Security
**Affected Component:** API authentication endpoints

**Findings:**
- Missing API endpoint returns 404 instead of 401 for unauthenticated requests
- Expired JWT tokens return 404 instead of 401
- Invalid JWT signatures return 404 instead of 401
- JWT with alg=none bypass returns 404 instead of 401
- Empty authentication cookies return 404 instead of proper error
- Malformed JWT tokens return 404 instead of validation error

**Root Cause:**
- API endpoints returning 404 "File not found" for all authentication failures
- This indicates the endpoint may not exist or is not properly configured
- No JWT validation is occurring (all invalid tokens get same 404 response)

**Impact:**
- Attackers cannot distinguish between missing endpoints and authentication failures
- However, this also suggests JWT authentication may not be implemented at all
- **Risk Level:** CRITICAL - JWT authentication appears non-functional

**Remediation Steps:**

1. **Verify API Endpoint Existence**
   - Check if `/api/ai_chat.php` exists
   - Verify endpoint is accessible and routing correctly
   - File: `/var/www/html/alfred/dashboard/api/ai_chat.php`

2. **Implement Proper JWT Validation**
   ```php
   // Add to api/ai_chat.php
   require_once __DIR__ . '/../includes/jwt-validation.php';

   // Validate JWT from Authorization header
   $jwt = getBearerToken();
   if (!$jwt) {
       http_response_code(401);
       echo json_encode(['error' => 'Missing authentication token']);
       exit;
   }

   try {
       $decoded = validateJWT($jwt);
   } catch (Exception $e) {
       http_response_code(401);
       echo json_encode(['error' => 'Invalid authentication token']);
       exit;
   }
   ```

3. **Add Proper HTTP Status Codes**
   - 401 Unauthorized: Missing or invalid authentication
   - 403 Forbidden: Valid auth but insufficient permissions
   - 404 Not Found: Only for truly missing resources

4. **Test Authentication Flow**
   ```bash
   # Test with no auth
   curl -I https://8qdj5it341kfv92u.brandonquig.com/api/ai_chat.php
   # Expected: 401 Unauthorized

   # Test with invalid JWT
   curl -I -H "Authorization: Bearer invalid.jwt.token" \
     https://8qdj5it341kfv92u.brandonquig.com/api/ai_chat.php
   # Expected: 401 Unauthorized

   # Test with valid JWT
   curl -I -H "Authorization: Bearer <valid_token>" \
     https://8qdj5it341kfv92u.brandonquig.com/api/ai_chat.php
   # Expected: 200 OK
   ```

**Estimated Effort:** 4-8 hours
**Assigned To:** [TBD]
**Target Completion:** Within 48 hours

---

### 2. Admin Panel Authentication Bypass

**Severity:** CRITICAL
**Category:** API Security
**Affected Component:** Admin panel authentication

**Finding:**
- API session cookie with role "vessel-officer" was accepted by admin web panel
- Admin panel at `/admin/index.php` does not enforce separate authentication
- Any valid API token grants access to web admin interface

**Root Cause:**
- No role-based access control (RBAC) enforcement on admin panel
- API authentication tokens are accepted for admin panel access
- Missing privilege escalation checks

**Impact:**
- Low-privilege users can access administrative functions
- Privilege escalation from regular user to admin
- **Risk Level:** CRITICAL - Complete admin access control bypass

**Remediation Steps:**

1. **Implement RBAC Middleware**
   - File: `/var/www/html/alfred/dashboard/admin/index.php`
   ```php
   // Add at top of admin/index.php
   require_once __DIR__ . '/../includes/auth.php';
   require_once __DIR__ . '/../includes/rbac.php';

   // Verify session and role
   if (!isAuthenticated()) {
       header('Location: /login.php');
       exit;
   }

   if (!hasRole(['admin', 'security-admin'])) {
       http_response_code(403);
       die('Access denied. Administrator privileges required.');
   }
   ```

2. **Create RBAC Helper Functions**
   - File: `/var/www/html/alfred/dashboard/includes/rbac.php` (create new)
   ```php
   <?php
   function hasRole($allowedRoles) {
       if (!isset($_SESSION['user_role'])) {
           return false;
       }

       $userRole = $_SESSION['user_role'];
       return in_array($userRole, (array)$allowedRoles, true);
   }

   function requireRole($allowedRoles, $message = 'Access denied') {
       if (!hasRole($allowedRoles)) {
           http_response_code(403);
           die($message);
       }
   }
   ```

3. **Audit All Admin Endpoints**
   - Review all files in `/admin/` directory
   - Add role checks to each endpoint
   - Create inventory of admin functions and required roles

4. **Test RBAC Implementation**
   ```bash
   # Test with vessel-officer token (should deny)
   # Test with admin token (should allow)
   # Test with no token (should redirect to login)
   ```

**Estimated Effort:** 8-16 hours
**Assigned To:** [TBD]
**Target Completion:** Within 72 hours

---

## HIGH Priority (30 Day Timeline)

### 3. Rate Limiting and Account Lockout

**Severity:** MEDIUM
**Category:** API Security
**Affected Components:** Login endpoint, API endpoints

**Findings:**
- No account lockout after failed login attempts (10 attempts in 0.0s succeeded)
- No rate limit headers in login response
- Brute-force attacks possible without detection
- NIST 3.1.8 compliance failure

**Root Cause:**
- Missing rate limiting middleware
- No failed login attempt tracking
- No progressive delays on authentication failures

**Impact:**
- Brute-force password attacks feasible
- Credential stuffing attacks possible
- Account compromise risk

**Remediation Steps:**

1. **Implement Redis-Based Rate Limiting**
   ```bash
   # Install Redis
   sudo apt-get install redis-server
   sudo systemctl enable redis-server
   sudo systemctl start redis-server
   ```

2. **Create Rate Limiter Class**
   - File: `/var/www/html/alfred/dashboard/includes/RateLimiter.php` (create new)
   ```php
   <?php
   class RateLimiter {
       private $redis;

       public function __construct() {
           $this->redis = new Redis();
           $this->redis->connect('127.0.0.1', 6379);
       }

       public function checkLimit($key, $maxAttempts, $windowSeconds) {
           $current = $this->redis->incr($key);

           if ($current === 1) {
               $this->redis->expire($key, $windowSeconds);
           }

           return $current <= $maxAttempts;
       }

       public function getRemainingAttempts($key, $maxAttempts) {
           $current = $this->redis->get($key) ?: 0;
           return max(0, $maxAttempts - $current);
       }

       public function reset($key) {
           $this->redis->del($key);
       }
   }
   ```

3. **Apply to Login Endpoint**
   - File: `/var/www/html/alfred/dashboard/api/auth/login.php`
   ```php
   require_once __DIR__ . '/../../includes/RateLimiter.php';

   $limiter = new RateLimiter();
   $ip = $_SERVER['REMOTE_ADDR'];
   $username = $_POST['username'] ?? '';

   // IP-based rate limiting (10 attempts per 15 minutes)
   $ipKey = "login_ip:$ip";
   if (!$limiter->checkLimit($ipKey, 10, 900)) {
       http_response_code(429);
       header('Retry-After: 900');
       echo json_encode(['error' => 'Too many requests. Try again in 15 minutes.']);
       exit;
   }

   // Username-based rate limiting (5 attempts per 30 minutes)
   $userKey = "login_user:" . hash('sha256', $username);
   if (!$limiter->checkLimit($userKey, 5, 1800)) {
       http_response_code(429);
       header('Retry-After: 1800');
       echo json_encode(['error' => 'Account temporarily locked. Try again in 30 minutes.']);
       exit;
   }

   // Add rate limit headers
   header('X-RateLimit-Limit: 10');
   header('X-RateLimit-Remaining: ' . $limiter->getRemainingAttempts($ipKey, 10));
   ```

4. **Add Progressive Delays**
   ```php
   // After failed login attempt
   $attempts = $redis->get($userKey) ?: 0;
   if ($attempts > 3) {
       // Exponential backoff: 2^(attempts-3) seconds
       $delay = pow(2, $attempts - 3);
       sleep(min($delay, 16)); // Max 16 second delay
   }
   ```

**Estimated Effort:** 8-12 hours
**Assigned To:** [TBD]
**Target Completion:** 7 days

---

### 4. Password Policy Enforcement

**Severity:** MEDIUM
**Category:** API Security / Compliance
**Affected Component:** Password management

**Findings:**
- No password change endpoint exists (returns 404)
- Cannot enforce password complexity requirements
- Cannot enforce password rotation
- NIST 3.5.8 compliance failure

**Root Cause:**
- Missing password change functionality
- No password policy validation

**Impact:**
- Users cannot change weak passwords
- Cannot enforce password rotation policies
- Compliance violations (NIST, PCI, HIPAA)

**Remediation Steps:**

1. **Create Password Change Endpoint**
   - File: `/var/www/html/alfred/dashboard/api/auth/change-password.php` (create new)
   ```php
   <?php
   require_once __DIR__ . '/../../includes/auth.php';
   require_once __DIR__ . '/../../includes/password-policy.php';

   // Require authentication
   requireAuth();

   header('Content-Type: application/json');

   if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
       http_response_code(405);
       echo json_encode(['error' => 'Method not allowed']);
       exit;
   }

   $currentPassword = $_POST['current_password'] ?? '';
   $newPassword = $_POST['new_password'] ?? '';
   $confirmPassword = $_POST['confirm_password'] ?? '';

   // Validate inputs
   if (!$currentPassword || !$newPassword || !$confirmPassword) {
       http_response_code(400);
       echo json_encode(['error' => 'Missing required fields']);
       exit;
   }

   if ($newPassword !== $confirmPassword) {
       http_response_code(400);
       echo json_encode(['error' => 'Passwords do not match']);
       exit;
   }

   // Verify current password
   $userId = $_SESSION['user_id'];
   if (!verifyCurrentPassword($userId, $currentPassword)) {
       http_response_code(401);
       echo json_encode(['error' => 'Current password is incorrect']);
       exit;
   }

   // Validate new password against policy
   $validation = validatePasswordPolicy($newPassword);
   if (!$validation['valid']) {
       http_response_code(400);
       echo json_encode(['error' => $validation['message']]);
       exit;
   }

   // Update password
   if (updateUserPassword($userId, $newPassword)) {
       echo json_encode(['success' => true, 'message' => 'Password updated successfully']);
   } else {
       http_response_code(500);
       echo json_encode(['error' => 'Failed to update password']);
   }
   ```

2. **Implement Password Policy Validation**
   - File: `/var/www/html/alfred/dashboard/includes/password-policy.php` (create new)
   ```php
   <?php
   function validatePasswordPolicy($password) {
       $errors = [];

       // Minimum length (NIST 800-63B: 8 characters)
       if (strlen($password) < 8) {
           $errors[] = 'Password must be at least 8 characters long';
       }

       // Maximum length (NIST 800-63B: allow up to 64 characters)
       if (strlen($password) > 64) {
           $errors[] = 'Password must not exceed 64 characters';
       }

       // Check against common passwords (implement HaveIBeenPwned API check)
       if (isCommonPassword($password)) {
           $errors[] = 'Password is too common. Please choose a different password.';
       }

       // Check for username/email in password
       $userId = $_SESSION['user_id'] ?? null;
       if ($userId && containsUserInfo($password, $userId)) {
           $errors[] = 'Password must not contain your username or email';
       }

       if (empty($errors)) {
           return ['valid' => true];
       }

       return [
           'valid' => false,
           'message' => implode('. ', $errors)
       ];
   }

   function isCommonPassword($password) {
       // Check against top 10,000 common passwords
       $commonPasswords = file(__DIR__ . '/../data/common-passwords.txt', FILE_IGNORE_NEW_LINES);
       return in_array(strtolower($password), $commonPasswords, true);
   }
   ```

3. **Download Common Passwords List**
   ```bash
   mkdir -p /var/www/html/alfred/dashboard/data
   wget -O /var/www/html/alfred/dashboard/data/common-passwords.txt \
     https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-10000.txt
   ```

4. **Add Password Change UI**
   - File: `/var/www/html/alfred/dashboard/admin/change-password.php` (create new)
   - Create user-friendly form for password changes
   - Add client-side validation
   - Display password strength meter

**Estimated Effort:** 12-16 hours
**Assigned To:** [TBD]
**Target Completion:** 14 days

---

### 5. DNS Security (DNSSEC and Email Authentication)

**Severity:** MEDIUM
**Category:** DNS Security
**Affected Domain:** brandonquig.com

**Findings:**
- DNSSEC not enabled on brandonquig.com
- Missing or incomplete SPF/DMARC/DKIM records
- Email spoofing risk
- DNS cache poisoning risk

**Root Cause:**
- DNS provider may not support DNSSEC
- Email authentication records not configured

**Impact:**
- Email spoofing attacks possible
- Phishing emails can impersonate domain
- DNS cache poisoning risk (lower impact with HTTPS)

**Remediation Steps:**

1. **Check DNS Provider DNSSEC Support**
   ```bash
   # Check current nameservers
   dig NS brandonquig.com +short

   # Check if DNSSEC is already enabled
   dig DNSKEY brandonquig.com +dnssec
   ```

2. **Enable DNSSEC (if supported)**
   - Log into DNS provider (Cloudflare/Route53/etc.)
   - Enable DNSSEC in DNS settings
   - Add DS records to domain registrar
   - Wait for propagation (24-48 hours)
   - Verify: `dig brandonquig.com +dnssec`

3. **Configure Email Authentication Records**

   **SPF Record:**
   ```dns
   brandonquig.com. IN TXT "v=spf1 include:_spf.google.com include:sendgrid.net ~all"
   ```

   **DMARC Record:**
   ```dns
   _dmarc.brandonquig.com. IN TXT "v=DMARC1; p=quarantine; rua=mailto:dmarc@brandonquig.com; pct=100; adkim=s; aspf=s"
   ```

   **DKIM Record:**
   - Generate DKIM key in email provider (Google Workspace/SendGrid)
   - Add provided DKIM TXT record to DNS
   ```dns
   default._domainkey.brandonquig.com. IN TXT "v=DKIM1; k=rsa; p=<public_key>"
   ```

4. **Verify Email Authentication**
   ```bash
   # Check SPF
   dig TXT brandonquig.com +short | grep spf1

   # Check DMARC
   dig TXT _dmarc.brandonquig.com +short

   # Check DKIM
   dig TXT default._domainkey.brandonquig.com +short

   # Test email authentication
   # Send test email to: check-auth@verifier.port25.com
   ```

**Estimated Effort:** 4-6 hours
**Assigned To:** [TBD]
**Target Completion:** 14 days

---

### 6. Infrastructure Hardening

**Severity:** MEDIUM
**Category:** Infrastructure
**Affected Components:** File permissions, SSH configuration, firewall

**Findings:**
- File permission misconfigurations
- Weak SSH configuration
- Firewall rule gaps

**Remediation Steps:**

1. **File Permission Audit**
   ```bash
   # Check for world-writable files
   find /var/www/html/alfred -type f -perm -002 -ls

   # Check for files owned by wrong user
   find /var/www/html/alfred ! -user www-data -ls

   # Fix permissions
   sudo bash ~/fixperms brandonquig.com
   ```

2. **SSH Hardening**
   - File: `/etc/ssh/sshd_config`
   ```bash
   # Disable password authentication (use keys only)
   PasswordAuthentication no

   # Disable root login
   PermitRootLogin no

   # Use protocol 2 only
   Protocol 2

   # Limit authentication attempts
   MaxAuthTries 3

   # Set login grace time
   LoginGraceTime 30

   # Restart SSH
   sudo systemctl restart sshd
   ```

3. **Firewall Review**
   ```bash
   # Check current firewall rules
   sudo ufw status verbose

   # Ensure only required ports are open
   # 22 (SSH), 80 (HTTP), 443 (HTTPS), 5432 (PostgreSQL - localhost only)

   # Restrict PostgreSQL to localhost
   sudo ufw delete allow 5432
   sudo ufw allow from 127.0.0.1 to any port 5432
   ```

**Estimated Effort:** 6-8 hours
**Assigned To:** [TBD]
**Target Completion:** 21 days

---

### 7. Server Information Disclosure

**Severity:** MEDIUM
**Category:** Web Security
**Affected Component:** Nginx configuration

**Findings:**
- Nginx version exposed in headers and error pages
- Server fingerprinting possible
- Information leakage in error messages

**Root Cause:**
- Default nginx configuration includes server version
- Error pages display server information

**Impact:**
- Attackers can identify nginx version and known vulnerabilities
- Increases attack surface

**Remediation Steps:**

1. **Hide Nginx Version**
   - File: `/etc/nginx/nginx.conf`
   ```nginx
   http {
       # Hide nginx version
       server_tokens off;

       # Custom error pages
       error_page 404 /404.html;
       error_page 500 502 503 504 /50x.html;
   }
   ```

2. **Create Custom Error Pages**
   - Create minimal error pages without server info
   - File: `/var/www/html/alfred/dashboard/404.html`
   ```html
   <!DOCTYPE html>
   <html>
   <head><title>Not Found</title></head>
   <body><h1>404 - Page Not Found</h1></body>
   </html>
   ```

3. **Add Security Headers**
   ```nginx
   # Add to server block
   add_header X-Frame-Options "SAMEORIGIN" always;
   add_header X-Content-Type-Options "nosniff" always;
   add_header X-XSS-Protection "1; mode=block" always;
   add_header Referrer-Policy "strict-origin-when-cross-origin" always;
   ```

4. **Restart Nginx**
   ```bash
   sudo nginx -t
   sudo systemctl reload nginx
   ```

5. **Verify Changes**
   ```bash
   curl -I https://8qdj5it341kfv92u.brandonquig.com/
   # Should NOT see "Server: nginx/1.24.0"
   # Should see "Server: nginx"
   ```

**Estimated Effort:** 2-3 hours
**Assigned To:** [TBD]
**Target Completion:** 7 days

---

## MEDIUM Priority (60 Day Timeline)

### 8. Compliance Framework Implementation

**Severity:** MEDIUM
**Category:** Compliance
**Affected Frameworks:** NIST 800-171, PCI DSS v4, HIPAA

**Findings:**
- 13 compliance control gaps identified
- CUI data flow controls missing
- Encryption requirements not fully met
- Audit logging gaps

**Remediation Steps:**

1. **NIST 800-171 Controls**
   - Implement CUI data classification
   - Add encryption at rest for sensitive data
   - Implement comprehensive audit logging
   - Create incident response procedures

2. **PCI DSS v4 Controls**
   - Implement payment data encryption
   - Add quarterly vulnerability scanning
   - Create cardholder data retention policy
   - Implement access control requirements

3. **HIPAA Controls**
   - Implement PHI encryption (at rest and in transit)
   - Add comprehensive audit trails
   - Create breach notification procedures
   - Implement access controls for PHI

**Note:** Full compliance implementation requires dedicated project planning.
See separate compliance implementation plan.

**Estimated Effort:** 80-120 hours
**Assigned To:** [TBD]
**Target Completion:** 60 days

---

### 9. Secrets Management

**Severity:** MEDIUM
**Category:** Secrets
**Finding:** Git history may contain sensitive data

**Remediation Steps:**

1. **Scan Git History**
   ```bash
   # Install gitleaks
   brew install gitleaks

   # Scan repository
   cd /var/www/html/alfred/dashboard
   gitleaks detect --source . --verbose
   ```

2. **Remove Secrets from History (if found)**
   ```bash
   # Use BFG Repo-Cleaner
   java -jar bfg.jar --delete-files passwords.txt
   git reflog expire --expire=now --all
   git gc --prune=now --aggressive
   ```

3. **Prevent Future Secret Commits**
   - Add `.env` to `.gitignore`
   - Use pre-commit hooks to detect secrets
   - Implement secret scanning in CI/CD

**Estimated Effort:** 4-6 hours
**Assigned To:** [TBD]
**Target Completion:** 30 days

---

## Testing and Verification

### Re-Scan After Remediation

After implementing mitigations, re-run the red team scan to verify fixes:

```bash
cd /opt/claude-workspace/projects/cyber-guardian
source venv/bin/activate
python3 redteam/runner.py --mode aws --all --report json html \
  --compare redteam/reports/redteam-report-20260308_184540.json
```

This will show:
- New vulnerabilities (if any)
- Resolved issues
- Regressed findings

### Success Criteria

- [ ] All CRITICAL findings resolved
- [ ] 80% of HIGH findings resolved
- [ ] 50% of MEDIUM findings resolved
- [ ] No new vulnerabilities introduced
- [ ] All compliance frameworks showing improvement

---

## Resource Allocation

### Estimated Total Effort

- **CRITICAL Priority:** 12-24 hours
- **HIGH Priority:** 38-50 hours
- **MEDIUM Priority:** 86-129 hours
- **Total:** 136-203 hours (17-25 business days)

### Recommended Timeline

- **Week 1-2:** CRITICAL fixes (items 1-2)
- **Week 3-4:** HIGH priority (items 3-7)
- **Week 5-12:** MEDIUM priority (items 8-9)

### Required Skills

- PHP development
- Security architecture
- DNS configuration
- System administration
- Compliance knowledge

---

## Tracking and Reporting

### Status Updates

- **Weekly:** Update this document with progress
- **Bi-weekly:** Executive summary to stakeholders
- **Monthly:** Re-scan and comparison report

### Metrics

- Vulnerabilities resolved (by severity)
- Average time to remediation
- Compliance score improvement
- Security posture trend

---

## Appendix

### Related Documents

- CYBER_GUARDIAN_SETUP.md - Scanner setup and usage
- /tmp/project-keystone-deployment-summary.md - Deployment documentation
- Scan reports: /opt/claude-workspace/projects/cyber-guardian/redteam/reports/

### References

- NIST 800-171 Rev 2
- PCI DSS v4.0
- HIPAA Security Rule
- OWASP Top 10 2021
- CWE Top 25

---

**Document Version:** 1.0
**Last Updated:** 2026-03-08
**Next Review:** 2026-03-15
