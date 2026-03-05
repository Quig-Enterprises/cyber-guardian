# BT-03: AuditLogger PHP Class

**Goal:** Implement a thin audit logging middleware class that captures all security-relevant events to the `audit_events` PostgreSQL table.

**Files:**
- Create: `/var/www/html/eqmon/lib/AuditLogger.php`

**Depends on:** BT-02

---

## Step 1: Implement AuditLogger.php

```php
<?php
/**
 * AuditLogger - Centralized audit event logging for NIST 800-171 compliance
 *
 * NIST Controls: 3.3.1 (create audit logs), 3.3.2 (user traceability),
 *                3.3.7 (UTC timestamps), 3.3.8 (protected logging)
 *
 * @package EQMON
 */

class AuditLogger
{
    // Event categories matching NIST control families
    const CAT_AUTH   = 'auth';    // Authentication events (3.5.x)
    const CAT_ACCESS = 'access';  // Resource access events (3.1.x)
    const CAT_ADMIN  = 'admin';   // Administrative actions (3.1.7)
    const CAT_DATA   = 'data';    // CUI data operations (3.1.3)
    const CAT_AI     = 'ai';     // AI chat events
    const CAT_SYSTEM = 'system';  // System events (3.14.x)

    // Result values
    const RESULT_SUCCESS = 'success';
    const RESULT_FAILURE = 'failure';
    const RESULT_DENIED  = 'denied';

    private static ?PDO $db = null;
    private static bool $failed = false;

    /**
     * Log an audit event.
     *
     * @param string      $category     Event category (CAT_* constant)
     * @param string      $action       Specific action (e.g., 'login', 'view_bearing')
     * @param string      $result       Outcome (RESULT_* constant)
     * @param string|null $userId       User performing the action
     * @param array       $metadata     Additional context (JSONB)
     * @param bool        $cuiAccessed  Whether CUI was involved
     * @param string|null $resourceType API endpoint or page type
     * @param string|null $resourceId   Specific resource identifier
     * @param string|null $instanceId   Tenant context
     */
    public static function log(
        string  $category,
        string  $action,
        string  $result = self::RESULT_SUCCESS,
        ?string $userId = null,
        array   $metadata = [],
        bool    $cuiAccessed = false,
        ?string $resourceType = null,
        ?string $resourceId = null,
        ?string $instanceId = null
    ): void {
        // Don't retry if DB connection already failed this request
        if (self::$failed) return;

        try {
            $db = self::getDb();
            if (!$db) return;

            $stmt = $db->prepare("
                INSERT INTO audit_events
                    (category, action, result, user_id, session_id,
                     ip_address, user_agent, resource_type, resource_id,
                     instance_id, cui_accessed, metadata)
                VALUES
                    (:category, :action, :result, :user_id, :session_id,
                     :ip_address, :user_agent, :resource_type, :resource_id,
                     :instance_id, :cui_accessed, :metadata)
            ");

            $stmt->execute([
                ':category'      => $category,
                ':action'        => $action,
                ':result'        => $result,
                ':user_id'       => $userId,
                ':session_id'    => self::getSessionId(),
                ':ip_address'    => self::getClientIp(),
                ':user_agent'    => self::getUserAgent(),
                ':resource_type' => $resourceType ?? self::getResourceType(),
                ':resource_id'   => $resourceId,
                ':instance_id'   => $instanceId,
                ':cui_accessed'  => $cuiAccessed ? 'true' : 'false',
                ':metadata'      => json_encode($metadata),
            ]);
        } catch (Throwable $e) {
            self::$failed = true;
            // Log failure to syslog (3.3.4 — audit failure alerting)
            openlog('eqmon-audit', LOG_PID, LOG_AUTH);
            syslog(LOG_CRIT, "AUDIT_FAILURE: " . $e->getMessage() .
                " category={$category} action={$action}");
            closelog();
            // Also to PHP error log as backup
            error_log("AuditLogger FAILURE: " . $e->getMessage());
        }
    }

    /**
     * Log an API access event from middleware context.
     * Convenience method for requireApiAuth() integration.
     */
    public static function logApiAccess(array $session, string $result = self::RESULT_SUCCESS): void
    {
        $cuiAccessed = self::isCuiEndpoint();
        self::log(
            self::CAT_ACCESS,
            'api_request',
            $result,
            $session['user_id'] ?? null,
            [
                'method'  => $_SERVER['REQUEST_METHOD'] ?? 'unknown',
                'role'    => $session['role'] ?? 'unknown',
            ],
            $cuiAccessed,
            null, null,
            $session['instance_id'] ?? null
        );
    }

    /**
     * Log an authentication event.
     */
    public static function logAuth(
        string  $action,
        string  $result,
        ?string $userId = null,
        ?string $email = null,
        ?string $authSource = null,
        ?string $failureReason = null
    ): void {
        self::log(
            self::CAT_AUTH,
            $action,
            $result,
            $userId,
            array_filter([
                'email'          => $email,
                'auth_source'    => $authSource,
                'failure_reason' => $failureReason,
            ])
        );
    }

    /**
     * Log an admin action.
     */
    public static function logAdmin(
        string  $action,
        string  $result,
        ?string $userId,
        ?string $targetUserId = null,
        array   $details = []
    ): void {
        if ($targetUserId) {
            $details['target_user_id'] = $targetUserId;
        }
        self::log(self::CAT_ADMIN, $action, $result, $userId, $details);
    }

    /**
     * Log an AI chat event.
     */
    public static function logAI(
        string  $action,
        string  $result,
        ?string $userId,
        array   $details = [],
        bool    $cuiAccessed = true
    ): void {
        self::log(self::CAT_AI, $action, $result, $userId, $details, $cuiAccessed);
    }

    /**
     * Check if the current endpoint involves CUI.
     */
    private static function isCuiEndpoint(): bool
    {
        $uri = $_SERVER['REQUEST_URI'] ?? '';
        $cuiPaths = [
            '/api/ai_chat.php',
            '/api/stream.php',
            '/api/bearings',
            '/api/devices',
            '/api/measurements',
            '/api/alerts',
            '/api/reports',
            '/api/export',
        ];
        foreach ($cuiPaths as $path) {
            if (strpos($uri, $path) !== false) return true;
        }
        return false;
    }

    private static function getDb(): ?PDO
    {
        if (self::$db !== null) return self::$db;

        try {
            self::$db = new PDO(
                'pgsql:host=' . ($_ENV['DB_HOST'] ?? 'localhost') .
                ';dbname=' . ($_ENV['DB_NAME'] ?? 'eqmon'),
                $_ENV['DB_USER'] ?? 'eqmon',
                $_ENV['EQMON_AUTH_DB_PASS'] ?? $_ENV['DB_PASS'] ?? '',
                [
                    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                    PDO::ATTR_EMULATE_PREPARES => false,
                ]
            );
            return self::$db;
        } catch (PDOException $e) {
            self::$failed = true;
            openlog('eqmon-audit', LOG_PID, LOG_AUTH);
            syslog(LOG_CRIT, "AUDIT_DB_FAILURE: Cannot connect - " . $e->getMessage());
            closelog();
            return null;
        }
    }

    private static function getClientIp(): ?string
    {
        $ip = $_SERVER['HTTP_X_FORWARDED_FOR']
            ?? $_SERVER['HTTP_X_REAL_IP']
            ?? $_SERVER['REMOTE_ADDR']
            ?? null;
        if ($ip) {
            $ip = explode(',', $ip)[0];
            $ip = trim($ip);
        }
        return $ip;
    }

    private static function getUserAgent(): ?string
    {
        $ua = $_SERVER['HTTP_USER_AGENT'] ?? null;
        return $ua ? substr($ua, 0, 500) : null;
    }

    private static function getSessionId(): ?string
    {
        $cookie = $_COOKIE['eqmon_session'] ?? null;
        if (!$cookie) return null;
        // Return first 16 chars of JWT as session identifier (don't log full JWT)
        return substr($cookie, 0, 16) . '...';
    }

    private static function getResourceType(): ?string
    {
        $uri = $_SERVER['REQUEST_URI'] ?? null;
        if (!$uri) return null;
        // Strip query string and return path
        return strtok($uri, '?');
    }
}
```

---

## Step 2: Verify the class loads without errors

```bash
php -r "require '/var/www/html/eqmon/lib/AuditLogger.php'; echo 'OK';"
# Expected: OK
```

---

## Step 3: Write a quick integration test

```bash
php -r "
require '/var/www/html/eqmon/lib/AuditLogger.php';
\$_ENV['DB_HOST'] = 'localhost';
\$_ENV['DB_NAME'] = 'eqmon';
\$_ENV['DB_USER'] = 'eqmon';
\$_ENV['DB_PASS'] = '';
AuditLogger::log('system', 'test_event', 'success', null, ['test' => true]);
echo 'Logged OK\n';
"
```

Verify event exists:
```bash
sudo -u postgres psql -d eqmon -c "SELECT event_id, category, action, result FROM audit_events ORDER BY timestamp DESC LIMIT 1;"
```

---

## Step 4: Commit

```bash
cd /var/www/html/eqmon
git add lib/AuditLogger.php
git commit -m "feat: add AuditLogger for centralized audit logging (NIST 3.3.1, 3.3.2)"
```
