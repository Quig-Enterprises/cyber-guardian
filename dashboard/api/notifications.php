<?php
/**
 * Notification Subscription API
 *
 * GET    - Get current user's subscription + last 20 notification history entries
 * POST   - Upsert subscription (INSERT ON CONFLICT UPDATE)
 * DELETE - Remove subscription
 *
 * Auth: Requires X-Auth-User-Id header (any authenticated user can manage own subscription)
 */

header('Content-Type: application/json');

$userId = $_SERVER['HTTP_X_AUTH_USER_ID'] ?? null;
if (!$userId) {
    http_response_code(401);
    echo json_encode(['error' => 'Unauthorized']);
    exit;
}
$userId = (int) $userId;

require_once __DIR__ . '/lib/db.php';

$method = $_SERVER['REQUEST_METHOD'];

try {
    $pdo = getSecurityDb();

    switch ($method) {
        case 'GET':
            handleGet($pdo, $userId);
            break;
        case 'POST':
            handlePost($pdo, $userId);
            break;
        case 'DELETE':
            handleDelete($pdo, $userId);
            break;
        default:
            http_response_code(405);
            echo json_encode(['error' => 'Method not allowed']);
    }
} catch (PDOException $e) {
    http_response_code(500);
    error_log("Notifications API Error: " . $e->getMessage());
    echo json_encode(['error' => 'Database error']);
}

function handleGet(PDO $pdo, int $userId): void
{
    // Get subscription
    $stmt = $pdo->prepare("
        SELECT * FROM blueteam.notification_subscriptions WHERE user_id = :uid
    ");
    $stmt->execute([':uid' => $userId]);
    $sub = $stmt->fetch(PDO::FETCH_ASSOC);

    if ($sub) {
        // Cast booleans
        foreach ($sub as $key => &$val) {
            if (in_array($key, ['enabled','cat_ai','cat_api','cat_web','cat_compliance',
                'notify_vulnerable','notify_partial','notify_defended','notify_error','emergency_alerts'])) {
                $val = (bool) $val;
            }
        }
        unset($val);
        $sub['subscription_id'] = (int) $sub['subscription_id'];
        $sub['user_id'] = (int) $sub['user_id'];
    }

    // Get last 20 notification history entries
    $stmt2 = $pdo->prepare("
        SELECT notification_id, scan_timestamp, finding_fingerprint, finding_severity,
               finding_status, finding_category, finding_attack, finding_variant,
               email_subject, is_emergency, delivery_status, sent_at, created_at
        FROM blueteam.notification_history
        WHERE user_id = :uid
        ORDER BY created_at DESC
        LIMIT 20
    ");
    $stmt2->execute([':uid' => $userId]);
    $history = $stmt2->fetchAll(PDO::FETCH_ASSOC);

    foreach ($history as &$h) {
        $h['notification_id'] = (int) $h['notification_id'];
        $h['is_emergency'] = (bool) $h['is_emergency'];
    }
    unset($h);

    echo json_encode([
        'subscription' => $sub ?: null,
        'history' => $history,
    ]);
}

function handlePost(PDO $pdo, int $userId): void
{
    $input = json_decode(file_get_contents('php://input'), true);
    if (!$input) {
        http_response_code(400);
        echo json_encode(['error' => 'Invalid JSON body']);
        return;
    }

    // Get user email/name from headers (set by JS from AUTH object)
    $userEmail = $_SERVER['HTTP_X_AUTH_EMAIL'] ?? '';
    $userName  = $_SERVER['HTTP_X_AUTH_NAME'] ?? '';

    if (empty($userEmail)) {
        http_response_code(400);
        echo json_encode(['error' => 'X-Auth-Email header required']);
        return;
    }

    // Validate min_severity
    $validSeverities = ['info', 'low', 'medium', 'high', 'critical'];
    $minSeverity = strtolower($input['min_severity'] ?? 'medium');
    if (!in_array($minSeverity, $validSeverities)) {
        $minSeverity = 'medium';
    }

    // Validate dedup_mode
    $dedupMode = $input['dedup_mode'] ?? 'first_only';
    if (!in_array($dedupMode, ['first_only', 'every_scan'])) {
        $dedupMode = 'first_only';
    }

    $stmt = $pdo->prepare("
        INSERT INTO blueteam.notification_subscriptions
            (user_id, user_email, user_name, enabled, cat_ai, cat_api, cat_web, cat_compliance,
             min_severity, dedup_mode, notify_vulnerable, notify_partial, notify_defended,
             notify_error, emergency_alerts)
        VALUES
            (:user_id, :email, :name, :enabled, :cat_ai, :cat_api, :cat_web, :cat_compliance,
             :min_severity, :dedup_mode, :notify_vulnerable, :notify_partial, :notify_defended,
             :notify_error, :emergency_alerts)
        ON CONFLICT (user_id) DO UPDATE SET
            user_email = EXCLUDED.user_email,
            user_name = EXCLUDED.user_name,
            enabled = EXCLUDED.enabled,
            cat_ai = EXCLUDED.cat_ai,
            cat_api = EXCLUDED.cat_api,
            cat_web = EXCLUDED.cat_web,
            cat_compliance = EXCLUDED.cat_compliance,
            min_severity = EXCLUDED.min_severity,
            dedup_mode = EXCLUDED.dedup_mode,
            notify_vulnerable = EXCLUDED.notify_vulnerable,
            notify_partial = EXCLUDED.notify_partial,
            notify_defended = EXCLUDED.notify_defended,
            notify_error = EXCLUDED.notify_error,
            emergency_alerts = EXCLUDED.emergency_alerts,
            updated_at = NOW()
        RETURNING subscription_id
    ");

    $boolVal = fn($key, $default = true) => !empty($input[$key]) || (!isset($input[$key]) && $default) ? 'true' : 'false';

    $stmt->execute([
        ':user_id'           => $userId,
        ':email'             => $userEmail,
        ':name'              => $userName,
        ':enabled'           => isset($input['enabled']) ? ($input['enabled'] ? 'true' : 'false') : 'true',
        ':cat_ai'            => $boolVal('cat_ai', true),
        ':cat_api'           => $boolVal('cat_api', true),
        ':cat_web'           => $boolVal('cat_web', true),
        ':cat_compliance'    => $boolVal('cat_compliance', true),
        ':min_severity'      => $minSeverity,
        ':dedup_mode'        => $dedupMode,
        ':notify_vulnerable' => $boolVal('notify_vulnerable', true),
        ':notify_partial'    => $boolVal('notify_partial', true),
        ':notify_defended'   => $boolVal('notify_defended', false),
        ':notify_error'      => $boolVal('notify_error', false),
        ':emergency_alerts'  => $boolVal('emergency_alerts', true),
    ]);

    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    echo json_encode(['success' => true, 'subscription_id' => (int) $row['subscription_id']]);
}

function handleDelete(PDO $pdo, int $userId): void
{
    $stmt = $pdo->prepare("DELETE FROM blueteam.notification_subscriptions WHERE user_id = :uid");
    $stmt->execute([':uid' => $userId]);

    echo json_encode(['success' => true, 'deleted' => $stmt->rowCount() > 0]);
}
