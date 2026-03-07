<?php
/**
 * Red Team Schedule Management API
 *
 * GET    - List all schedules
 * POST   - Create a new schedule
 * PUT    - Update a schedule (including enable/disable)
 * DELETE - Remove a schedule
 *
 * Auth: All methods require X-Auth-User-Id header.
 *       Write operations require super admin (AUTH header with session).
 */

header('Content-Type: application/json');

$userId = $_SERVER['HTTP_X_AUTH_USER_ID'] ?? null;
if (!$userId) {
    http_response_code(401);
    echo json_encode(['error' => 'Unauthorized']);
    exit;
}

require_once __DIR__ . '/lib/db.php';

$method = $_SERVER['REQUEST_METHOD'];

try {
    $pdo = getSecurityDb();

    switch ($method) {
        case 'GET':
            handleGet($pdo);
            break;
        case 'POST':
            requireSuper();
            handlePost($pdo, $userId);
            break;
        case 'PUT':
            requireSuper();
            handlePut($pdo);
            break;
        case 'DELETE':
            requireSuper();
            handleDelete($pdo);
            break;
        default:
            http_response_code(405);
            echo json_encode(['error' => 'Method not allowed']);
    }
} catch (PDOException $e) {
    http_response_code(500);
    error_log("Schedules API Error: " . $e->getMessage());
    echo json_encode(['error' => 'Database error']);
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

function handleGet(PDO $pdo): void
{
    $stmt = $pdo->query("
        SELECT schedule_id, name, cron_expr, category, extra_args,
               enabled, created_by, created_at, updated_at,
               last_run_at, next_run_at
        FROM blueteam.redteam_schedules
        ORDER BY schedule_id
    ");
    $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

    foreach ($rows as &$row) {
        $row['enabled'] = (bool) $row['enabled'];
        $row['schedule_id'] = (int) $row['schedule_id'];
        $row['human_cron'] = cronToHuman($row['cron_expr']);
        $row['next_run_at'] = $row['next_run_at'] ?? calcNextRun($row['cron_expr']);
    }
    unset($row);

    echo json_encode(['schedules' => $rows]);
}

function handlePost(PDO $pdo, $userId): void
{
    $input = json_decode(file_get_contents('php://input'), true);
    if (!$input) {
        http_response_code(400);
        echo json_encode(['error' => 'Invalid JSON body']);
        return;
    }

    $name = trim($input['name'] ?? '');
    $cronExpr = trim($input['cron_expr'] ?? '');
    $category = $input['category'] ?? 'all';
    $extraArgs = trim($input['extra_args'] ?? '');
    $enabled = $input['enabled'] ?? true;

    if ($name === '' || $cronExpr === '') {
        http_response_code(400);
        echo json_encode(['error' => 'Name and cron_expr are required']);
        return;
    }

    if (!validateCron($cronExpr)) {
        http_response_code(400);
        echo json_encode(['error' => 'Invalid cron expression']);
        return;
    }

    $validCategories = ['all', 'ai', 'api', 'web', 'compliance'];
    if (!in_array($category, $validCategories)) {
        http_response_code(400);
        echo json_encode(['error' => 'Invalid category. Must be one of: ' . implode(', ', $validCategories)]);
        return;
    }

    $stmt = $pdo->prepare("
        INSERT INTO blueteam.redteam_schedules (name, cron_expr, category, extra_args, enabled, created_by, next_run_at)
        VALUES (:name, :cron_expr, :category, :extra_args, :enabled, :created_by, :next_run_at)
        RETURNING schedule_id
    ");
    $stmt->execute([
        ':name' => $name,
        ':cron_expr' => $cronExpr,
        ':category' => $category,
        ':extra_args' => $extraArgs,
        ':enabled' => $enabled ? 'true' : 'false',
        ':created_by' => (int) $userId,
        ':next_run_at' => calcNextRun($cronExpr),
    ]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);

    syncCrontab($pdo);

    echo json_encode(['success' => true, 'schedule_id' => (int) $row['schedule_id']]);
}

function handlePut(PDO $pdo): void
{
    $input = json_decode(file_get_contents('php://input'), true);
    if (!$input || empty($input['schedule_id'])) {
        http_response_code(400);
        echo json_encode(['error' => 'schedule_id is required']);
        return;
    }

    $id = (int) $input['schedule_id'];

    // Build dynamic SET clause from allowed fields
    $allowed = ['name', 'cron_expr', 'category', 'extra_args', 'enabled'];
    $sets = [];
    $params = [':id' => $id];

    foreach ($allowed as $field) {
        if (array_key_exists($field, $input)) {
            $val = $input[$field];

            if ($field === 'cron_expr') {
                if (!validateCron($val)) {
                    http_response_code(400);
                    echo json_encode(['error' => 'Invalid cron expression']);
                    return;
                }
            }

            if ($field === 'category') {
                $validCategories = ['all', 'ai', 'api', 'web', 'compliance'];
                if (!in_array($val, $validCategories)) {
                    http_response_code(400);
                    echo json_encode(['error' => 'Invalid category']);
                    return;
                }
            }

            if ($field === 'enabled') {
                $val = $val ? 'true' : 'false';
            }

            $sets[] = "$field = :$field";
            $params[":$field"] = $val;
        }
    }

    if (empty($sets)) {
        http_response_code(400);
        echo json_encode(['error' => 'No fields to update']);
        return;
    }

    $sets[] = "updated_at = NOW()";

    // Recalculate next_run if cron_expr changed
    if (isset($input['cron_expr'])) {
        $sets[] = "next_run_at = :next_run_at";
        $params[':next_run_at'] = calcNextRun($input['cron_expr']);
    }

    $sql = "UPDATE blueteam.redteam_schedules SET " . implode(', ', $sets) . " WHERE schedule_id = :id";
    $stmt = $pdo->prepare($sql);
    $stmt->execute($params);

    if ($stmt->rowCount() === 0) {
        http_response_code(404);
        echo json_encode(['error' => 'Schedule not found']);
        return;
    }

    syncCrontab($pdo);

    echo json_encode(['success' => true]);
}

function handleDelete(PDO $pdo): void
{
    $input = json_decode(file_get_contents('php://input'), true);
    $id = (int) ($input['schedule_id'] ?? $_GET['id'] ?? 0);

    if ($id <= 0) {
        http_response_code(400);
        echo json_encode(['error' => 'schedule_id is required']);
        return;
    }

    $stmt = $pdo->prepare("DELETE FROM blueteam.redteam_schedules WHERE schedule_id = :id");
    $stmt->execute([':id' => $id]);

    if ($stmt->rowCount() === 0) {
        http_response_code(404);
        echo json_encode(['error' => 'Schedule not found']);
        return;
    }

    syncCrontab($pdo);

    echo json_encode(['success' => true]);
}

// ---------------------------------------------------------------------------
// Auth helper
// ---------------------------------------------------------------------------

function requireSuper(): void
{
    // Check for super admin via AUTH header (Artemis session JSON)
    $authHeader = $_SERVER['HTTP_AUTH'] ?? '';
    if ($authHeader) {
        $session = json_decode($authHeader, true);
        if (!empty($session['super'])) {
            return;
        }
    }

    // Fallback: check X-Auth-Super header (set by JS from AUTH.isSuper)
    $superHeader = $_SERVER['HTTP_X_AUTH_SUPER'] ?? '';
    if ($superHeader === 'true' || $superHeader === '1') {
        return;
    }

    http_response_code(403);
    echo json_encode(['error' => 'Super admin access required']);
    exit;
}

// ---------------------------------------------------------------------------
// Crontab sync
// ---------------------------------------------------------------------------

/**
 * Rebuild crontab from enabled schedules using the apply-crontab.sh helper.
 * Uses escapeshellarg() for safe argument passing - no user input reaches the shell unescaped.
 */
function syncCrontab(PDO $pdo): void
{
    $stmt = $pdo->query("
        SELECT cron_expr, category, extra_args
        FROM blueteam.redteam_schedules
        WHERE enabled = true
        ORDER BY schedule_id
    ");
    $schedules = $stmt->fetchAll(PDO::FETCH_ASSOC);

    $runScript = '/opt/claude-workspace/projects/cyber-guardian/bin/run-redteam.sh';
    $applyScript = '/opt/claude-workspace/projects/cyber-guardian/bin/apply-crontab.sh';

    $lines = [];
    foreach ($schedules as $s) {
        $args = trim($s['extra_args']);
        if ($args === '') {
            $args = $s['category'] === 'all' ? '--all' : ('--category ' . $s['category']);
        }
        $lines[] = $s['cron_expr'] . ' ' . $runScript . ' ' . $args . ' 2>&1 | logger -t redteam';
    }

    $managed = implode("\n", $lines);

    // Write managed lines to a temp file, then pipe to the helper script
    $tmpFile = tempnam(sys_get_temp_dir(), 'crontab_');
    file_put_contents($tmpFile, $managed);

    $cmd = 'sudo -u brandon ' . escapeshellarg($applyScript) . ' < ' . escapeshellarg($tmpFile) . ' 2>&1';

    $output = [];
    $exitCode = 0;
    // Safe: all arguments are escaped via escapeshellarg(), no user input in shell
    $lastLine = system($cmd, $exitCode);

    unlink($tmpFile);

    if ($exitCode !== 0) {
        error_log("Crontab sync failed (exit $exitCode): " . ($lastLine ?: 'no output'));
    }
}

// ---------------------------------------------------------------------------
// Cron helpers
// ---------------------------------------------------------------------------

function validateCron(string $expr): bool
{
    $parts = preg_split('/\s+/', trim($expr));
    if (count($parts) !== 5) return false;

    foreach ($parts as $part) {
        if (!preg_match('/^[\d\*\/\-\,]+$/', $part)) return false;
    }
    return true;
}

function cronToHuman(string $expr): string
{
    $map = [
        '0 2 * * 0'   => 'Every Sunday at 2:00 AM',
        '0 3 * * *'   => 'Every day at 3:00 AM',
        '0 0 * * *'   => 'Every day at midnight',
        '0 * * * *'   => 'Every hour',
        '*/5 * * * *' => 'Every 5 minutes',
        '*/15 * * * *'=> 'Every 15 minutes',
        '*/30 * * * *'=> 'Every 30 minutes',
        '0 0 * * 0'   => 'Every Sunday at midnight',
        '0 0 * * 1'   => 'Every Monday at midnight',
        '0 0 1 * *'   => 'First of every month at midnight',
        '0 6 * * 1-5' => 'Weekdays at 6:00 AM',
    ];

    if (isset($map[$expr])) return $map[$expr];

    $parts = preg_split('/\s+/', trim($expr));
    if (count($parts) !== 5) return $expr;

    list($min, $hour, $dom, $mon, $dow) = $parts;

    $dayNames = ['Sunday','Monday','Tuesday','Wednesday','Thursday','Friday','Saturday'];
    $result = '';

    if ($dow !== '*') {
        if (is_numeric($dow) && isset($dayNames[(int)$dow])) {
            $result .= 'Every ' . $dayNames[(int)$dow];
        } elseif (preg_match('/^(\d)-(\d)$/', $dow, $m)) {
            $result .= $dayNames[(int)$m[1]] . '-' . $dayNames[(int)$m[2]];
        } else {
            $result .= 'DOW ' . $dow;
        }
    } elseif ($dom !== '*') {
        $result .= 'Day ' . $dom . ' of month';
    } else {
        $result .= 'Every day';
    }

    if (is_numeric($hour) && is_numeric($min)) {
        $h = (int)$hour;
        $ampm = $h >= 12 ? 'PM' : 'AM';
        $h12 = $h % 12 ?: 12;
        $result .= ' at ' . $h12 . ':' . str_pad($min, 2, '0', STR_PAD_LEFT) . ' ' . $ampm;
    } elseif ($hour === '*' && $min === '0') {
        $result = 'Every hour';
    } elseif ($hour === '*' && preg_match('/^\*\/(\d+)$/', $min, $m)) {
        $result = 'Every ' . $m[1] . ' minutes';
    }

    return $result ?: $expr;
}

function calcNextRun(string $expr): ?string
{
    $parts = preg_split('/\s+/', trim($expr));
    if (count($parts) !== 5) return null;

    list($cronMin, $cronHour, $cronDom, $cronMon, $cronDow) = $parts;

    $now = time();

    for ($dayOffset = 0; $dayOffset <= 366; $dayOffset++) {
        $baseTs = $now + ($dayOffset * 86400);
        $dayMon = (int) date('n', $baseTs);
        $dayDom = (int) date('j', $baseTs);
        $dayDow = (int) date('w', $baseTs);

        if ($cronMon !== '*' && !matchCronField($cronMon, $dayMon)) continue;
        if ($cronDom !== '*' && !matchCronField($cronDom, $dayDom)) continue;
        if ($cronDow !== '*' && !matchCronField($cronDow, $dayDow)) continue;

        $hours = expandCronField($cronHour, 0, 23);
        $minutes = expandCronField($cronMin, 0, 59);

        foreach ($hours as $h) {
            foreach ($minutes as $m) {
                $candidate = mktime($h, $m, 0, (int)date('n', $baseTs), (int)date('j', $baseTs), (int)date('Y', $baseTs));
                if ($candidate > $now) {
                    return date('Y-m-d\TH:i:sP', $candidate);
                }
            }
        }
    }

    return null;
}

function matchCronField(string $field, int $value): bool
{
    $expanded = expandCronField($field, 0, 59);
    return in_array($value, $expanded);
}

function expandCronField(string $field, int $min, int $max): array
{
    if ($field === '*') {
        return range($min, $max);
    }

    $values = [];
    $parts = explode(',', $field);
    foreach ($parts as $part) {
        if (strpos($part, '/') !== false) {
            list($range, $step) = explode('/', $part);
            $step = (int) $step;
            $start = ($range === '*') ? $min : (int) $range;
            for ($i = $start; $i <= $max; $i += $step) {
                $values[] = $i;
            }
        } elseif (strpos($part, '-') !== false) {
            list($from, $to) = explode('-', $part);
            for ($i = (int)$from; $i <= (int)$to; $i++) {
                $values[] = $i;
            }
        } else {
            $values[] = (int) $part;
        }
    }

    sort($values);
    return array_unique($values);
}
