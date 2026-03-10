<?php
/**
 * Lynis Schedule Management API
 *
 * Endpoints:
 * - GET /schedule - Get current cron schedule
 * - POST /schedule - Update cron schedule
 * - POST /run-now - Trigger immediate audit
 * - GET /status - Get last audit status
 */

header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, X-Auth-User-ID');

// Handle preflight OPTIONS request
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

// Authentication check (expects X-Auth-User-ID header from Keystone)
$userId = $_SERVER['HTTP_X_AUTH_USER_ID'] ?? null;
if (!$userId) {
    http_response_code(401);
    echo json_encode(['error' => 'Unauthorized - X-Auth-User-ID header required']);
    exit;
}

// Database connection to eqmon database (where Lynis data is stored)
function getEqmonDb(): PDO {
    static $pdo = null;
    if ($pdo === null) {
        $host = '127.0.0.1';
        $user = 'eqmon';
        $pass = 'Mtd2l6LXNlcnAiF25vZGVyZ'; // From lynis-auditor.py
        $db   = 'eqmon';
        $pdo = new PDO(
            "pgsql:host={$host};dbname={$db}",
            $user,
            $pass,
            [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES => false
            ]
        );
    }
    return $pdo;
}

try {
    $pdo = getEqmonDb();
} catch (PDOException $e) {
    http_response_code(500);
    echo json_encode(['error' => 'Database connection failed: ' . $e->getMessage()]);
    exit;
}

// Route request
$method = $_SERVER['REQUEST_METHOD'];
$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);

try {
    if ($method === 'GET' && strpos($path, '/schedule') !== false) {
        handleGetSchedule();
    } elseif ($method === 'POST' && strpos($path, '/schedule') !== false) {
        handleUpdateSchedule();
    } elseif ($method === 'POST' && strpos($path, '/run-now') !== false) {
        handleRunNow();
    } elseif ($method === 'GET' && strpos($path, '/status') !== false) {
        handleGetStatus($pdo);
    } else {
        http_response_code(404);
        echo json_encode(['error' => 'Endpoint not found']);
    }
} catch (Exception $e) {
    http_response_code(500);
    echo json_encode(['error' => $e->getMessage()]);
}

/**
 * Get current Lynis cron schedule
 */
function handleGetSchedule() {
    // Get current crontab
    exec('crontab -l 2>&1', $output, $returnCode);

    if ($returnCode !== 0) {
        throw new Exception('Failed to read crontab');
    }

    // Find Lynis cron line
    $lynisLine = null;
    foreach ($output as $line) {
        if (strpos($line, 'weekly-audit-cron.sh') !== false) {
            $lynisLine = $line;
            break;
        }
    }

    if (!$lynisLine) {
        echo json_encode([
            'enabled' => false,
            'schedule' => null,
            'message' => 'Lynis cron job not found'
        ]);
        return;
    }

    // Parse cron expression
    $parts = preg_split('/\s+/', trim($lynisLine), 6);
    if (count($parts) < 5) {
        throw new Exception('Invalid cron format');
    }

    list($minute, $hour, $dom, $month, $dow) = $parts;

    // Determine frequency
    $frequency = 'custom';
    if ($dom === '*' && $month === '*') {
        if ($dow === '0') {
            $frequency = 'weekly';
        } elseif ($dow === '*') {
            $frequency = 'daily';
        }
    } elseif ($dom === '1' && $month === '*' && $dow === '*') {
        $frequency = 'monthly';
    }

    echo json_encode([
        'enabled' => true,
        'frequency' => $frequency,
        'time' => sprintf('%02d:%02d', (int)$hour, (int)$minute),
        'day_of_week' => $dow,
        'day_of_month' => $dom,
        'cron_expression' => "$minute $hour $dom $month $dow",
        'raw_line' => $lynisLine
    ]);
}

/**
 * Update Lynis cron schedule
 */
function handleUpdateSchedule() {
    $input = json_decode(file_get_contents('php://input'), true);

    if (!$input) {
        http_response_code(400);
        echo json_encode(['error' => 'Invalid JSON']);
        return;
    }

    // Validate input
    $frequency = $input['frequency'] ?? null;
    $time = $input['time'] ?? '02:00';

    if (!in_array($frequency, ['daily', 'weekly', 'monthly', 'disabled'])) {
        http_response_code(400);
        echo json_encode(['error' => 'Invalid frequency. Must be: daily, weekly, monthly, or disabled']);
        return;
    }

    // Parse time
    if (!preg_match('/^(\d{1,2}):(\d{2})$/', $time, $matches)) {
        http_response_code(400);
        echo json_encode(['error' => 'Invalid time format. Use HH:MM']);
        return;
    }

    $hour = (int)$matches[1];
    $minute = (int)$matches[2];

    if ($hour < 0 || $hour > 23 || $minute < 0 || $minute > 59) {
        http_response_code(400);
        echo json_encode(['error' => 'Invalid time. Hour: 0-23, Minute: 0-59']);
        return;
    }

    // Get current crontab
    exec('crontab -l 2>&1', $output, $returnCode);
    if ($returnCode !== 0 && $returnCode !== 1) { // 1 = no crontab
        throw new Exception('Failed to read crontab');
    }

    // Build new cron expression
    $scriptPath = '/opt/claude-workspace/projects/cyber-guardian/scripts/weekly-audit-cron.sh';
    $logPath = '/var/log/cyber-guardian/cron.log';

    if ($frequency === 'disabled') {
        $newCronLine = null; // Will remove the line
    } else {
        switch ($frequency) {
            case 'daily':
                $cronExpr = "$minute $hour * * *";
                break;
            case 'weekly':
                $cronExpr = "$minute $hour * * 0"; // Sunday
                break;
            case 'monthly':
                $cronExpr = "$minute $hour 1 * *"; // First of month
                break;
        }

        $newCronLine = "$cronExpr $scriptPath >> $logPath 2>&1";
    }

    // Remove old Lynis line and add new one
    $newCrontab = [];
    $found = false;

    foreach ($output as $line) {
        if (strpos($line, 'weekly-audit-cron.sh') !== false) {
            if ($newCronLine !== null) {
                $newCrontab[] = "# Weekly Lynis security audits";
                $newCrontab[] = $newCronLine;
            }
            $found = true;
        } else {
            $newCrontab[] = $line;
        }
    }

    // If not found and not disabling, add new line
    if (!$found && $newCronLine !== null) {
        $newCrontab[] = "# Weekly Lynis security audits";
        $newCrontab[] = $newCronLine;
    }

    // Write new crontab
    $tempFile = tempnam(sys_get_temp_dir(), 'cron');
    file_put_contents($tempFile, implode("\n", $newCrontab) . "\n");

    exec("crontab $tempFile 2>&1", $installOutput, $installCode);
    unlink($tempFile);

    if ($installCode !== 0) {
        throw new Exception('Failed to update crontab: ' . implode("\n", $installOutput));
    }

    echo json_encode([
        'success' => true,
        'message' => $frequency === 'disabled'
            ? 'Lynis automated scanning disabled'
            : "Schedule updated to $frequency at $time",
        'frequency' => $frequency,
        'time' => $time,
        'cron_expression' => $newCronLine
    ]);
}

/**
 * Trigger immediate audit
 */
function handleRunNow() {
    $scriptPath = '/opt/claude-workspace/projects/cyber-guardian/scripts/audit-all-servers.sh';
    $logPath = '/var/log/cyber-guardian/manual-audit-' . date('YmdHis') . '.log';

    // Run in background
    $cmd = "nohup bash $scriptPath > $logPath 2>&1 &";
    exec($cmd, $output, $returnCode);

    echo json_encode([
        'success' => true,
        'message' => 'Audit started in background',
        'log_file' => $logPath,
        'started_at' => date('Y-m-d H:i:s')
    ]);
}

/**
 * Get last audit status
 */
function handleGetStatus($pdo) {
    // Get latest audit from database
    $stmt = $pdo->query("
        SELECT
            server_name,
            audit_date,
            hardening_index,
            tests_performed,
            warnings_count,
            suggestions_count
        FROM blueteam.lynis_audits
        ORDER BY audit_date DESC
        LIMIT 10
    ");

    $audits = $stmt->fetchAll();

    // Get security posture
    $stmt = $pdo->query("
        SELECT
            server_name,
            compliance_score,
            lynis_hardening,
            combined_score
        FROM blueteam.v_security_posture
        ORDER BY server_name
    ");

    $posture = $stmt->fetchAll();

    // Get most recent log file
    $logFiles = glob('/var/log/cyber-guardian/lynis-weekly-*.log');
    rsort($logFiles);
    $lastLogFile = $logFiles[0] ?? null;

    $lastRunTime = null;
    if ($lastLogFile) {
        $lastRunTime = date('Y-m-d H:i:s', filemtime($lastLogFile));
    }

    echo json_encode([
        'last_run' => $lastRunTime,
        'recent_audits' => $audits,
        'security_posture' => $posture,
        'log_file' => $lastLogFile
    ]);
}
