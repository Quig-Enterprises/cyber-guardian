<?php
/**
 * Scan Now API
 *
 * POST - Launch a red team scan in the background.
 *
 * Body:
 *   {
 *     "categories": ["api","web","infrastructure"],  // or ["all"]
 *     "target_id": 1                                 // optional, defaults to self
 *   }
 *
 * Returns: { "job_id": 42 }
 *
 * Auth: requires super admin.
 */

header('Content-Type: application/json');

$userId = $_SERVER['HTTP_X_AUTH_USER_ID'] ?? null;
if (!$userId) {
    http_response_code(401);
    echo json_encode(['error' => 'Unauthorized']);
    exit;
}

requireSuper();

require_once __DIR__ . '/lib/db.php';

// DELETE — stop a running scan
if ($_SERVER['REQUEST_METHOD'] === 'DELETE') {
    $pdo = getSecurityDb();
    $job = $pdo->query("SELECT job_id, pid FROM blueteam.scan_jobs WHERE status = 'running' ORDER BY job_id DESC LIMIT 1")->fetch();
    if (!$job) {
        http_response_code(404);
        echo json_encode(['error' => 'No running scan']);
        exit;
    }
    $pid = (int) $job['pid'];
    $killed = false;
    if ($pid > 0) {
        // Kill the process group to catch child processes
        shell_exec('kill -TERM -' . $pid . ' 2>/dev/null || kill -TERM ' . $pid . ' 2>/dev/null');
        usleep(300000);
        // SIGKILL if still alive
        if (file_exists('/proc/' . $pid)) {
            shell_exec('kill -KILL ' . $pid . ' 2>/dev/null');
        }
        $killed = true;
    }
    $pdo->prepare("UPDATE blueteam.scan_jobs SET status = 'cancelled', completed_at = NOW() WHERE job_id = :id")
        ->execute([':id' => $job['job_id']]);
    // Remove lock file so next scan can start
    @unlink('/tmp/redteam-runner.lock');
    echo json_encode(['stopped' => true, 'job_id' => (int) $job['job_id'], 'pid' => $pid, 'killed' => $killed]);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['error' => 'POST required']);
    exit;
}

$input = json_decode(file_get_contents('php://input'), true);
if (!$input) {
    http_response_code(400);
    echo json_encode(['error' => 'Invalid JSON']);
    exit;
}

$validCategories = ['all', 'ai', 'api', 'web', 'compliance', 'wordpress', 'cve',
                    'malware', 'infrastructure', 'dns', 'secrets', 'exposure', 'cloud'];

$requestedCategories = $input['categories'] ?? ['all'];
if (!is_array($requestedCategories) || empty($requestedCategories)) {
    http_response_code(400);
    echo json_encode(['error' => 'categories must be a non-empty array']);
    exit;
}

foreach ($requestedCategories as $cat) {
    if (!in_array($cat, $validCategories, true)) {
        http_response_code(400);
        echo json_encode(['error' => "Invalid category: $cat"]);
        exit;
    }
}

try {
    $pdo = getSecurityDb();

    // Prevent concurrent scans
    $running = $pdo->query("SELECT job_id FROM blueteam.scan_jobs WHERE status = 'running' LIMIT 1")->fetch();
    if ($running) {
        http_response_code(409);
        echo json_encode(['error' => 'A scan is already running', 'job_id' => (int) $running['job_id']]);
        exit;
    }

    // Resolve target
    $targetId = isset($input['target_id']) ? (int) $input['target_id'] : null;
    $targetUrl = null;
    $targetType = 'app';
    $originIp = null;
    $wpUser = null;
    $wpPass = null;

    if ($targetId !== null) {
        $stmt = $pdo->prepare("SELECT * FROM blueteam.redteam_targets WHERE target_id = :id AND enabled = TRUE");
        $stmt->execute([':id' => $targetId]);
        $target = $stmt->fetch(PDO::FETCH_ASSOC);
        if (!$target) {
            http_response_code(404);
            echo json_encode(['error' => 'Target not found or disabled']);
            exit;
        }
        $targetUrl  = $target['base_url'];
        $targetType = $target['target_type'];
        $originIp   = $target['origin_ip'];
        $wpUser     = $target['wp_user'];
        $wpPass     = $target['wp_pass_enc'] ? base64_decode($target['wp_pass_enc']) : null;
    } else {
        // Default to self target
        $self = $pdo->query("SELECT * FROM blueteam.redteam_targets WHERE is_self = TRUE LIMIT 1")->fetch(PDO::FETCH_ASSOC);
        if ($self) {
            $targetId   = (int) $self['target_id'];
            $targetUrl  = $self['base_url'];
            $targetType = $self['target_type'];
        }
    }

    $categoriesStr = implode(',', $requestedCategories);
    $logDir = '/opt/claude-workspace/projects/cyber-guardian/logs';
    $logFile = $logDir . '/scan-' . date('Ymd_His') . '-job.log';

    // Insert job record first to get job_id
    $stmt = $pdo->prepare("
        INSERT INTO blueteam.scan_jobs (status, categories, target_id, target_url, log_file, initiated_by)
        VALUES ('running', :cats, :tid, :turl, :log, :uid)
        RETURNING job_id
    ");
    $stmt->execute([
        ':cats' => $categoriesStr,
        ':tid'  => $targetId,
        ':turl' => $targetUrl,
        ':log'  => $logFile,
        ':uid'  => (int) $userId,
    ]);
    $jobId = (int) $stmt->fetch(PDO::FETCH_ASSOC)['job_id'];

    // Build the runner script path
    $runScript = '/opt/claude-workspace/projects/cyber-guardian/bin/run-redteam.sh';

    // Build runner args
    $args = [];
    if (count($requestedCategories) === 1 && $requestedCategories[0] === 'all') {
        $args[] = '--all';
    } else {
        foreach ($requestedCategories as $cat) {
            $args[] = '--category ' . escapeshellarg($cat);
        }
    }
    if ($targetUrl !== null) {
        $args[] = '--url ' . escapeshellarg($targetUrl);
    }
    if ($targetType !== 'app') {
        $args[] = '--target ' . escapeshellarg($targetType);
    }
    if ($originIp !== null && $originIp !== '') {
        $args[] = '--origin-ip ' . escapeshellarg($originIp);
    }
    if ($wpUser !== null && $wpUser !== '') {
        $args[] = '--wp-user ' . escapeshellarg($wpUser);
    }
    if ($wpPass !== null && $wpPass !== '') {
        $args[] = '--wp-pass ' . escapeshellarg($wpPass);
    }
    $args[] = '--job-id ' . escapeshellarg((string) $jobId);

    // Launch in background — the wrapper script updates DB on completion.
    // Write PID to a temp file because shell_exec() doesn't reliably return $! output.
    $argsStr = implode(' ', $args);
    $wrapScript = '/opt/claude-workspace/projects/cyber-guardian/bin/scan-job-wrapper.sh';
    $pidFile = '/tmp/scan-job-' . $jobId . '.pid';
    $cmd = 'nohup bash ' . escapeshellarg($wrapScript) . ' '
         . escapeshellarg((string) $jobId) . ' '
         . escapeshellarg($logFile) . ' '
         . $argsStr
         . ' > ' . escapeshellarg($logFile) . ' 2>&1 & echo $! > ' . escapeshellarg($pidFile);

    shell_exec($cmd);

    // Give the shell a moment to write the PID file, then read it
    usleep(200000);
    $pid = 0;
    if (file_exists($pidFile)) {
        $pid = (int) trim(file_get_contents($pidFile));
        unlink($pidFile);
    }

    if ($pid > 0) {
        $pdo->prepare("UPDATE blueteam.scan_jobs SET pid = :pid WHERE job_id = :id")
            ->execute([':pid' => $pid, ':id' => $jobId]);
    }

    echo json_encode(['job_id' => $jobId, 'pid' => $pid]);

} catch (PDOException $e) {
    http_response_code(500);
    error_log('scan-now.php DB error: ' . $e->getMessage());
    echo json_encode(['error' => 'Database error']);
}

function requireSuper(): void
{
    $authHeader = $_SERVER['HTTP_AUTH'] ?? '';
    if ($authHeader) {
        $session = json_decode($authHeader, true);
        if (!empty($session['super'])) return;
    }
    $superHeader = $_SERVER['HTTP_X_AUTH_SUPER'] ?? '';
    if ($superHeader === 'true' || $superHeader === '1') return;

    http_response_code(403);
    echo json_encode(['error' => 'Super admin access required']);
    exit;
}
