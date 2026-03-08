<?php
/**
 * Scan Job Status API
 *
 * GET ?job_id=42          - Status of specific job
 * GET ?latest=1           - Status of most recent job
 *
 * Returns:
 *   {
 *     "job_id": 42,
 *     "status": "running"|"done"|"failed",
 *     "categories": "api,web",
 *     "target_url": "http://...",
 *     "started_at": "...",
 *     "finished_at": "...",
 *     "exit_code": 0,
 *     "report_json": "redteam-report-20260307_183000.json",
 *     "log_tail": "last 30 lines of log"
 *   }
 */

header('Content-Type: application/json');

$userId = $_SERVER['HTTP_X_AUTH_USER_ID'] ?? null;
if (!$userId) {
    http_response_code(401);
    echo json_encode(['error' => 'Unauthorized']);
    exit;
}

require_once __DIR__ . '/lib/db.php';

try {
    $pdo = getSecurityDb();

    if (isset($_GET['job_id'])) {
        $jobId = (int) $_GET['job_id'];
        $stmt = $pdo->prepare("SELECT * FROM blueteam.scan_jobs WHERE job_id = :id");
        $stmt->execute([':id' => $jobId]);
        $job = $stmt->fetch(PDO::FETCH_ASSOC);
        if (!$job) {
            http_response_code(404);
            echo json_encode(['error' => 'Job not found']);
            exit;
        }
    } elseif (isset($_GET['latest'])) {
        $job = $pdo->query("SELECT * FROM blueteam.scan_jobs ORDER BY job_id DESC LIMIT 1")->fetch(PDO::FETCH_ASSOC);
        if (!$job) {
            echo json_encode(['job_id' => null, 'status' => 'none']);
            exit;
        }
    } else {
        http_response_code(400);
        echo json_encode(['error' => 'job_id or latest parameter required']);
        exit;
    }

    // Detect stale "running" jobs — only after 5 minutes with no DB update from wrapper.
    // The PID stored is the nohup shell which exits immediately; the actual scan process
    // is a child. We rely on the wrapper to update status when done. Only mark as failed
    // if the job has been "running" for > 5 minutes with no finished_at (true hung/crashed).
    if ($job['status'] === 'running') {
        $startedAt = strtotime($job['started_at']);
        $ageSeconds = time() - $startedAt;
        if ($ageSeconds > 300) {
            // Check if the lock file still exists (runner holds it while running)
            $lockFile = '/tmp/redteam-runner.lock';
            if (!file_exists($lockFile)) {
                $pdo->prepare("UPDATE blueteam.scan_jobs SET status='failed', finished_at=NOW(), exit_code=255 WHERE job_id=:id")
                    ->execute([':id' => $job['job_id']]);
                $job['status'] = 'failed';
                $job['exit_code'] = 255;
            }
        }
    }

    // Append log tail if log file exists
    $logTail = null;
    if (!empty($job['log_file']) && is_readable($job['log_file'])) {
        $lines = file($job['log_file'], FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        $tail = array_slice($lines, -30);
        $logTail = implode("\n", $tail);
    }

    echo json_encode([
        'job_id'      => (int) $job['job_id'],
        'status'      => $job['status'],
        'categories'  => $job['categories'],
        'target_id'   => $job['target_id'] ? (int) $job['target_id'] : null,
        'target_url'  => $job['target_url'],
        'pid'         => $job['pid'] ? (int) $job['pid'] : null,
        'started_at'  => $job['started_at'],
        'finished_at' => $job['finished_at'],
        'exit_code'   => $job['exit_code'] !== null ? (int) $job['exit_code'] : null,
        'report_json' => $job['report_json'],
        'log_tail'    => $logTail,
    ]);

} catch (PDOException $e) {
    http_response_code(500);
    error_log('scan-status.php error: ' . $e->getMessage());
    echo json_encode(['error' => 'Database error']);
}
