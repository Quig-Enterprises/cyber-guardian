<?php
/**
 * Password Audit API
 *
 * GET - Returns latest password audit results.
 * POST - Triggers an immediate audit scan (super admin only).
 */

header('Content-Type: application/json');

$userId = $_SERVER['HTTP_X_AUTH_USER_ID'] ?? null;
if (!$userId) {
    http_response_code(401);
    echo json_encode(['error' => 'Unauthorized']);
    exit;
}

require_once __DIR__ . '/lib/db.php';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Trigger immediate scan — super admin only
    $superHeader = $_SERVER['HTTP_X_AUTH_SUPER'] ?? '';
    if ($superHeader !== 'true' && $superHeader !== '1') {
        $authHeader = $_SERVER['HTTP_AUTH'] ?? '';
        $session = $authHeader ? json_decode($authHeader, true) : [];
        if (empty($session['super'])) {
            http_response_code(403);
            echo json_encode(['error' => 'Super admin access required']);
            exit;
        }
    }

    $logFile = '/opt/claude-workspace/projects/cyber-guardian/logs/password-audit-' . date('Ymd_His') . '.log';
    $cmd = 'cd /opt/claude-workspace/projects/cyber-guardian'
         . ' && venv/bin/python bin/scan-passwords.py'
         . ' >> ' . escapeshellarg($logFile) . ' 2>&1 &';
    shell_exec($cmd);

    echo json_encode(['status' => 'started', 'log' => $logFile]);
    exit;
}

try {
    $pdo = getSecurityDb();

    // Latest completed run
    $run = $pdo->query("
        SELECT run_id, run_at, duration_sec, total_checked,
               weak_count, insecure_count, ok_count, status, error_msg
        FROM blueteam.password_audit_runs
        WHERE status = 'completed'
        ORDER BY run_at DESC
        LIMIT 1
    ")->fetch(PDO::FETCH_ASSOC);

    // Active (unresolved) findings from latest run
    $findings = [];
    if ($run) {
        $stmt = $pdo->prepare("
            SELECT finding_id, source_db, source_table, user_id, user_email,
                   hash_algorithm, hash_cost, severity, finding, detected_at
            FROM blueteam.password_audit_findings
            WHERE resolved_at IS NULL
            ORDER BY
                CASE severity
                    WHEN 'critical'  THEN 1
                    WHEN 'insecure'  THEN 2
                    WHEN 'weak'      THEN 3
                    ELSE 4
                END,
                detected_at DESC
            LIMIT 200
        ");
        $stmt->execute();
        $findings = $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    // Severity summary (all active)
    $severity_counts = ['critical' => 0, 'insecure' => 0, 'weak' => 0];
    foreach ($findings as $f) {
        $sev = $f['severity'];
        if (isset($severity_counts[$sev])) $severity_counts[$sev]++;
    }

    // Last 10 runs for history
    $history = $pdo->query("
        SELECT run_id, run_at, total_checked, weak_count, insecure_count, ok_count, status
        FROM blueteam.password_audit_runs
        ORDER BY run_at DESC
        LIMIT 10
    ")->fetchAll(PDO::FETCH_ASSOC);

    // Score: 100 base, -20 per insecure/critical, -5 per weak
    $score = 100;
    $score -= ($severity_counts['critical'] + $severity_counts['insecure']) * 20;
    $score -= $severity_counts['weak'] * 5;
    $score = max(0, $score);

    echo json_encode([
        'score'           => $score,
        'latest_run'      => $run,
        'severity_counts' => $severity_counts,
        'active_findings' => $findings,
        'history'         => $history,
        'timestamp'       => date('c'),
    ]);

} catch (PDOException $e) {
    http_response_code(500);
    error_log('password-audit.php DB error: ' . $e->getMessage());
    echo json_encode(['error' => 'Database error']);
}
