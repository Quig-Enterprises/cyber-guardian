<?php
/**
 * Codebase Security Scanner API
 *
 * POST - Launch a blue team codebase scan or regenerate TODOs.
 * GET  - Check if a scan is currently running.
 */

header('Content-Type: application/json');

$userId = $_SERVER['HTTP_X_AUTH_USER_ID'] ?? null;
if (!$userId) {
    http_response_code(401);
    echo json_encode(['error' => 'Unauthorized']);
    exit;
}

// Require super admin
$authHeader = $_SERVER['HTTP_AUTH'] ?? '';
$isSuperAdmin = false;
if ($authHeader) {
    $session = json_decode($authHeader, true);
    if (!empty($session['super'])) $isSuperAdmin = true;
}
if (!$isSuperAdmin) {
    $superHeader = $_SERVER['HTTP_X_AUTH_SUPER'] ?? '';
    if ($superHeader === 'true' || $superHeader === '1') $isSuperAdmin = true;
}
if (!$isSuperAdmin) {
    http_response_code(403);
    echo json_encode(['error' => 'Super admin access required']);
    exit;
}

$projectDir = '/opt/claude-workspace/projects/cyber-guardian';
$logDir = $projectDir . '/logs';
$lockFile = '/tmp/codebase-scan.lock';

// GET — check status
if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    $running = file_exists($lockFile);
    $logFile = null;
    if ($running) {
        $lockData = json_decode(file_get_contents($lockFile), true);
        $pid = $lockData['pid'] ?? 0;
        // Check if process is actually still running
        if ($pid > 0 && !file_exists('/proc/' . $pid)) {
            $running = false;
            @unlink($lockFile);
        } else {
            $logFile = $lockData['log_file'] ?? null;
        }
    }
    echo json_encode(['running' => $running, 'log_file' => $logFile]);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['error' => 'POST or GET required']);
    exit;
}

// Check not already running
if (file_exists($lockFile)) {
    $lockData = json_decode(file_get_contents($lockFile), true);
    $pid = $lockData['pid'] ?? 0;
    if ($pid > 0 && file_exists('/proc/' . $pid)) {
        http_response_code(409);
        echo json_encode(['error' => 'A codebase scan is already running', 'pid' => $pid]);
        exit;
    }
    @unlink($lockFile);
}

$input = json_decode(file_get_contents('php://input'), true);
$action = $input['action'] ?? 'scan-and-generate';
$validActions = ['scan', 'generate-todos', 'scan-and-generate'];
if (!in_array($action, $validActions, true)) {
    http_response_code(400);
    echo json_encode(['error' => 'Invalid action. Valid: ' . implode(', ', $validActions)]);
    exit;
}

$timestamp = date('Ymd_His');
$logFile = $logDir . '/codebase-scan-' . $timestamp . '.log';

// Build command
$scanCmd = 'cd ' . escapeshellarg($projectDir) . ' && python3 blueteam/cli_codebase_scan.py';
$todoCmd = 'cd ' . escapeshellarg($projectDir) . ' && python3 scripts/generate-mitigation-todos.py';

if ($action === 'scan') {
    $cmd = $scanCmd;
} elseif ($action === 'generate-todos') {
    $cmd = $todoCmd;
} else {
    $cmd = $scanCmd . ' && ' . $todoCmd;
}

// Add lock file cleanup to command
$fullCmd = '(' . $cmd . '; rm -f ' . escapeshellarg($lockFile) . ') > ' . escapeshellarg($logFile) . ' 2>&1 & echo $!';

$pid = (int) trim(shell_exec($fullCmd));

// Write lock file
file_put_contents($lockFile, json_encode([
    'pid' => $pid,
    'action' => $action,
    'started' => date('c'),
    'log_file' => $logFile,
    'initiated_by' => (int) $userId
]));

echo json_encode([
    'success' => true,
    'action' => $action,
    'pid' => $pid,
    'log_file' => $logFile
]);
