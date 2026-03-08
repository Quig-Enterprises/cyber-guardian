<?php
/**
 * Export consolidated open TODOs as a Markdown file for Claude sessions.
 * GET ?mode=cxq|all
 */

$userId = $_SERVER['HTTP_X_AUTH_USER_ID'] ?? null;
if (!$userId) {
    http_response_code(401);
    echo json_encode(['error' => 'Unauthorized']);
    exit;
}

$include3p = isset($_GET['mode']) && $_GET['mode'] === 'all';

$script = '/opt/claude-workspace/shared-resources/consolidate-todos.sh';
if (!file_exists($script)) {
    http_response_code(500);
    echo json_encode(['error' => 'Consolidator script not found']);
    exit;
}

$args = $include3p ? '--3rdparty' : '';
$output = shell_exec('bash ' . escapeshellarg($script) . ' ' . $args . ' 2>/dev/null');

if ($output === null) {
    http_response_code(500);
    echo json_encode(['error' => 'Failed to generate TODO list']);
    exit;
}

$date = date('Y-m-d');
$label = $include3p ? 'all' : 'cxq';
$filename = "todos-{$label}-{$date}.md";

header('Content-Type: text/markdown; charset=utf-8');
header('Content-Disposition: attachment; filename="' . $filename . '"');
header('Cache-Control: no-store');
echo $output;
