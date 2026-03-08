<?php
/**
 * Return TODO_SECURITY.md content as JSON for in-page display.
 * GET ?path=/var/www/html/eqmon/api/TODO_SECURITY.md
 */

header('Content-Type: application/json');

$userId = $_SERVER['HTTP_X_AUTH_USER_ID'] ?? null;
if (!$userId) {
    http_response_code(401);
    echo json_encode(['error' => 'Unauthorized']);
    exit;
}

$path = $_GET['path'] ?? '';
if ($path === '') {
    http_response_code(400);
    echo json_encode(['error' => 'Missing path parameter']);
    exit;
}

$real = realpath($path);
if ($real === false || !is_file($real)) {
    http_response_code(404);
    echo json_encode(['error' => 'File not found']);
    exit;
}

// Whitelist: only TODO_SECURITY.md under known directories
$allowed = [
    '/var/www/html/eqmon/',
    '/opt/claude-workspace/projects/',
    '/opt/artemis/www/'
];

$ok = false;
foreach ($allowed as $prefix) {
    if (strpos($real, $prefix) === 0) {
        $ok = true;
        break;
    }
}

if (!$ok || basename($real) !== 'TODO_SECURITY.md') {
    http_response_code(403);
    echo json_encode(['error' => 'Access denied']);
    exit;
}

echo json_encode([
    'success' => true,
    'path' => $real,
    'content' => file_get_contents($real)
]);
