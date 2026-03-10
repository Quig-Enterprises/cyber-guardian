<?php
// JWT-based session check for security dashboard
// Uses Project Keystone's JWT session system

// Locate project-keystone admin libs — path varies by deployment.
// Search common locations: KEYSTONE_PATH env var, then well-known paths.
$_keystone_candidates = [
    getenv('KEYSTONE_PATH') ?: '',
    '/var/www/html/project-keystone/dashboard',
    '/opt/project-keystone',
    '/opt/artemis/www',
];
$_keystone_admin = null;
foreach ($_keystone_candidates as $_candidate) {
    if ($_candidate && file_exists($_candidate . '/admin/lib/db.php')) {
        $_keystone_admin = $_candidate . '/admin/lib';
        break;
    }
}
if (!$_keystone_admin) {
    http_response_code(500);
    error_log('auth-check.php: Could not locate project-keystone admin/lib — set KEYSTONE_PATH env var');
    exit('Security dashboard misconfigured: keystone admin lib not found.');
}
require_once $_keystone_admin . '/db.php';
require_once $_keystone_admin . '/session.php';

// Get session from JWT cookie
$sessionData = Session::getCurrent();

if (!$sessionData) {
    header('Location: /admin/login.php?redirect=' . urlencode($_SERVER['REQUEST_URI']));
    exit;
}

// Populate session array in expected format
$session = [
    'sub'   => (int) $sessionData['sub'],
    'name'  => $sessionData['name'] ?? 'User',
    'email' => $sessionData['email'] ?? '',
    'super' => !empty($sessionData['super']),
];
