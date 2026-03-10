<?php
// JWT-based session check for security dashboard
// Uses Project Keystone's JWT session system

// Locate project-keystone admin libs.
// DOCUMENT_ROOT is set by nginx to the keystone dashboard root (the directory
// that contains both admin/ and security-dashboard/).
// KEYSTONE_PATH env var overrides for non-standard deployments.
$_keystone_candidates = array_filter([
    getenv('KEYSTONE_PATH') ?: null,
    $_SERVER['DOCUMENT_ROOT'] ?? null,
    '/var/www/html/project-keystone/dashboard',  // alfred
    '/opt/project-keystone/dashboard',           // artemis
    '/opt/artemis/www',                          // artemis legacy
]);
$_keystone_admin = null;
foreach ($_keystone_candidates as $_candidate) {
    if (is_readable($_candidate . '/admin/lib/db.php')) {
        $_keystone_admin = $_candidate . '/admin/lib';
        break;
    }
}
if (!$_keystone_admin) {
    http_response_code(500);
    error_log('auth-check.php: Could not locate project-keystone admin/lib. Set KEYSTONE_PATH env var to the keystone dashboard root.');
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
