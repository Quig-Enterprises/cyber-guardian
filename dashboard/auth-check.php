<?php
// JWT-based session check for security dashboard
// Uses Project Keystone's JWT session system

// Locate project-keystone admin libs via DOCUMENT_ROOT.
// Each deployment's nginx security-dashboard fastcgi block must set:
//   fastcgi_param DOCUMENT_ROOT /path/to/project-keystone/dashboard;
$_keystone_admin = ($_SERVER['DOCUMENT_ROOT'] ?? '') . '/admin/lib';
if (!is_readable($_keystone_admin . '/db.php')) {
    http_response_code(500);
    error_log('auth-check.php: admin/lib not found at ' . $_keystone_admin . '. Ensure nginx sets fastcgi_param DOCUMENT_ROOT to the project-keystone dashboard root.');
    exit('Security dashboard misconfigured: ensure nginx sets DOCUMENT_ROOT to the project-keystone dashboard root.');
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
