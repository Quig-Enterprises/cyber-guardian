<?php
// JWT-based session check for security dashboard
// Uses Project Keystone's JWT session system

// When symlinked from /var/www/html/alfred/dashboard/security-dashboard/ to here,
// we need to reference the Keystone admin files by absolute path
require_once '/var/www/html/project-keystone/dashboard/admin/lib/db.php';
require_once '/var/www/html/project-keystone/dashboard/admin/lib/session.php';

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
