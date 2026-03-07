<?php

$userId = $_SERVER['HTTP_X_AUTH_USER_ID'] ?? null;
if (!$userId) {
    http_response_code(401);
    echo '<!DOCTYPE html><html><body><h1>Unauthorized</h1></body></html>';
    exit;
}

$t = $_GET['t'] ?? '';

if (!preg_match('/^\d{8}_\d{6}$/', $t)) {
    http_response_code(400);
    echo '<!DOCTYPE html><html><body><h1>Bad Request</h1><p>Invalid timestamp format.</p></body></html>';
    exit;
}

$path = "/opt/security-red-team/reports/redteam-report-{$t}.html";

if (!file_exists($path)) {
    http_response_code(404);
    echo '<!DOCTYPE html><html><body><h1>Not Found</h1><p>Report not found.</p></body></html>';
    exit;
}

header('Content-Type: text/html; charset=UTF-8');
readfile($path);
exit;
