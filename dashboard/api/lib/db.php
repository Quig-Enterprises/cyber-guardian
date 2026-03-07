<?php
// Load dashboard .env for credentials (DB_USER, DB_PASS, DB_NAME)
// DB_HOST is always 127.0.0.1 on alfred — Postgres listens on all interfaces
// and the shared admin/.env uses 172.200.1.1 (Docker bridge) for Keystone.
foreach ([
    __DIR__ . '/../../../admin/.env',
    $_SERVER['DOCUMENT_ROOT'] . '/admin/.env',
    '/opt/artemis/www/admin/.env',
] as $_envFile) {
    if (file_exists($_envFile)) {
        foreach (file($_envFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $_line) {
            if (strpos($_line, '#') === 0 || strpos($_line, '=') === false) continue;
            [$_key, $_value] = explode('=', $_line, 2);
            $_ENV[trim($_key)] = trim($_value);
        }
        break;
    }
}

function getSecurityDb(): PDO {
    static $pdo = null;
    if ($pdo === null) {
        // Always use 127.0.0.1 — PHP-FPM runs on the host and Postgres is local.
        // (admin/.env uses 172.200.1.1 for Keystone/Docker, which we don't use here.)
        $host = '127.0.0.1';
        $user = $_ENV['DB_USER'] ?? 'alfred_admin';
        $pass = $_ENV['DB_PASS'] ?? '';
        $db   = $_ENV['DB_NAME'] ?? 'alfred_admin';
        $pdo = new PDO(
            "pgsql:host={$host};dbname={$db}",
            $user,
            $pass,
            [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES => false
            ]
        );
    }
    return $pdo;
}
