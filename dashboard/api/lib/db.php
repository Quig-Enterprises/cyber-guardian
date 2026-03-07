<?php
// Load dashboard .env (admin credentials for alfred_admin DB)
foreach ([
    __DIR__ . '/../../admin/.env',
    $_SERVER['DOCUMENT_ROOT'] . '/admin/.env',
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
        $host = $_ENV['DB_HOST'] ?? 'localhost';
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
