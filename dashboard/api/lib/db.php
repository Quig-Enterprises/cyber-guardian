<?php
// Load eqmon .env if available
$_envFile = '/var/www/html/eqmon/.env';
if (file_exists($_envFile)) {
    foreach (file($_envFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $_line) {
        if (strpos($_line, '#') === 0 || strpos($_line, '=') === false) continue;
        list($_key, $_value) = explode('=', $_line, 2);
        $_ENV[trim($_key)] = trim($_value);
    }
}

function getSecurityDb(): PDO {
    static $pdo = null;
    if ($pdo === null) {
        $host = $_ENV['DB_HOST'] ?? getenv('EQMON_DB_HOST') ?: 'localhost';
        $user = $_ENV['DB_USER'] ?? getenv('EQMON_DB_USER') ?: 'eqmon';
        $pass = $_ENV['DB_PASS'] ?? getenv('EQMON_AUTH_DB_PASS') ?: '';
        $db   = $_ENV['DB_NAME'] ?? getenv('EQMON_DB_NAME') ?: 'eqmon';
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
