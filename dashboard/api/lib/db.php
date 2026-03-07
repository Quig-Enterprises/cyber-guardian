<?php
function getSecurityDb(): PDO {
    static $pdo = null;
    if ($pdo === null) {
        $host = getenv('EQMON_DB_HOST') ?: '172.200.1.1';
        $pass = getenv('EQMON_AUTH_DB_PASS') ?: 'Mtd2l6LXNlcnAiF25vZGVyZ';
        $pdo = new PDO(
            "pgsql:host={$host};dbname=eqmon",
            'eqmon',
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
