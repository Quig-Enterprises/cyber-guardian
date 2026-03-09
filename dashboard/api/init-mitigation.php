<?php
/**
 * ONE-TIME INITIALIZATION SCRIPT
 * Import mitigation data from scan results
 * DELETE THIS FILE AFTER RUNNING ONCE
 */

// Simple password protection
$init_password = 'temp_import_2026';
if (!isset($_GET['key']) || $_GET['key'] !== $init_password) {
    http_response_code(403);
    die('Access denied. Usage: INIT_MITIGATION.php?key=temp_import_2026');
}

header('Content-Type: text/plain');

// Load database
$envFile = '/var/www/html/alfred/dashboard/admin/.env';
if (file_exists($envFile)) {
    foreach (file($envFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
        if (strpos($line, '#') === 0 || strpos($line, '=') === false) continue;
        list($key, $value) = explode('=', $line, 2);
        $_ENV[trim($key)] = trim($value);
    }
}

$host = $_ENV['DB_HOST'] ?? 'localhost';
$dbname = $_ENV['DB_NAME'] ?? 'alfred_admin';
$user = $_ENV['DB_USER'] ?? 'alfred_admin';
$pass = $_ENV['DB_PASS'] ?? '';

try {
    $dsn = "pgsql:host={$host};dbname={$dbname}";
    $db = new PDO($dsn, $user, $pass, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION
    ]);

    echo "Connected to database successfully.\n\n";

    // Read and execute SQL
    $sqlFile = __DIR__ . '/mitigation-import.sql';
    if (!file_exists($sqlFile)) {
        die("ERROR: SQL file not found\n");
    }

    $sql = file_get_contents($sqlFile);
    echo "Executing SQL import...\n\n";
    $db->exec($sql);
    echo "SQL executed successfully!\n\n";

    // Get summary
    $stmt = $db->query("
        SELECT
            mp.id,
            mp.name,
            COUNT(mi.id) as total_issues,
            SUM(CASE WHEN mi.severity = 'critical' THEN 1 ELSE 0 END) as critical,
            SUM(CASE WHEN mi.severity = 'high' THEN 1 ELSE 0 END) as high,
            SUM(CASE WHEN mi.severity = 'medium' THEN 1 ELSE 0 END) as medium,
            SUM(CASE WHEN mi.severity = 'low' THEN 1 ELSE 0 END) as low
        FROM blueteam.mitigation_projects mp
        LEFT JOIN blueteam.mitigation_issues mi ON mp.id = mi.project_id
        WHERE mp.scan_date = '2026-03-08'
        GROUP BY mp.id, mp.name
        ORDER BY mp.id DESC
        LIMIT 1
    ");

    $result = $stmt->fetch();

    if ($result) {
        echo "=== IMPORT SUCCESSFUL ===\n\n";
        echo "Project ID: " . $result['id'] . "\n";
        echo "Project: " . $result['name'] . "\n";
        echo "Total Issues: " . $result['total_issues'] . "\n\n";
        echo "By Severity:\n";
        echo "  CRITICAL: " . $result['critical'] . "\n";
        echo "  HIGH: " . $result['high'] . "\n";
        echo "  MEDIUM: " . $result['medium'] . "\n";
        echo "  LOW: " . $result['low'] . "\n\n";
        echo "View dashboard at:\n";
        echo "https://8qdj5it341kfv92u.brandonquig.com/security-dashboard/#mitigation\n\n";
        echo "DELETE THIS FILE NOW: INIT_MITIGATION.php\n";
    } else {
        echo "WARNING: SQL executed but no data found\n";
    }

} catch (Exception $e) {
    echo "ERROR: " . $e->getMessage() . "\n";
    echo $e->getTraceAsString() . "\n";
}
