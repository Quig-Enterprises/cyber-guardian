<?php
/**
 * Import Mitigation Data from SQL File
 * Run this once to populate mitigation dashboard with scan results
 */

require_once '/var/www/html/alfred/dashboard/admin/lib/db.php';

try {
    $db = Database::getConnection();

    // Read SQL file
    $sqlFile = __DIR__ . '/mitigation-import.sql';
    if (!file_exists($sqlFile)) {
        die("Error: SQL file not found at $sqlFile\n");
    }

    $sql = file_get_contents($sqlFile);

    // Execute SQL
    echo "Importing mitigation data...\n\n";
    $db->exec($sql);

    // Get summary
    $stmt = $db->query("
        SELECT
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
    ");

    $result = $stmt->fetch();

    echo "SUCCESS!\n\n";
    echo "Project: " . $result['name'] . "\n";
    echo "Total Issues: " . $result['total_issues'] . "\n";
    echo "\nBy Severity:\n";
    echo "  CRITICAL: " . $result['critical'] . "\n";
    echo "  HIGH: " . $result['high'] . "\n";
    echo "  MEDIUM: " . $result['medium'] . "\n";
    echo "  LOW: " . $result['low'] . "\n";
    echo "\nMitigation dashboard is now populated!\n";
    echo "View at: https://8qdj5it341kfv92u.brandonquig.com/security-dashboard/ (Mitigation tab)\n";

} catch (Exception $e) {
    echo "ERROR: " . $e->getMessage() . "\n";
    exit(1);
}
