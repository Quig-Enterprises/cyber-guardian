<?php
/**
 * API endpoint to import mitigation data
 * Call via: curl https://8qdj5it341kfv92u.brandonquig.com/security-dashboard/api/run-import.php
 */

// Allow execution without auth for initial import (remove this after first run)
header('Content-Type: application/json');

require_once '/var/www/html/alfred/dashboard/admin/lib/db.php';

try {
    $db = Database::getConnection();

    // Read SQL file
    $sqlFile = '/var/www/html/alfred/dashboard/security-dashboard/mitigation-import.sql';
    if (!file_exists($sqlFile)) {
        http_response_code(404);
        echo json_encode(['error' => 'SQL file not found']);
        exit;
    }

    $sql = file_get_contents($sqlFile);

    // Execute SQL
    $db->exec($sql);

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
        echo json_encode([
            'status' => 'success',
            'project' => $result['name'],
            'project_id' => $result['id'],
            'total_issues' => (int)$result['total_issues'],
            'by_severity' => [
                'critical' => (int)$result['critical'],
                'high' => (int)$result['high'],
                'medium' => (int)$result['medium'],
                'low' => (int)$result['low']
            ],
            'dashboard_url' => 'https://8qdj5it341kfv92u.brandonquig.com/security-dashboard/#mitigation'
        ]);
    } else {
        echo json_encode([
            'status' => 'warning',
            'message' => 'SQL executed but no project found'
        ]);
    }

} catch (Exception $e) {
    http_response_code(500);
    echo json_encode([
        'error' => $e->getMessage(),
        'trace' => $e->getTraceAsString()
    ]);
}
