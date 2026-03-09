<?php
/**
 * Mitigation Dashboard API
 * Serves security mitigation metrics from database
 */

header('Content-Type: application/json');

// Universal database connection - works on any server
// Tries multiple credential sources in order of priority
try {
    // Option 1: Environment variables (set by systemd, docker, or .env loader)
    $host = getenv('DB_HOST') ?: '127.0.0.1';
    $dbname = getenv('DB_NAME') ?: 'alfred_admin';
    $user = getenv('DB_USER') ?: 'alfred_admin';
    $pass = getenv('DB_PASS') ?: '';

    // Option 2: Load from admin/.env if available (for alfred server)
    $envFiles = [
        '/var/www/html/alfred/dashboard/admin/.env',
        __DIR__ . '/../../../admin/.env',
        $_SERVER['DOCUMENT_ROOT'] . '/admin/.env'
    ];

    foreach ($envFiles as $envFile) {
        if (file_exists($envFile)) {
            foreach (file($envFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
                if (strpos($line, '#') === 0 || strpos($line, '=') === false) continue;
                list($key, $value) = explode('=', $line, 2);
                $key = trim($key);
                $value = trim($value);
                if ($key === 'DB_HOST') $host = $value;
                elseif ($key === 'DB_NAME') $dbname = $value;
                elseif ($key === 'DB_USER') $user = $value;
                elseif ($key === 'DB_PASS') $pass = $value;
            }
            break; // Use first found .env file
        }
    }

    // Always use localhost when connecting from PHP-FPM (not Docker bridge)
    if ($host === '172.200.1.1') {
        $host = '127.0.0.1';
    }

    $pdo = new PDO(
        "pgsql:host={$host};dbname={$dbname}",
        $user,
        $pass,
        [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES => false
        ]
    );
    $db = $pdo;

    // Get summary stats
    $stmt = $db->query("
        SELECT
            COUNT(*) as total_issues,
            SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) as critical,
            SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END) as high,
            SUM(CASE WHEN severity = 'medium' THEN 1 ELSE 0 END) as medium,
            SUM(CASE WHEN severity = 'low' THEN 1 ELSE 0 END) as low,
            SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) as completed,
            MAX(created_at) as last_updated
        FROM blueteam.mitigation_issues
        WHERE status != 'wont_fix'
    ");
    $summary = $stmt->fetch();

    // Calculate net improvement (last 7 days)
    $stmt = $db->query("
        SELECT COUNT(*) as fixed_count
        FROM blueteam.mitigation_issues
        WHERE status = 'completed'
        AND completed_at >= NOW() - INTERVAL '7 days'
    ");
    $improvement = $stmt->fetch();
    $net_improvement = (int)$improvement['fixed_count'];

    // Get projects list
    $stmt = $db->query("
        SELECT
            mp.id,
            mp.name,
            mp.scan_date,
            mp.status,
            COUNT(mi.id) as total_issues,
            SUM(CASE WHEN mi.severity = 'critical' THEN 1 ELSE 0 END) as critical,
            SUM(CASE WHEN mi.severity = 'high' THEN 1 ELSE 0 END) as high,
            SUM(CASE WHEN mi.severity = 'medium' THEN 1 ELSE 0 END) as medium
        FROM blueteam.mitigation_projects mp
        LEFT JOIN blueteam.mitigation_issues mi ON mp.id = mi.project_id AND mi.status != 'wont_fix'
        GROUP BY mp.id, mp.name, mp.scan_date, mp.status
        ORDER BY mp.scan_date DESC
    ");
    $projects = $stmt->fetchAll();

    // Get recent activity (last 10 events)
    $stmt = $db->query("
        SELECT
            ma.id,
            ma.activity_type,
            ma.old_value,
            ma.new_value,
            ma.comment,
            ma.user_name,
            ma.created_at,
            mi.title as issue_title,
            mi.severity
        FROM blueteam.mitigation_activity ma
        JOIN blueteam.mitigation_issues mi ON ma.issue_id = mi.id
        ORDER BY ma.created_at DESC
        LIMIT 10
    ");
    $activity_raw = $stmt->fetchAll();

    // Format activity
    $activity = [];
    foreach ($activity_raw as $act) {
        $timestamp = date('Y-m-d H:i:s', strtotime($act['created_at']));
        $message = '';
        $type = 'info';

        switch ($act['activity_type']) {
            case 'created':
                $message = "New {$act['severity']} issue: {$act['issue_title']}";
                $type = 'warning';
                break;
            case 'status_change':
                $message = "Status changed: {$act['issue_title']} ({$act['old_value']} → {$act['new_value']})";
                if ($act['new_value'] === 'completed') {
                    $type = 'success';
                }
                break;
            case 'comment':
                $message = "Comment on: {$act['issue_title']}";
                break;
            case 'assignment':
                $message = "Assigned: {$act['issue_title']} → {$act['new_value']}";
                break;
            case 'verification':
                $message = "Verified fix: {$act['issue_title']}";
                $type = 'success';
                break;
            default:
                $message = "{$act['activity_type']}: {$act['issue_title']}";
        }

        $activity[] = [
            'timestamp' => $timestamp,
            'type' => $type,
            'message' => $message
        ];
    }

    // Build response
    $response = [
        'success' => true,
        'summary' => [
            'total_issues' => (int)$summary['total_issues'],
            'critical' => (int)$summary['critical'],
            'high' => (int)$summary['high'],
            'medium' => (int)$summary['medium'],
            'low' => (int)$summary['low'],
            'completed' => (int)$summary['completed'],
            'net_improvement' => $net_improvement,
            'last_updated' => $summary['last_updated']
        ],
        'projects' => array_map(function($p) {
            return [
                'id' => (int)$p['id'],
                'name' => $p['name'],
                'scan_date' => $p['scan_date'],
                'status' => $p['status'],
                'total' => (int)$p['total_issues'],
                'critical' => (int)$p['critical'],
                'high' => (int)$p['high'],
                'medium' => (int)$p['medium']
            ];
        }, $projects),
        'activity' => $activity,
        'trend' => [] // TODO: Implement trend data from historical snapshots
    ];

    echo json_encode($response, JSON_PRETTY_PRINT);

} catch (Exception $e) {
    http_response_code(500);
    echo json_encode([
        'success' => false,
        'error' => $e->getMessage()
    ]);
}
