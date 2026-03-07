<?php
header('Content-Type: application/json');

$userId = $_SERVER['HTTP_X_AUTH_USER_ID'] ?? null;
if (!$userId) {
    http_response_code(401);
    echo json_encode(['error' => 'Unauthorized']);
    exit;
}

require_once __DIR__ . '/lib/db.php';
try {
    $pdo = getSecurityDb();
} catch (PDOException $e) {
    http_response_code(500);
    echo json_encode(['error' => 'Database connection failed']);
    exit;
}

try {
    // Recent alerts
    $stmt = $pdo->query("
        SELECT alert_id, rule_id, severity, title, description,
               incident_id, acknowledged, acknowledged_by, acknowledged_at, created_at
        FROM blueteam.alert_history
        ORDER BY created_at DESC
        LIMIT 50
    ");
    $alerts = [];
    while ($row = $stmt->fetch()) {
        $alerts[] = [
            'alert_id' => $row['alert_id'],
            'rule_id' => $row['rule_id'],
            'severity' => $row['severity'],
            'title' => $row['title'],
            'description' => $row['description'],
            'incident_id' => $row['incident_id'],
            'acknowledged' => (bool) $row['acknowledged'],
            'acknowledged_by' => $row['acknowledged_by'],
            'acknowledged_at' => $row['acknowledged_at'],
            'created_at' => $row['created_at'],
        ];
    }

    // Unacknowledged count
    $stmt = $pdo->query("SELECT COUNT(*) as cnt FROM blueteam.alert_history WHERE acknowledged = false");
    $countRow = $stmt->fetch();

    echo json_encode([
        'alerts' => $alerts,
        'unacknowledged_count' => (int) $countRow['cnt']
    ]);

} catch (PDOException $e) {
    http_response_code(500);
    echo json_encode(['error' => 'Query failed']);
}
