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
    // Active incidents ordered by severity then detection time
    $stmt = $pdo->query("
        SELECT incident_id, title, description, severity, status,
               detected_at, detected_by, assigned_to,
               cui_involved, dfars_reportable, dfars_reported_at,
               contained_at, eradicated_at, recovered_at, closed_at,
               root_cause,
               EXTRACT(EPOCH FROM (NOW() - detected_at)) / 3600 as elapsed_hours
        FROM blueteam.security_incidents
        WHERE status != 'closed'
        ORDER BY
            CASE severity
                WHEN 'critical' THEN 1
                WHEN 'high' THEN 2
                WHEN 'medium' THEN 3
                WHEN 'low' THEN 4
            END,
            detected_at DESC
    ");
    $incidents = [];
    while ($row = $stmt->fetch()) {
        $incidents[] = [
            'incident_id' => $row['incident_id'],
            'title' => $row['title'],
            'description' => $row['description'],
            'severity' => $row['severity'],
            'status' => $row['status'],
            'detected_at' => $row['detected_at'],
            'detected_by' => $row['detected_by'],
            'assigned_to' => $row['assigned_to'],
            'cui_involved' => (bool) $row['cui_involved'],
            'dfars_reportable' => (bool) $row['dfars_reportable'],
            'dfars_reported_at' => $row['dfars_reported_at'],
            'elapsed_hours' => round((float) $row['elapsed_hours'], 1),
        ];
    }

    // DFARS reporting status
    $stmt = $pdo->query("
        SELECT
            COUNT(*) FILTER (WHERE cui_involved = true AND severity IN ('critical', 'high') AND dfars_reported_at IS NOT NULL) as reported,
            COUNT(*) FILTER (WHERE cui_involved = true AND severity IN ('critical', 'high') AND dfars_reported_at IS NULL AND detected_at >= NOW() - INTERVAL '72 hours') as pending,
            COUNT(*) FILTER (WHERE cui_involved = true AND severity IN ('critical', 'high') AND dfars_reported_at IS NULL AND detected_at < NOW() - INTERVAL '72 hours') as overdue
        FROM blueteam.security_incidents
        WHERE status != 'closed'
    ");
    $dfarsRow = $stmt->fetch();

    // Overdue list
    $stmt = $pdo->query("
        SELECT incident_id, title, severity, detected_at,
               EXTRACT(EPOCH FROM (NOW() - detected_at)) / 3600 as elapsed_hours
        FROM blueteam.security_incidents
        WHERE status != 'closed'
          AND cui_involved = true
          AND severity IN ('critical', 'high')
          AND dfars_reported_at IS NULL
          AND detected_at < NOW() - INTERVAL '72 hours'
        ORDER BY detected_at ASC
    ");
    $overdueList = [];
    while ($row = $stmt->fetch()) {
        $overdueList[] = [
            'incident_id' => $row['incident_id'],
            'title' => $row['title'],
            'severity' => $row['severity'],
            'detected_at' => $row['detected_at'],
            'elapsed_hours' => round((float) $row['elapsed_hours'], 1),
        ];
    }

    echo json_encode([
        'incidents' => $incidents,
        'dfars' => [
            'pending' => (int) $dfarsRow['pending'],
            'reported' => (int) $dfarsRow['reported'],
            'overdue' => (int) $dfarsRow['overdue'],
            'overdue_list' => $overdueList
        ]
    ]);

} catch (PDOException $e) {
    http_response_code(500);
    echo json_encode(['error' => 'Query failed']);
}
