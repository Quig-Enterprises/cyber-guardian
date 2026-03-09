<?php
/**
 * Import Latest Red Team Scan to Mitigation Dashboard
 *
 * API endpoint to import scan results into mitigation tracking system
 */

// For CLI execution - will work from web request in docker
header('Content-Type: application/json');

// Database connection using environment variables (docker container has access)
try {
    $host = getenv('DB_HOST') ?: '172.200.1.1';
    $dbname = getenv('DB_NAME') ?: 'alfred_admin';
    $user = getenv('DB_USER') ?: 'alfred_admin';
    $pass = getenv('DB_PASS') ?: '';

    $dsn = "pgsql:host={$host};dbname={$dbname}";
    $db = new PDO($dsn, $user, $pass, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC
    ]);
} catch (PDOException $e) {
    http_response_code(500);
    echo json_encode(['error' => 'Database connection failed: ' . $e->getMessage()]);
    exit;
}

// Find latest scan report
$scanDir = '/opt/claude-workspace/projects/cyber-guardian/redteam/reports';
$latestJson = null;
$latestTime = 0;

foreach (glob("$scanDir/redteam-report-*.json") as $file) {
    $mtime = filemtime($file);
    if ($mtime > $latestTime) {
        $latestTime = $mtime;
        $latestJson = $file;
    }
}

if (!$latestJson || !file_exists($latestJson)) {
    http_response_code(404);
    echo json_encode(['error' => 'No scan report found']);
    exit;
}

// Load scan results
$scanData = json_decode(file_get_contents($latestJson), true);
if (!$scanData) {
    http_response_code(500);
    echo json_encode(['error' => 'Failed to parse scan report']);
    exit;
}

// Extract scan date from filename
$filename = basename($latestJson, '.json');
$parts = explode('-', $filename);
if (count($parts) >= 3) {
    $dateStr = explode('_', $parts[2])[0];
    $scanDate = DateTime::createFromFormat('Ymd', $dateStr)->format('Y-m-d');
} else {
    $scanDate = date('Y-m-d');
}

// Check if this scan was already imported
$stmt = $db->prepare("
    SELECT id FROM blueteam.mitigation_projects
    WHERE scan_report_path = ?
");
$stmt->execute([$latestJson]);
if ($stmt->fetchColumn()) {
    echo json_encode([
        'status' => 'already_imported',
        'message' => 'This scan has already been imported',
        'scan_file' => basename($latestJson)
    ]);
    exit;
}

// Create mitigation project
$projectName = "Red Team Scan - $scanDate";
$description = "Automated red team security scan conducted on $scanDate";

$stmt = $db->prepare("
    INSERT INTO blueteam.mitigation_projects
    (name, description, scan_date, scan_report_path, status)
    VALUES (?, ?, ?, ?, 'active')
    RETURNING id
");
$stmt->execute([$projectName, $description, $scanDate, $latestJson]);
$projectId = $stmt->fetchColumn();

// Import vulnerabilities
$importedCount = 0;
$severityCounts = [];

foreach ($scanData['results'] as $result) {
    // Only import vulnerable findings
    if ($result['status'] !== 'vulnerable') {
        continue;
    }

    $attackName = $result['attack_name'] ?? 'unknown';
    $variant = $result['variant'] ?? '';
    $severity = $result['severity'] ?? 'low';
    $message = $result['message'] ?? '';
    $evidence = $result['evidence'] ?? '';
    $category = $result['category'] ?? 'unknown';

    // Create title
    $title = $attackName;
    if ($variant) {
        $title .= " / $variant";
    }

    // Map severity to priority
    $priorityMap = [
        'critical' => 1,
        'high' => 2,
        'medium' => 3,
        'low' => 4
    ];
    $priority = $priorityMap[strtolower($severity)] ?? 3;

    // Set due date based on severity
    $dueDays = [
        'critical' => 3,
        'high' => 30,
        'medium' => 60,
        'low' => 90
    ];
    $days = $dueDays[strtolower($severity)] ?? 60;
    $dueDate = date('Y-m-d', strtotime("+$days days"));

    // Store request/response details as JSON
    $requestDetails = json_encode($result['request'] ?? []);
    $responseDetails = json_encode($result['response'] ?? []);

    $stmt = $db->prepare("
        INSERT INTO blueteam.mitigation_issues
        (project_id, title, description, severity, category, attack_name, variant,
         status, priority, due_date, evidence, request_details, response_details)
        VALUES (?, ?, ?, ?, ?, ?, ?, 'not_started', ?, ?, ?, ?::jsonb, ?::jsonb)
        RETURNING id
    ");
    $stmt->execute([
        $projectId, $title, $message, $severity, $category, $attackName, $variant,
        $priority, $dueDate, $evidence, $requestDetails, $responseDetails
    ]);
    $issueId = $stmt->fetchColumn();

    // Log initial activity
    $stmt = $db->prepare("
        INSERT INTO blueteam.mitigation_activity
        (issue_id, activity_type, comment, user_name)
        VALUES (?, 'created', 'Imported from red team scan', 'system')
    ");
    $stmt->execute([$issueId]);

    $importedCount++;

    if (!isset($severityCounts[$severity])) {
        $severityCounts[$severity] = 0;
    }
    $severityCounts[$severity]++;
}

echo json_encode([
    'status' => 'success',
    'project_id' => $projectId,
    'imported_count' => $importedCount,
    'scan_date' => $scanDate,
    'scan_file' => basename($latestJson),
    'severity_counts' => $severityCounts
]);
