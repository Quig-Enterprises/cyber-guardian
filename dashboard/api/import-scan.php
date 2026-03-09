<?php
/**
 * Import Red Team Scan Results to Mitigation Dashboard
 *
 * Usage: php import-scan.php <scan-report.json>
 */

require_once '/var/www/html/alfred/dashboard/admin/lib/db.php';

if ($argc < 2) {
    echo "Usage: php import-scan.php <scan-report.json>\n";
    exit(1);
}

$scanReportPath = $argv[1];

if (!file_exists($scanReportPath)) {
    echo "Error: File not found: $scanReportPath\n";
    exit(1);
}

// Load scan results
$scanData = json_decode(file_get_contents($scanReportPath), true);
if (!$scanData) {
    echo "Error: Failed to parse JSON file\n";
    exit(1);
}

$db = Database::getConnection();

// Create mitigation project
$filename = basename($scanReportPath, '.json');
$parts = explode('-', $filename);
if (count($parts) >= 3) {
    $dateStr = explode('_', $parts[2])[0]; // 20260308
    $scanDate = DateTime::createFromFormat('Ymd', $dateStr)->format('Y-m-d');
} else {
    $scanDate = date('Y-m-d');
}

$projectName = "Red Team Scan - " . date('Y-m-d', strtotime($scanDate));
$description = "Automated red team security scan conducted on $scanDate";

$stmt = $db->prepare("
    INSERT INTO blueteam.mitigation_projects
    (name, description, scan_date, scan_report_path, status)
    VALUES (?, ?, ?, ?, 'active')
    RETURNING id
");
$stmt->execute([$projectName, $description, $scanDate, $scanReportPath]);
$projectId = $stmt->fetchColumn();

echo "Created mitigation project ID: $projectId\n";

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
        'critical' => 3,    // 48-72 hours
        'high' => 30,       // 30 days
        'medium' => 60,     // 60 days
        'low' => 90         // 90 days
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

    // Count by severity
    if (!isset($severityCounts[$severity])) {
        $severityCounts[$severity] = 0;
    }
    $severityCounts[$severity]++;
}

echo "Imported $importedCount vulnerable findings\n\n";
echo "Summary by Severity:\n";

// Order by severity
$severityOrder = ['critical', 'high', 'medium', 'low'];
foreach ($severityOrder as $sev) {
    if (isset($severityCounts[$sev])) {
        echo "  " . strtoupper($sev) . ": " . $severityCounts[$sev] . "\n";
    }
}

echo "\nImport complete!\n";
