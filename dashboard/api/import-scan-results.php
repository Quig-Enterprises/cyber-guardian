<?php
/**
 * Import Red Team Scan Results into Mitigation Database
 * One-time import script - DELETE after use
 */

header('Content-Type: text/plain');

// Security: Require authentication
$userId = $_SERVER['HTTP_X_AUTH_USER_ID'] ?? null;
$isSuper = ($_SERVER['HTTP_X_AUTH_SUPER'] ?? 'false') === 'true';

if (!$userId || !$isSuper) {
    http_response_code(403);
    die("ERROR: Super admin access required\n");
}

// Database connection
try {
    $pdo = new PDO(
        'pgsql:host=127.0.0.1;dbname=alfred_admin',
        'alfred_admin',
        'Xk9OUuMWtRkBEnY2jugt6992',
        [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC
        ]
    );
} catch (Exception $e) {
    die("ERROR: Database connection failed: " . $e->getMessage() . "\n");
}

// Find the most recent scan report
$reportsDir = '/opt/claude-workspace/projects/cyber-guardian/reports';
$jsonFiles = glob($reportsDir . '/redteam-report-*.json');
if (empty($jsonFiles)) {
    die("ERROR: No scan reports found in $reportsDir\n");
}

// Sort by modification time (newest first)
usort($jsonFiles, function($a, $b) {
    return filemtime($b) - filemtime($a);
});

$reportFile = $jsonFiles[0];
echo "Found scan report: $reportFile\n";
echo "Modified: " . date('Y-m-d H:i:s', filemtime($reportFile)) . "\n\n";

// Load the report
$reportData = json_decode(file_get_contents($reportFile), true);
if (!$reportData) {
    die("ERROR: Failed to parse JSON report\n");
}

// Extract metadata
$targetUrl = $reportData['target'] ?? 'Unknown';
$scanDate = $reportData['scan_date'] ?? date('Y-m-d');
$summary = $reportData['summary'] ?? [];

echo "Target: $targetUrl\n";
echo "Scan Date: $scanDate\n";
echo "Total Attacks: " . ($summary['attacks_executed'] ?? 0) . "\n";
echo "Vulnerable: " . ($summary['vulnerable'] ?? 0) . "\n\n";

// Check if project already exists for this target
$existingProject = $pdo->prepare("
    SELECT id FROM blueteam.mitigation_projects
    WHERE target_url = :url AND scan_date = :date
");
$existingProject->execute([':url' => $targetUrl, ':date' => $scanDate]);
$existing = $existingProject->fetch();

if ($existing) {
    die("ERROR: Project already exists for this target and date (ID: {$existing['id']})\n" .
        "Delete it first if you want to re-import.\n");
}

// Determine project name
$projectName = "Red Team Scan - " . parse_url($targetUrl, PHP_URL_HOST);

echo "Creating mitigation project: $projectName\n";

// Create project
$stmt = $pdo->prepare("
    INSERT INTO blueteam.mitigation_projects
    (name, description, scan_date, target_url, scan_report_path, status)
    VALUES (:name, :desc, :date, :url, :report, 'active')
    RETURNING id
");
$stmt->execute([
    ':name' => $projectName,
    ':desc' => 'Automated red team security scan',
    ':date' => $scanDate,
    ':url' => $targetUrl,
    ':report' => $reportFile
]);
$projectId = $stmt->fetchColumn();

echo "Created project ID: $projectId\n\n";

// Import issues from attacks
$issuesImported = 0;
$attacks = $reportData['attacks'] ?? [];

foreach ($attacks as $attack) {
    $attackName = $attack['name'] ?? 'Unknown';
    $category = $attack['category'] ?? 'unknown';
    $variants = $attack['variants'] ?? [];

    foreach ($variants as $variant) {
        if ($variant['status'] !== 'vulnerable') {
            continue; // Only import vulnerable findings
        }

        $severity = strtolower($variant['severity'] ?? 'medium');
        $description = $variant['description'] ?? '';
        $evidence = $variant['evidence'] ?? '';
        $recommendation = $variant['recommendation'] ?? '';

        $title = $attackName . ": " . ($variant['name'] ?? 'Vulnerability detected');

        $stmt = $pdo->prepare("
            INSERT INTO blueteam.mitigation_issues
            (project_id, title, severity, category, attack_name, status, priority, evidence)
            VALUES (:pid, :title, :severity, :category, :attack, 'not_started', 3, :evidence)
        ");

        $stmt->execute([
            ':pid' => $projectId,
            ':title' => $title,
            ':severity' => $severity,
            ':category' => $category,
            ':attack' => $attackName,
            ':evidence' => json_encode([
                'description' => $description,
                'evidence' => $evidence,
                'recommendation' => $recommendation
            ])
        ]);

        $issuesImported++;
    }
}

echo "Imported $issuesImported vulnerable findings\n";

// Show summary by severity
$severityCounts = $pdo->prepare("
    SELECT severity, COUNT(*) as count
    FROM blueteam.mitigation_issues
    WHERE project_id = :pid
    GROUP BY severity
    ORDER BY CASE severity
        WHEN 'critical' THEN 1
        WHEN 'high' THEN 2
        WHEN 'medium' THEN 3
        WHEN 'low' THEN 4
    END
");
$severityCounts->execute([':pid' => $projectId]);

echo "\nSeverity Breakdown:\n";
foreach ($severityCounts->fetchAll() as $row) {
    echo "  " . strtoupper($row['severity']) . ": " . $row['count'] . "\n";
}

echo "\n✅ Import completed successfully!\n";
echo "View in dashboard: /security-dashboard/#mitigation\n";
