<?php
// Temporary script to query Project 1 details
// DELETE after use

header('Content-Type: text/plain');

require_once '/var/www/html/alfred/dashboard/admin/lib/db.php';

$pdo = getAdminDb();  // Uses alfred_admin database

// Get Project 1 details
$project = $pdo->query("SELECT * FROM blueteam.mitigation_projects WHERE id = 1")->fetch(PDO::FETCH_ASSOC);
echo "PROJECT 1:\n";
echo "Name: {$project['name']}\n";
echo "Description: {$project['description']}\n";
echo "Scan Date: {$project['scan_date']}\n";
echo "Report: {$project['scan_report_path']}\n";

// Count severity levels
$severities = $pdo->query("
    SELECT severity, COUNT(*) as count
    FROM blueteam.mitigation_issues
    WHERE project_id = 1
    GROUP BY severity
    ORDER BY CASE severity
        WHEN 'CRITICAL' THEN 1
        WHEN 'HIGH' THEN 2
        WHEN 'MEDIUM' THEN 3
        WHEN 'LOW' THEN 4
    END
")->fetchAll(PDO::FETCH_ASSOC);

echo "\nSEVERITY COUNTS:\n";
foreach ($severities as $sev) {
    echo "{$sev['severity']}: {$sev['count']}\n";
}

// Count by category
$categories = $pdo->query("
    SELECT category, COUNT(*) as count
    FROM blueteam.mitigation_issues
    WHERE project_id = 1
    GROUP BY category
    ORDER BY count DESC
")->fetchAll(PDO::FETCH_ASSOC);

echo "\nCATEGORY COUNTS:\n";
foreach ($categories as $cat) {
    echo "{$cat['category']}: {$cat['count']}\n";
}

// Total count
$total = $pdo->query("SELECT COUNT(*) FROM blueteam.mitigation_issues WHERE project_id = 1")->fetchColumn();
echo "\nTOTAL ISSUES: $total\n";

// Sample of issues
echo "\nSAMPLE ISSUES (first 10):\n";
$issues = $pdo->query("
    SELECT title, severity, category, attack_name
    FROM blueteam.mitigation_issues
    WHERE project_id = 1
    ORDER BY
        CASE severity
            WHEN 'CRITICAL' THEN 1
            WHEN 'HIGH' THEN 2
            WHEN 'MEDIUM' THEN 3
            WHEN 'LOW' THEN 4
        END,
        id
    LIMIT 10
")->fetchAll(PDO::FETCH_ASSOC);

foreach ($issues as $issue) {
    echo "\n[{$issue['severity']}] {$issue['title']}\n";
    echo "  Category: {$issue['category']} | Attack: {$issue['attack_name']}\n";
}
