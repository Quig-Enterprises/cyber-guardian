<?php
/**
 * Mitigation Dashboard API
 * Serves security mitigation metrics and project status
 */

header('Content-Type: application/json');

// Paths
$base_dir = dirname(dirname(__DIR__));
$state_dir = "$base_dir/.scan-state";
$reports_dir = "$base_dir/reports";
$metrics_file = "$state_dir/mitigation_metrics.json";
$scan_log = "$state_dir/scan.log";

// Find latest codebase scan report
$latest_report = null;
if (is_dir($reports_dir)) {
    $report_files = glob("$reports_dir/codebase-security-scan-*.md");
    if ($report_files) {
        sort($report_files);
        $latest_report = end($report_files);
    }
}

// Response structure
$response = [
    'success' => true,
    'summary' => [
        'total_issues' => 0,
        'critical' => 0,
        'high' => 0,
        'medium' => 0,
        'net_improvement' => 0,
        'last_updated' => null
    ],
    'projects' => [],
    'activity' => [],
    'trend' => []
];

// Load metrics
if (file_exists($metrics_file)) {
    $metrics = json_decode(file_get_contents($metrics_file), true);
    if ($metrics && isset($metrics['current'])) {
        $response['summary'] = [
            'total_issues' => $metrics['current']['total_issues'] ?? 0,
            'critical' => 0, // Will get from dashboard
            'high' => 0,     // Will get from dashboard
            'medium' => 0,   // Will get from dashboard
            'net_improvement' => $metrics['current']['net_improvement'] ?? 0,
            'last_updated' => $metrics['current']['last_updated'] ?? null
        ];

        // Trend data (last 24 hours)
        if (isset($metrics['history'])) {
            $response['trend'] = array_slice($metrics['history'], -24);
        }
    }
}

// Parse latest scan report for project list and severity counts
if ($latest_report && file_exists($latest_report)) {
    $content = file_get_contents($latest_report);

    // Extract overall severity counts from Executive Summary table
    // Format: | **CRITICAL** | 149 |
    if (preg_match('/\| \*\*CRITICAL\*\* \| (\d+) \|/', $content, $matches)) {
        $response['summary']['critical'] = (int)$matches[1];
    }
    if (preg_match('/\| \*\*HIGH\*\* \| (\d+) \|/', $content, $matches)) {
        $response['summary']['high'] = (int)$matches[1];
    }
    if (preg_match('/\| \*\*MEDIUM\*\* \| (\d+) \|/', $content, $matches)) {
        $response['summary']['medium'] = (int)$matches[1];
    }
    if (preg_match('/\| \*\*Total Issues\*\* \| (\d+) \|/', $content, $matches)) {
        $response['summary']['total_issues'] = (int)$matches[1];
    }

    // Extract Projects Summary table
    // Format: | Project | Files | Issues | CRITICAL | HIGH | MEDIUM | LOW |
    $lines = explode("\n", $content);
    $in_projects_table = false;
    foreach ($lines as $line) {
        if (strpos($line, '| Project | Files | Issues |') !== false) {
            $in_projects_table = true;
            continue;
        }
        if ($in_projects_table) {
            if (strpos($line, '|') !== 0) break; // end of table
            if (strpos($line, '---') !== false) continue; // separator row

            // Parse: | project | files | issues | critical | high | medium | low |
            $cols = array_map('trim', explode('|', trim($line, '|')));
            if (count($cols) < 7) continue;

            $project_name = $cols[0];
            if ($project_name === '') continue;

            $total    = (int)$cols[2];
            $critical = (int)$cols[3];
            $high     = (int)$cols[4];
            $medium   = (int)$cols[5];

            // Look for a TODO.md for this project in known plugin/project locations
            $todo_link = null;
            $plugin_todo = "/var/www/html/wordpress/wp-content/plugins/{$project_name}/TODO.md";
            $project_todo = "/opt/claude-workspace/projects/{$project_name}/TODO.md";
            if (file_exists($plugin_todo)) {
                $todo_link = $plugin_todo;
            } elseif (file_exists($project_todo)) {
                $todo_link = $project_todo;
            }

            $response['projects'][] = [
                'name'      => $project_name,
                'critical'  => $critical,
                'high'      => $high,
                'medium'    => $medium,
                'total'     => $total,
                'todo_path' => $todo_link
            ];
        }
    }
}

// Parse scan log for recent activity (last 10 entries)
if (file_exists($scan_log)) {
    $log_lines = file($scan_log, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    $recent_lines = array_slice($log_lines, -20); // Last 20 lines

    foreach (array_reverse($recent_lines) as $line) {
        // Parse log format: [2026-03-07 21:00:55] Message
        if (preg_match('/\[(.+?)\] (.+)/', $line, $matches)) {
            $timestamp = $matches[1];
            $message = $matches[2];

            // Remove ANSI color codes
            $message = preg_replace('/\\033\[[0-9;]+m/', '', $message);

            // Only include interesting events
            if (strpos($message, 'FIXED:') !== false ||
                strpos($message, 'NEW:') !== false ||
                strpos($message, 'IMPROVEMENT:') !== false ||
                strpos($message, 'ALERT:') !== false ||
                strpos($message, 'Scan complete:') !== false) {

                $event_type = 'info';
                if (strpos($message, 'FIXED:') !== false) $event_type = 'success';
                if (strpos($message, 'ALERT:') !== false) $event_type = 'warning';
                if (strpos($message, 'NEW:') !== false) $event_type = 'warning';

                $response['activity'][] = [
                    'timestamp' => $timestamp,
                    'type' => $event_type,
                    'message' => $message
                ];

                // Limit to 10 activity items
                if (count($response['activity']) >= 10) break;
            }
        }
    }
}

// Output JSON
echo json_encode($response, JSON_PRETTY_PRINT);
