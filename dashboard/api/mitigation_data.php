<?php
/**
 * Mitigation Dashboard API
 * Serves security mitigation metrics and project status
 */

header('Content-Type: application/json');

// Paths
$base_dir = dirname(dirname(__DIR__));
$state_dir = "$base_dir/.scan-state";
$dashboard_file = "$base_dir/MITIGATION_DASHBOARD.md";
$metrics_file = "$state_dir/mitigation_metrics.json";
$scan_log = "$state_dir/scan.log";

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

// Parse dashboard for project list and severity counts
if (file_exists($dashboard_file)) {
    $content = file_get_contents($dashboard_file);

    // Extract overall severity counts from overview table
    if (preg_match('/\| \*\*CRITICAL Issues\*\* \| \*\*(\d+)\*\*/', $content, $matches)) {
        $response['summary']['critical'] = (int)$matches[1];
    }
    if (preg_match('/\| \*\*HIGH Issues\*\* \| \*\*(\d+)\*\*/', $content, $matches)) {
        $response['summary']['high'] = (int)$matches[1];
    }
    if (preg_match('/\| MEDIUM Issues \| (\d+)/', $content, $matches)) {
        $response['summary']['medium'] = (int)$matches[1];
    }

    // Extract project table rows
    $lines = explode("\n", $content);
    $in_table = false;
    foreach ($lines as $line) {
        if (strpos($line, '| Project | Critical |') !== false) {
            $in_table = true;
            continue;
        }
        if ($in_table && strpos($line, '|') === 0) {
            if (strpos($line, '---') !== false) continue;
            if (strpos($line, '## Quick Actions') !== false) break;

            // Parse project row: | name | critical | high | medium | total | TODO |
            $cols = array_map('trim', explode('|', trim($line, '|')));
            if (count($cols) >= 6) {
                $project_name = $cols[0];
                // Extract TODO link
                $todo_link = null;
                if (preg_match('/\[TODO\]\((.+?)\)/', $cols[5], $matches)) {
                    $todo_link = $matches[1];
                }

                $response['projects'][] = [
                    'name' => $project_name,
                    'critical' => (int)$cols[1],
                    'high' => (int)$cols[2],
                    'medium' => (int)$cols[3],
                    'total' => (int)$cols[4],
                    'todo_path' => $todo_link
                ];
            }
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
