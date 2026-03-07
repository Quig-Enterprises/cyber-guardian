<?php
/**
 * Post-Scan Notification Processor (CLI only)
 *
 * Usage: php process-scan.php /path/to/redteam-report.json
 *
 * Called by run-redteam.sh after each scan completes.
 * Loads the report, processes notification subscriptions, and dispatches emails.
 */

if (php_sapi_name() !== 'cli') {
    http_response_code(403);
    echo "CLI only\n";
    exit(1);
}

if (empty($argv[1])) {
    echo "Usage: php process-scan.php <report-path>\n";
    exit(1);
}

$reportPath = $argv[1];

if (!is_file($reportPath)) {
    echo "Error: Report file not found: {$reportPath}\n";
    exit(1);
}

require_once __DIR__ . '/lib/db.php';
require_once __DIR__ . '/lib/SecurityMailer.php';
require_once __DIR__ . '/lib/NotificationProcessor.php';

echo "Processing post-scan notifications for: {$reportPath}\n";

try {
    $result = NotificationProcessor::processPostScanNotifications($reportPath);

    echo json_encode([
        'status' => 'complete',
        'report' => basename($reportPath),
        'total_findings' => $result['total_findings'],
        'notifications_sent' => $result['notifications_sent'],
        'notifications_skipped' => $result['notifications_skipped'],
        'errors' => $result['errors'],
    ], JSON_PRETTY_PRINT) . "\n";

    if ($result['errors'] > 0) {
        exit(2); // partial failure
    }
} catch (Throwable $e) {
    echo "Error: " . $e->getMessage() . "\n";
    error_log("process-scan.php fatal: " . $e->getMessage());
    exit(1);
}
