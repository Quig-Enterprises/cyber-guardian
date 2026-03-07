<?php
header('Content-Type: application/json');

$userId = $_SERVER['HTTP_X_AUTH_USER_ID'] ?? null;
if (!$userId) {
    http_response_code(401);
    echo json_encode(['error' => 'Unauthorized']);
    exit;
}

try {
    $reportFiles = glob('/opt/security-red-team/reports/redteam-report-*.json');
    if ($reportFiles === false) {
        http_response_code(500);
        echo json_encode(['error' => 'Failed to scan reports directory']);
        exit;
    }

    rsort($reportFiles);

    $reports = [];
    foreach ($reportFiles as $filePath) {
        $raw = file_get_contents($filePath);
        if ($raw === false) {
            continue;
        }

        $report = json_decode($raw, true);
        if ($report === null) {
            continue;
        }

        $timestamp = null;
        if (preg_match('/redteam-report-(\d{8}_\d{6})\.json$/', $filePath, $matches)) {
            $timestamp = $matches[1];
        }

        $hasHtml = false;
        if ($timestamp !== null) {
            $htmlPath = '/opt/security-red-team/reports/redteam-report-' . $timestamp . '.html';
            $hasHtml = file_exists($htmlPath);
        }

        $reports[] = [
            'timestamp'        => $timestamp,
            'generated'        => $report['generated'] ?? null,
            'total_attacks'    => (int) ($report['total_attacks'] ?? 0),
            'total_variants'   => (int) ($report['total_variants'] ?? 0),
            'total_vulnerable' => (int) ($report['total_vulnerable'] ?? 0),
            'total_partial'    => (int) ($report['total_partial'] ?? 0),
            'total_defended'   => (int) ($report['total_defended'] ?? 0),
            'total_errors'     => (int) ($report['total_errors'] ?? 0),
            'worst_severity'   => $report['worst_severity'] ?? null,
            'has_html'         => $hasHtml,
        ];
    }

    echo json_encode($reports);

} catch (Exception $e) {
    http_response_code(500);
    echo json_encode(['error' => 'Failed to list red team reports']);
}
