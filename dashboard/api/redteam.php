<?php
header('Content-Type: application/json');

$userId = $_SERVER['HTTP_X_AUTH_USER_ID'] ?? null;
if (!$userId) {
    http_response_code(401);
    echo json_encode(['error' => 'Unauthorized']);
    exit;
}

try {
    $reportsDir = '/opt/claude-workspace/projects/cyber-guardian/reports';
    $reportFiles = glob("{$reportsDir}/redteam-report-*.json");
    if (empty($reportFiles)) {
        echo json_encode(['error' => 'No red team reports found']);
        exit;
    }

    rsort($reportFiles); // newest first

    // If a specific report is requested, serve it directly
    $requestedReport = $_GET['report'] ?? null;
    if ($requestedReport) {
        $safeName = basename($requestedReport);
        $reportPath = "{$reportsDir}/{$safeName}";
        if (!file_exists($reportPath)) {
            http_response_code(404);
            echo json_encode(['error' => 'Report not found']);
            exit;
        }
        $report = json_decode(file_get_contents($reportPath), true);
        outputReport($report, $reportPath);
        exit;
    }

    // --- Default: merge latest full-suite report with newer partial reports ---

    // Classify reports: "full" has 3+ categories, "partial" has fewer
    $fullReport = null;
    $fullReportPath = null;
    $newerPartials = [];

    foreach ($reportFiles as $file) {
        $data = json_decode(file_get_contents($file), true);
        if ($data === null) continue;

        $categories = array_keys($data['by_category'] ?? []);
        $catCount = count($categories);

        if ($fullReport === null && $catCount >= 3) {
            $fullReport = $data;
            $fullReportPath = $file;
        } elseif ($fullReport === null && $catCount > 0) {
            // This partial is newer than the latest full — queue for merge
            $newerPartials[] = ['data' => $data, 'categories' => $categories, 'path' => $file];
        }
        // Once we have the full report, stop scanning
        if ($fullReport !== null) break;
    }

    // Fallback: no full-suite report found, just use the latest report
    if ($fullReport === null) {
        $report = json_decode(file_get_contents($reportFiles[0]), true);
        outputReport($report, $reportFiles[0]);
        exit;
    }

    // If no newer partials exist, serve the full report as-is
    if (empty($newerPartials)) {
        outputReport($fullReport, $fullReportPath);
        exit;
    }

    // Merge: start with full report, overlay newer partial categories
    $mergedFindings = $fullReport['findings'] ?? [];
    $mergedByCategory = $fullReport['by_category'] ?? [];
    $mergedBySeverity = $fullReport['by_severity'] ?? [];
    $sourceParts = [basename($fullReportPath)];

    foreach ($newerPartials as $partial) {
        $pData = $partial['data'];
        $pCats = $partial['categories'];
        $sourceParts[] = basename($partial['path']);

        // Remove findings from the full report for categories covered by this partial
        $mergedFindings = array_values(array_filter($mergedFindings, function ($f) use ($pCats) {
            return !in_array($f['category'] ?? '', $pCats);
        }));

        // Remove old category stats
        foreach ($pCats as $cat) {
            unset($mergedByCategory[$cat]);
        }

        // Add partial's findings and category stats
        $mergedFindings = array_merge($mergedFindings, $pData['findings'] ?? []);
        foreach ($pData['by_category'] ?? [] as $cat => $stats) {
            $mergedByCategory[$cat] = $stats;
        }
    }

    // Recalculate totals from merged findings
    $totalAttacks = 0;
    $totalVariants = count($mergedFindings);
    $totalVulnerable = 0;
    $totalPartial = 0;
    $totalDefended = 0;
    $totalErrors = 0;
    $attackNames = [];
    $bySeverity = [];

    foreach ($mergedFindings as $f) {
        $status = $f['status'] ?? '';
        $severity = $f['severity'] ?? 'info';
        $attack = $f['attack'] ?? '';

        if (!in_array($attack, $attackNames)) {
            $attackNames[] = $attack;
            $totalAttacks++;
        }

        switch ($status) {
            case 'vulnerable': $totalVulnerable++; break;
            case 'partial':    $totalPartial++; break;
            case 'defended':   $totalDefended++; break;
            case 'error':      $totalErrors++; break;
        }

        if (!isset($bySeverity[$severity])) {
            $bySeverity[$severity] = ['vulnerable' => 0, 'partial' => 0, 'defended' => 0, 'error' => 0];
        }
        if (isset($bySeverity[$severity][$status])) {
            $bySeverity[$severity][$status]++;
        }
    }

    // Determine worst severity
    $sevRank = ['critical' => 1, 'high' => 2, 'medium' => 3, 'low' => 4, 'info' => 5];
    $worstSev = 'info';
    foreach ($mergedFindings as $f) {
        $s = strtolower($f['severity'] ?? 'info');
        if (($sevRank[$s] ?? 99) < ($sevRank[$worstSev] ?? 99)) {
            $worstSev = $s;
        }
    }

    // Use the newest report's timestamp
    $latestGenerated = $newerPartials[0]['data']['generated'] ?? $fullReport['generated'] ?? null;

    // Preserve timing from newest report; merge attacks arrays
    $mergedTiming = $newerPartials[0]['data']['timing'] ?? $fullReport['timing'] ?? null;
    $mergedAttacks = [];
    // Start with full report attacks, then overlay partials
    $fullAttacks = $fullReport['attacks'] ?? [];
    $partialAttackNames = [];
    foreach ($newerPartials as $partial) {
        foreach ($partial['data']['attacks'] ?? [] as $a) {
            $mergedAttacks[] = $a;
            $partialAttackNames[] = $a['name'] ?? '';
        }
    }
    foreach ($fullAttacks as $a) {
        if (!in_array($a['name'] ?? '', $partialAttackNames)) {
            $mergedAttacks[] = $a;
        }
    }

    $merged = [
        'generated' => $latestGenerated,
        'merged_from' => $sourceParts,
        'total_attacks' => $totalAttacks,
        'total_variants' => $totalVariants,
        'total_vulnerable' => $totalVulnerable,
        'total_partial' => $totalPartial,
        'total_defended' => $totalDefended,
        'total_errors' => $totalErrors,
        'worst_severity' => $worstSev,
        'by_category' => $mergedByCategory,
        'by_severity' => $bySeverity,
        'timing' => $mergedTiming,
        'attacks' => $mergedAttacks ?: null,
        'findings' => $mergedFindings,
    ];

    outputReport($merged);

} catch (Exception $e) {
    http_response_code(500);
    echo json_encode(['error' => 'Failed to load red team report']);
}

/**
 * Sort findings and output the final JSON response.
 */
function outputReport(array $report, ?string $path = null): void
{
    $severityOrder = ['critical' => 1, 'high' => 2, 'medium' => 3, 'low' => 4, 'info' => 5];
    $statusOrder = ['vulnerable' => 1, 'partial' => 2, 'defended' => 3, 'error' => 4];

    $findings = $report['findings'] ?? [];
    usort($findings, function ($a, $b) use ($statusOrder, $severityOrder) {
        $sa = $statusOrder[$a['status']] ?? 99;
        $sb = $statusOrder[$b['status']] ?? 99;
        if ($sa !== $sb) return $sa - $sb;
        $sevA = $severityOrder[$a['severity']] ?? 99;
        $sevB = $severityOrder[$b['severity']] ?? 99;
        return $sevA - $sevB;
    });

    echo json_encode([
        'generated' => $report['generated'] ?? null,
        'merged_from' => $report['merged_from'] ?? ($path ? [basename($path)] : null),
        'total_attacks' => (int) ($report['total_attacks'] ?? 0),
        'total_variants' => (int) ($report['total_variants'] ?? 0),
        'total_vulnerable' => (int) ($report['total_vulnerable'] ?? 0),
        'total_partial' => (int) ($report['total_partial'] ?? 0),
        'total_defended' => (int) ($report['total_defended'] ?? 0),
        'total_errors' => (int) ($report['total_errors'] ?? 0),
        'by_category' => $report['by_category'] ?? new \stdClass(),
        'by_severity' => $report['by_severity'] ?? new \stdClass(),
        'timing' => $report['timing'] ?? null,
        'attacks' => $report['attacks'] ?? null,
        'findings' => $findings,
    ]);
}
