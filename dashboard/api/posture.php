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
    // Fetch posture score history
    $stmt = $pdo->query('SELECT score_id, scored_at, overall_score, compliance_score, redteam_score, monitoring_score, incident_score, malware_score, details, redteam_report_id FROM blueteam.posture_scores ORDER BY scored_at DESC LIMIT 30');
    $history = $stmt->fetchAll();

    $latest = !empty($history) ? $history[0] : null;
    $hasFullScores = $latest && $latest['overall_score'] !== null && $latest['compliance_score'] !== null;

    if ($hasFullScores) {
        $current = [
            'overall' => (float) $latest['overall_score'],
            'compliance' => (float) $latest['compliance_score'],
            'redteam' => (float) $latest['redteam_score'],
            'incident' => (float) $latest['incident_score'],
            'monitoring' => (float) $latest['monitoring_score'],
            'malware' => (float) ($latest['malware_score'] ?? 100.0),
        ];
    } else {
        // Calculate scores dynamically

        // Compliance score
        $stmt = $pdo->query("SELECT status, COUNT(*) as cnt FROM blueteam.compliance_controls GROUP BY status");
        $statusCounts = [];
        $controlsTotal = 0;
        while ($row = $stmt->fetch()) {
            $statusCounts[$row['status']] = (int) $row['cnt'];
            $controlsTotal += (int) $row['cnt'];
        }
        $controlsImplemented = ($statusCounts['implemented'] ?? 0);
        $complianceScore = $controlsTotal > 0 ? round(($controlsImplemented / $controlsTotal) * 100, 2) : 0;

        // Red team score — use latest DB row if available, else scan report files
        $redteamScore = ($latest && $latest['redteam_score'] !== null) ? (float) $latest['redteam_score'] : 0;
        if ($redteamScore == 0) {
            $reportFiles = glob('/opt/claude-workspace/projects/cyber-guardian/reports/redteam-report-*.json');
            if (!empty($reportFiles)) {
                rsort($reportFiles);
                $reportData = json_decode(file_get_contents($reportFiles[0]), true);
                if ($reportData && isset($reportData['total_defended'], $reportData['total_variants'])) {
                    $totalVariants = (int) $reportData['total_variants'];
                    if ($totalVariants > 0) {
                        $redteamScore = round(((int) $reportData['total_defended'] / $totalVariants) * 100, 2);
                    }
                }
            }
        }

        // Incident score
        $stmt = $pdo->query("SELECT severity, COUNT(*) as cnt FROM blueteam.security_incidents WHERE status != 'closed' GROUP BY severity");
        $incidentCounts = ['critical' => 0, 'high' => 0, 'medium' => 0, 'low' => 0];
        while ($row = $stmt->fetch()) {
            $incidentCounts[$row['severity']] = (int) $row['cnt'];
        }
        $incidentScore = max(0, 100 - ($incidentCounts['critical'] * 25 + $incidentCounts['high'] * 15 + $incidentCounts['medium'] * 5));

        // Monitoring score — derived from correlator service state + alert delivery
        $monitoringScore = 80; // baseline
        $corrOut = shell_exec('systemctl show cyber-guardian-correlator --property=ActiveState 2>/dev/null');
        if ($corrOut && strpos(trim($corrOut), 'ActiveState=active') !== false) {
            $monitoringScore += 10;
        }
        $alertOut = shell_exec('journalctl -t eqmon-blueteam --since "30 days ago" --no-pager -o short-iso 2>/dev/null | grep -c SECURITY_INCIDENT 2>/dev/null');
        if ($alertOut && (int) trim($alertOut) > 0) {
            $monitoringScore += 10;
        }

        // Malware score (using database function)
        $malwareScore = 100.0;
        try {
            $stmt = $pdo->query("SELECT blueteam.calculate_malware_score() as score");
            $scoreRow = $stmt->fetch(PDO::FETCH_ASSOC);
            if ($scoreRow) {
                $malwareScore = (float)$scoreRow['score'];
            }
        } catch (PDOException $e) {
            // If malware tables don't exist yet, default to 100
            error_log("Malware score calculation failed: " . $e->getMessage());
        }

        // Overall (new weights: compliance 30%, redteam 25%, incident 20%, monitoring 15%, malware 10%)
        $overallScore = round(
            $complianceScore * 0.30 +
            $redteamScore * 0.25 +
            $incidentScore * 0.20 +
            $monitoringScore * 0.15 +
            $malwareScore * 0.10,
            2
        );

        $current = [
            'overall' => $overallScore,
            'compliance' => $complianceScore,
            'redteam' => $redteamScore,
            'incident' => (float) $incidentScore,
            'monitoring' => (float) $monitoringScore,
            'malware' => $malwareScore,
        ];
    }

    // Compliance control counts
    $stmt = $pdo->query("SELECT COUNT(*) FILTER (WHERE status = 'implemented') as implemented, COUNT(*) as total FROM blueteam.compliance_controls");
    $controlRow = $stmt->fetch();
    $current['controls_implemented'] = (int) $controlRow['implemented'];
    $current['controls_total'] = (int) $controlRow['total'];

    // Active incident counts by severity
    $stmt = $pdo->query("SELECT severity, COUNT(*) as cnt FROM blueteam.security_incidents WHERE status != 'closed' GROUP BY severity");
    $activeIncidents = ['critical' => 0, 'high' => 0, 'medium' => 0, 'low' => 0];
    while ($row = $stmt->fetch()) {
        $activeIncidents[$row['severity']] = (int) $row['cnt'];
    }
    $current['active_incidents'] = $activeIncidents;

    // Format history rows
    $formattedHistory = array_map(function ($row) {
        return [
            'scored_at' => $row['scored_at'],
            'overall_score' => (float) $row['overall_score'],
            'compliance_score' => (float) $row['compliance_score'],
            'redteam_score' => (float) $row['redteam_score'],
            'monitoring_score' => (float) $row['monitoring_score'],
            'incident_score' => (float) $row['incident_score'],
            'malware_score' => (float) ($row['malware_score'] ?? 100.0),
        ];
    }, $history);

    echo json_encode([
        'current' => $current,
        'history' => $formattedHistory
    ]);

} catch (PDOException $e) {
    http_response_code(500);
    echo json_encode(['error' => 'Query failed']);
}
