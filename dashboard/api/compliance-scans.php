<?php
/**
 * Compliance Scanner API Endpoint
 *
 * Provides infrastructure compliance scanning data for the security dashboard
 * (Separate from compliance.php which handles NIST 800-171 controls)
 *
 * Endpoints:
 * - GET ?action=summary - Overall compliance summary across all servers
 * - GET ?action=server&name={server} - Detailed compliance data for specific server
 * - GET ?action=findings&severity={sev}&category={cat}&server={name} - Filtered findings
 * - GET ?action=categories - Compliance stats grouped by category
 * - GET ?action=history&server={name}&days={n} - Historical compliance scores
 */

header('Content-Type: application/json');

// Authentication check
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
    error_log("Compliance Scanner API: Database connection failed - " . $e->getMessage());
    echo json_encode(['error' => 'Database connection failed']);
    exit;
}

// Get action parameter
$action = $_GET['action'] ?? 'summary';

try {
    switch ($action) {
        case 'summary':
            handleSummary($pdo);
            break;

        case 'server':
            handleServer($pdo);
            break;

        case 'findings':
            handleFindings($pdo);
            break;

        case 'categories':
            handleCategories($pdo);
            break;

        case 'history':
            handleHistory($pdo);
            break;

        default:
            http_response_code(400);
            echo json_encode(['error' => 'Invalid action parameter']);
            exit;
    }
} catch (PDOException $e) {
    http_response_code(500);
    error_log("Compliance Scanner API Error (action={$action}): " . $e->getMessage());
    echo json_encode([
        'error' => 'Database query failed',
        'message' => $e->getMessage()
    ]);
}

/**
 * GET ?action=summary
 *
 * Returns overall compliance summary across all servers
 * Uses v_compliance_summary_by_server view
 */
function handleSummary(PDO $pdo): void {
    // Get summary data from view
    $stmt = $pdo->query("
        SELECT
            s.server_name,
            s.server_type,
            ls.scan_date as latest_scan_date,
            ls.overall_score,
            s.critical_findings,
            s.high_findings,
            s.medium_findings,
            s.low_findings,
            s.passing_checks,
            (s.critical_findings + s.high_findings + s.medium_findings + s.low_findings) as total_findings
        FROM blueteam.v_compliance_summary_by_server s
        JOIN blueteam.v_latest_compliance_scans ls ON s.server_name = ls.server_name
        ORDER BY s.server_name
    ");
    $servers = $stmt->fetchAll(PDO::FETCH_ASSOC);

    // Calculate overall compliance score across all servers
    $stmt = $pdo->query("SELECT blueteam.calculate_compliance_score() as overall_score");
    $scoreRow = $stmt->fetch(PDO::FETCH_ASSOC);
    $overallScore = $scoreRow['overall_score'] !== null ? (float)$scoreRow['overall_score'] : null;

    // Get total counts across all servers
    $totalCritical = 0;
    $totalHigh = 0;
    $totalMedium = 0;
    $totalLow = 0;
    $totalPassing = 0;

    foreach ($servers as &$server) {
        // Cast numeric values
        $server['overall_score'] = $server['overall_score'] !== null ? (float)$server['overall_score'] : null;
        $server['critical_findings'] = (int)$server['critical_findings'];
        $server['high_findings'] = (int)$server['high_findings'];
        $server['medium_findings'] = (int)$server['medium_findings'];
        $server['low_findings'] = (int)$server['low_findings'];
        $server['passing_checks'] = (int)$server['passing_checks'];
        $server['total_findings'] = (int)$server['total_findings'];

        $totalCritical += $server['critical_findings'];
        $totalHigh += $server['high_findings'];
        $totalMedium += $server['medium_findings'];
        $totalLow += $server['low_findings'];
        $totalPassing += $server['passing_checks'];
    }

    echo json_encode([
        'overall_score' => $overallScore,
        'total_servers' => count($servers),
        'total_findings' => $totalCritical + $totalHigh + $totalMedium + $totalLow,
        'severity_totals' => [
            'critical' => $totalCritical,
            'high' => $totalHigh,
            'medium' => $totalMedium,
            'low' => $totalLow,
            'passing' => $totalPassing
        ],
        'servers' => $servers,
        'timestamp' => date('c')
    ]);
}

/**
 * GET ?action=server&name={server_name}
 *
 * Returns detailed compliance data for a specific server
 * Includes latest scan info and all findings with remediation steps
 */
function handleServer(PDO $pdo): void {
    $serverName = $_GET['name'] ?? null;

    if (!$serverName) {
        http_response_code(400);
        echo json_encode(['error' => 'Missing required parameter: name']);
        exit;
    }

    // Validate server name (alphanumeric, dash, underscore only)
    if (!preg_match('/^[a-zA-Z0-9_-]+$/', $serverName)) {
        http_response_code(400);
        echo json_encode(['error' => 'Invalid server name format']);
        exit;
    }

    // Get latest scan for this server
    $stmt = $pdo->prepare("
        SELECT
            scan_id,
            server_name,
            server_type,
            scan_date,
            scan_duration_seconds,
            overall_score,
            findings_critical,
            findings_high,
            findings_medium,
            findings_low,
            findings_pass,
            checks_total,
            checks_run,
            checks_skipped,
            metadata
        FROM blueteam.v_latest_compliance_scans
        WHERE server_name = ?
    ");
    $stmt->execute([$serverName]);
    $scan = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$scan) {
        http_response_code(404);
        echo json_encode(['error' => 'Server not found or no scans available']);
        exit;
    }

    // Cast numeric values
    $scan['scan_duration_seconds'] = (int)$scan['scan_duration_seconds'];
    $scan['overall_score'] = $scan['overall_score'] !== null ? (float)$scan['overall_score'] : null;
    $scan['findings_critical'] = (int)$scan['findings_critical'];
    $scan['findings_high'] = (int)$scan['findings_high'];
    $scan['findings_medium'] = (int)$scan['findings_medium'];
    $scan['findings_low'] = (int)$scan['findings_low'];
    $scan['findings_pass'] = (int)$scan['findings_pass'];
    $scan['checks_total'] = (int)$scan['checks_total'];
    $scan['checks_run'] = (int)$scan['checks_run'];
    $scan['checks_skipped'] = (int)$scan['checks_skipped'];
    $scan['metadata'] = json_decode($scan['metadata'], true);

    // Get all findings for this scan
    $stmt = $pdo->prepare("
        SELECT
            finding_id,
            check_category,
            check_name,
            check_id,
            status,
            severity,
            finding_summary,
            finding_details,
            remediation_steps,
            aws_resource_id,
            aws_resource_type,
            file_path,
            service_name,
            cis_benchmark,
            aws_foundational_security,
            nist_csf,
            detected_at,
            resolved_at,
            resolved_by,
            resolution_notes
        FROM blueteam.compliance_findings
        WHERE scan_id = ?
        ORDER BY
            CASE status
                WHEN 'fail' THEN 1
                WHEN 'warning' THEN 2
                WHEN 'info' THEN 3
                WHEN 'skip' THEN 4
                WHEN 'pass' THEN 5
            END,
            CASE severity
                WHEN 'critical' THEN 1
                WHEN 'high' THEN 2
                WHEN 'medium' THEN 3
                WHEN 'low' THEN 4
                ELSE 5
            END,
            check_category,
            check_name
    ");
    $stmt->execute([$scan['scan_id']]);
    $findings = $stmt->fetchAll(PDO::FETCH_ASSOC);

    // Cast boolean values
    foreach ($findings as &$finding) {
        $finding['finding_id'] = (int)$finding['finding_id'];
        $finding['resolved'] = $finding['resolved_at'] !== null;
    }

    echo json_encode([
        'scan' => $scan,
        'findings' => $findings,
        'timestamp' => date('c')
    ]);
}

/**
 * GET ?action=findings&severity={severity}&category={category}&server={name}
 *
 * Returns active findings filtered by parameters
 * All parameters are optional filters
 */
function handleFindings(PDO $pdo): void {
    $severity = $_GET['severity'] ?? null;
    $category = $_GET['category'] ?? null;
    $server = $_GET['server'] ?? null;

    // Build WHERE clause dynamically
    $where = ["f.status = 'fail'", "f.resolved_at IS NULL"];
    $params = [];

    if ($severity) {
        // Validate severity
        $validSeverities = ['critical', 'high', 'medium', 'low'];
        if (!in_array($severity, $validSeverities, true)) {
            http_response_code(400);
            echo json_encode(['error' => 'Invalid severity value']);
            exit;
        }
        $where[] = "f.severity = ?";
        $params[] = $severity;
    }

    if ($category) {
        // Validate category (alphanumeric, dash, underscore only)
        if (!preg_match('/^[a-zA-Z0-9_-]+$/', $category)) {
            http_response_code(400);
            echo json_encode(['error' => 'Invalid category format']);
            exit;
        }
        $where[] = "f.check_category = ?";
        $params[] = $category;
    }

    if ($server) {
        // Validate server name
        if (!preg_match('/^[a-zA-Z0-9_-]+$/', $server)) {
            http_response_code(400);
            echo json_encode(['error' => 'Invalid server name format']);
            exit;
        }
        $where[] = "s.server_name = ?";
        $params[] = $server;
    }

    $whereClause = implode(' AND ', $where);

    $stmt = $pdo->prepare("
        SELECT
            f.finding_id,
            s.server_name,
            s.server_type,
            f.check_category,
            f.check_name,
            f.check_id,
            f.severity,
            f.finding_summary,
            f.finding_details,
            f.remediation_steps,
            f.aws_resource_id,
            f.aws_resource_type,
            f.file_path,
            f.service_name,
            f.cis_benchmark,
            f.aws_foundational_security,
            f.nist_csf,
            f.detected_at,
            s.scan_date
        FROM blueteam.compliance_findings f
        JOIN blueteam.compliance_scans s ON f.scan_id = s.scan_id
        WHERE {$whereClause}
        ORDER BY
            CASE f.severity
                WHEN 'critical' THEN 1
                WHEN 'high' THEN 2
                WHEN 'medium' THEN 3
                WHEN 'low' THEN 4
                ELSE 5
            END,
            f.detected_at DESC
        LIMIT 500
    ");

    $stmt->execute($params);
    $findings = $stmt->fetchAll(PDO::FETCH_ASSOC);

    // Cast numeric values
    foreach ($findings as &$finding) {
        $finding['finding_id'] = (int)$finding['finding_id'];
    }

    echo json_encode([
        'filters' => [
            'severity' => $severity,
            'category' => $category,
            'server' => $server
        ],
        'total_findings' => count($findings),
        'findings' => $findings,
        'timestamp' => date('c')
    ]);
}

/**
 * GET ?action=categories
 *
 * Returns compliance stats grouped by category
 * Uses v_compliance_by_category view
 */
function handleCategories(PDO $pdo): void {
    $stmt = $pdo->query("
        SELECT
            server_name,
            check_category,
            critical,
            high,
            medium,
            low,
            pass,
            total_checks,
            CASE
                WHEN total_checks > 0 THEN
                    ROUND(100.0 * pass / total_checks, 2)
                ELSE NULL
            END as pass_rate
        FROM blueteam.v_compliance_by_category
        ORDER BY server_name, check_category
    ");
    $categories = $stmt->fetchAll(PDO::FETCH_ASSOC);

    // Cast numeric values
    foreach ($categories as &$category) {
        $category['critical'] = (int)$category['critical'];
        $category['high'] = (int)$category['high'];
        $category['medium'] = (int)$category['medium'];
        $category['low'] = (int)$category['low'];
        $category['pass'] = (int)$category['pass'];
        $category['total_checks'] = (int)$category['total_checks'];
        $category['pass_rate'] = $category['pass_rate'] !== null ? (float)$category['pass_rate'] : null;
    }

    // Group by server for easier consumption
    $byServer = [];
    foreach ($categories as $category) {
        $serverName = $category['server_name'];
        unset($category['server_name']);

        if (!isset($byServer[$serverName])) {
            $byServer[$serverName] = [];
        }
        $byServer[$serverName][] = $category;
    }

    echo json_encode([
        'categories_by_server' => $byServer,
        'all_categories' => $categories,
        'timestamp' => date('c')
    ]);
}

/**
 * GET ?action=history&server={name}&days={n}
 *
 * Returns historical compliance scores for trend analysis
 */
function handleHistory(PDO $pdo): void {
    $serverName = $_GET['server'] ?? null;
    $days = (int)($_GET['days'] ?? 30);

    // Validate days parameter
    if ($days < 1 || $days > 365) {
        http_response_code(400);
        echo json_encode(['error' => 'Invalid days parameter (must be 1-365)']);
        exit;
    }

    // Build query
    $where = "scan_date >= NOW() - INTERVAL '{$days} days'";
    $params = [];

    if ($serverName) {
        // Validate server name
        if (!preg_match('/^[a-zA-Z0-9_-]+$/', $serverName)) {
            http_response_code(400);
            echo json_encode(['error' => 'Invalid server name format']);
            exit;
        }
        $where .= " AND server_name = ?";
        $params[] = $serverName;
    }

    $stmt = $pdo->prepare("
        SELECT
            server_name,
            scan_date,
            overall_score,
            findings_critical,
            findings_high,
            findings_medium,
            findings_low,
            findings_pass,
            checks_total
        FROM blueteam.compliance_scans
        WHERE {$where}
        ORDER BY server_name, scan_date ASC
    ");

    $stmt->execute($params);
    $history = $stmt->fetchAll(PDO::FETCH_ASSOC);

    // Cast numeric values
    foreach ($history as &$entry) {
        $entry['overall_score'] = $entry['overall_score'] !== null ? (float)$entry['overall_score'] : null;
        $entry['findings_critical'] = (int)$entry['findings_critical'];
        $entry['findings_high'] = (int)$entry['findings_high'];
        $entry['findings_medium'] = (int)$entry['findings_medium'];
        $entry['findings_low'] = (int)$entry['findings_low'];
        $entry['findings_pass'] = (int)$entry['findings_pass'];
        $entry['checks_total'] = (int)$entry['checks_total'];
    }

    // Group by server for trend analysis
    $byServer = [];
    foreach ($history as $entry) {
        $serverName = $entry['server_name'];
        if (!isset($byServer[$serverName])) {
            $byServer[$serverName] = [];
        }
        $byServer[$serverName][] = $entry;
    }

    echo json_encode([
        'days' => $days,
        'server_filter' => $serverName,
        'total_scans' => count($history),
        'history_by_server' => $byServer,
        'all_history' => $history,
        'timestamp' => date('c')
    ]);
}
