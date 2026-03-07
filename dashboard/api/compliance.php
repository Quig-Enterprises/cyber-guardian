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
    // Family-level counts grouped by status
    $stmt = $pdo->query("
        SELECT family, family_id, status, COUNT(*) as cnt
        FROM blueteam.compliance_controls
        GROUP BY family, family_id, status
        ORDER BY family_id
    ");
    $rows = $stmt->fetchAll();

    $familyMap = [];
    $totals = [
        'implemented' => 0,
        'partially_implemented' => 0,
        'not_assessed' => 0,
        'not_applicable' => 0,
        'planned' => 0,
        'not_implemented' => 0
    ];

    foreach ($rows as $row) {
        $key = $row['family_id'];
        if (!isset($familyMap[$key])) {
            $familyMap[$key] = [
                'name' => $row['family'],
                'family_id' => $row['family_id'],
                'implemented' => 0,
                'partially_implemented' => 0,
                'not_assessed' => 0,
                'not_applicable' => 0,
                'planned' => 0,
                'not_implemented' => 0,
                'total' => 0
            ];
        }
        $status = $row['status'];
        $cnt = (int) $row['cnt'];
        if (isset($familyMap[$key][$status])) {
            $familyMap[$key][$status] = $cnt;
        }
        $familyMap[$key]['total'] += $cnt;

        if (isset($totals[$status])) {
            $totals[$status] += $cnt;
        }
    }

    $families = array_values($familyMap);

    // All controls for expandable detail
    $stmt = $pdo->query("
        SELECT control_id, family, family_id, status, requirement, implementation_notes,
               evidence_type, responsible_party, last_assessed, assessor_notes, cmmc_level
        FROM blueteam.compliance_controls
        ORDER BY split_part(control_id, '.', 1)::int,
               split_part(control_id, '.', 2)::int,
               CASE WHEN regexp_replace(split_part(control_id, '.', 3), '[^0-9]', '', 'g') = '' THEN 0
                    ELSE regexp_replace(split_part(control_id, '.', 3), '[^0-9]', '', 'g')::int END,
               split_part(control_id, '.', 3)
    ");
    $controls = $stmt->fetchAll();

    // CMMC cumulative summary per level (1 = level<=1, 2 = level<=2, 3 = level<=3)
    $cmmcStmt = $pdo->query("
        SELECT cmmc_level, status, COUNT(*) as cnt
        FROM blueteam.compliance_controls
        WHERE cmmc_level IS NOT NULL
        GROUP BY cmmc_level, status
        ORDER BY cmmc_level
    ");
    $cmmcRows = $cmmcStmt->fetchAll();

    $cmmcBuckets = [];
    foreach ($cmmcRows as $row) {
        $lvl = (int) $row['cmmc_level'];
        $status = $row['status'];
        $cnt = (int) $row['cnt'];
        if (!isset($cmmcBuckets[$lvl])) {
            $cmmcBuckets[$lvl] = [
                'implemented' => 0,
                'partial' => 0,
                'not_assessed' => 0,
                'na' => 0
            ];
        }
        if ($status === 'implemented') {
            $cmmcBuckets[$lvl]['implemented'] += $cnt;
        } elseif ($status === 'partially_implemented') {
            $cmmcBuckets[$lvl]['partial'] += $cnt;
        } elseif ($status === 'not_assessed') {
            $cmmcBuckets[$lvl]['not_assessed'] += $cnt;
        } elseif ($status === 'not_applicable') {
            $cmmcBuckets[$lvl]['na'] += $cnt;
        }
    }

    // Build cumulative totals for each threshold level
    $cmmc = [];
    $levelNames = ['level1' => 1, 'level2' => 2, 'level3' => 3];
    $levelTotals = ['level1' => 17, 'level2' => 110, 'level3' => 134];
    foreach ($levelNames as $key => $maxLevel) {
        $agg = ['implemented' => 0, 'partial' => 0, 'not_assessed' => 0, 'na' => 0];
        for ($l = 1; $l <= $maxLevel; $l++) {
            if (isset($cmmcBuckets[$l])) {
                foreach ($agg as $field => $_) {
                    $agg[$field] += $cmmcBuckets[$l][$field];
                }
            }
        }
        $cmmc[$key] = array_merge(['total' => $levelTotals[$key]], $agg);
    }

    echo json_encode([
        'families' => $families,
        'controls' => $controls,
        'totals' => $totals,
        'cmmc' => $cmmc
    ]);

} catch (PDOException $e) {
    http_response_code(500);
    echo json_encode(['error' => 'Query failed']);
}
