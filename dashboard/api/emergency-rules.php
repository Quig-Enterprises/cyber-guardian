<?php
/**
 * Emergency Rules API
 *
 * GET    - List all emergency rules (any authenticated user)
 * POST   - Create a rule (super admin only)
 * PUT    - Update a rule (super admin only, can't edit default rules' match fields)
 * DELETE - Delete a rule (super admin only, can't delete default rules)
 *
 * Auth: X-Auth-User-Id for all. Write ops require super admin.
 */

header('Content-Type: application/json');

$userId = $_SERVER['HTTP_X_AUTH_USER_ID'] ?? null;
if (!$userId) {
    http_response_code(401);
    echo json_encode(['error' => 'Unauthorized']);
    exit;
}
$userId = (int) $userId;

require_once __DIR__ . '/lib/db.php';

$method = $_SERVER['REQUEST_METHOD'];

try {
    $pdo = getSecurityDb();

    switch ($method) {
        case 'GET':
            handleGet($pdo);
            break;
        case 'POST':
            requireSuper();
            handlePost($pdo, $userId);
            break;
        case 'PUT':
            requireSuper();
            handlePut($pdo);
            break;
        case 'DELETE':
            requireSuper();
            handleDelete($pdo);
            break;
        default:
            http_response_code(405);
            echo json_encode(['error' => 'Method not allowed']);
    }
} catch (PDOException $e) {
    http_response_code(500);
    error_log("Emergency Rules API Error: " . $e->getMessage());
    echo json_encode(['error' => 'Database error']);
}

function requireSuper(): void
{
    $authHeader = $_SERVER['HTTP_AUTH'] ?? '';
    if ($authHeader) {
        $session = json_decode($authHeader, true);
        if (!empty($session['super'])) return;
    }
    $superHeader = $_SERVER['HTTP_X_AUTH_SUPER'] ?? '';
    if ($superHeader === 'true' || $superHeader === '1') return;

    http_response_code(403);
    echo json_encode(['error' => 'Super admin access required']);
    exit;
}

function handleGet(PDO $pdo): void
{
    $rows = $pdo->query("
        SELECT rule_id, name, description, enabled, is_default,
               match_severity, match_status, match_category, match_attack,
               override_dedup, created_by, created_at, updated_at
        FROM blueteam.emergency_rules
        ORDER BY is_default DESC, rule_id
    ")->fetchAll(PDO::FETCH_ASSOC);

    foreach ($rows as &$row) {
        $row['rule_id'] = (int) $row['rule_id'];
        $row['enabled'] = (bool) $row['enabled'];
        $row['is_default'] = (bool) $row['is_default'];
        $row['override_dedup'] = (bool) $row['override_dedup'];
        $row['created_by'] = (int) $row['created_by'];
        // Parse PG arrays to JSON arrays
        $row['match_severity'] = pgArrayToJson($row['match_severity']);
        $row['match_status'] = pgArrayToJson($row['match_status']);
        $row['match_category'] = pgArrayToJson($row['match_category']);
    }
    unset($row);

    echo json_encode(['rules' => $rows]);
}

function handlePost(PDO $pdo, int $userId): void
{
    $input = json_decode(file_get_contents('php://input'), true);
    if (!$input || empty($input['name'])) {
        http_response_code(400);
        echo json_encode(['error' => 'name is required']);
        return;
    }

    $stmt = $pdo->prepare("
        INSERT INTO blueteam.emergency_rules
            (name, description, enabled, match_severity, match_status, match_category,
             match_attack, override_dedup, created_by)
        VALUES
            (:name, :description, :enabled, :match_severity, :match_status, :match_category,
             :match_attack, :override_dedup, :created_by)
        RETURNING rule_id
    ");

    $stmt->execute([
        ':name'           => trim($input['name']),
        ':description'    => trim($input['description'] ?? ''),
        ':enabled'        => ($input['enabled'] ?? true) ? 'true' : 'false',
        ':match_severity' => jsonToPgArray($input['match_severity'] ?? null),
        ':match_status'   => jsonToPgArray($input['match_status'] ?? null),
        ':match_category' => jsonToPgArray($input['match_category'] ?? null),
        ':match_attack'   => !empty($input['match_attack']) ? $input['match_attack'] : null,
        ':override_dedup' => ($input['override_dedup'] ?? true) ? 'true' : 'false',
        ':created_by'     => $userId,
    ]);

    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    echo json_encode(['success' => true, 'rule_id' => (int) $row['rule_id']]);
}

function handlePut(PDO $pdo): void
{
    $input = json_decode(file_get_contents('php://input'), true);
    if (!$input || empty($input['rule_id'])) {
        http_response_code(400);
        echo json_encode(['error' => 'rule_id is required']);
        return;
    }

    $id = (int) $input['rule_id'];

    // Check if default rule
    $check = $pdo->prepare("SELECT is_default FROM blueteam.emergency_rules WHERE rule_id = :id");
    $check->execute([':id' => $id]);
    $rule = $check->fetch(PDO::FETCH_ASSOC);
    if (!$rule) {
        http_response_code(404);
        echo json_encode(['error' => 'Rule not found']);
        return;
    }

    $isDefault = (bool) $rule['is_default'];

    $sets = [];
    $params = [':id' => $id];

    // Default rules: can only toggle enabled, not match fields
    $allowedFields = $isDefault
        ? ['enabled']
        : ['name', 'description', 'enabled', 'match_severity', 'match_status', 'match_category', 'match_attack', 'override_dedup'];

    foreach ($allowedFields as $field) {
        if (!array_key_exists($field, $input)) continue;

        $val = $input[$field];

        if ($field === 'enabled' || $field === 'override_dedup') {
            $val = $val ? 'true' : 'false';
        }
        if (in_array($field, ['match_severity', 'match_status', 'match_category'])) {
            $val = jsonToPgArray($val);
        }
        if ($field === 'match_attack') {
            $val = !empty($val) ? $val : null;
        }

        $sets[] = "{$field} = :{$field}";
        $params[":{$field}"] = $val;
    }

    if (empty($sets)) {
        http_response_code(400);
        echo json_encode(['error' => 'No fields to update']);
        return;
    }

    $sets[] = "updated_at = NOW()";
    $sql = "UPDATE blueteam.emergency_rules SET " . implode(', ', $sets) . " WHERE rule_id = :id";
    $pdo->prepare($sql)->execute($params);

    echo json_encode(['success' => true]);
}

function handleDelete(PDO $pdo): void
{
    $input = json_decode(file_get_contents('php://input'), true);
    $id = (int) ($input['rule_id'] ?? $_GET['id'] ?? 0);

    if ($id <= 0) {
        http_response_code(400);
        echo json_encode(['error' => 'rule_id is required']);
        return;
    }

    // Can't delete default rules
    $check = $pdo->prepare("SELECT is_default FROM blueteam.emergency_rules WHERE rule_id = :id");
    $check->execute([':id' => $id]);
    $rule = $check->fetch(PDO::FETCH_ASSOC);
    if ($rule && $rule['is_default']) {
        http_response_code(403);
        echo json_encode(['error' => 'Cannot delete default emergency rules']);
        return;
    }

    $stmt = $pdo->prepare("DELETE FROM blueteam.emergency_rules WHERE rule_id = :id AND is_default = false");
    $stmt->execute([':id' => $id]);

    echo json_encode(['success' => true, 'deleted' => $stmt->rowCount() > 0]);
}

// Helper: convert JSON array to PostgreSQL array literal
function jsonToPgArray($val): ?string
{
    if ($val === null || $val === '' || (is_array($val) && empty($val))) return null;
    if (is_string($val)) return $val; // already formatted
    if (is_array($val)) {
        return '{' . implode(',', array_map(fn($v) => trim((string) $v), $val)) . '}';
    }
    return null;
}

// Helper: parse PostgreSQL array literal to JSON-friendly array
function pgArrayToJson($val): ?array
{
    if ($val === null || $val === '') return null;
    if ($val === '{}') return [];
    $inner = trim($val, '{}');
    return array_map('trim', explode(',', $inner));
}
