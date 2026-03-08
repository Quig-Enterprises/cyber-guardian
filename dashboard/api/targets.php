<?php
/**
 * Scan Target Management API
 *
 * GET    - List all targets
 * POST   - Create a new target
 * PUT    - Update a target
 * DELETE - Delete a target (non-self only)
 *
 * Auth: read requires login; write requires super admin.
 */

header('Content-Type: application/json');

$userId = $_SERVER['HTTP_X_AUTH_USER_ID'] ?? null;
if (!$userId) {
    http_response_code(401);
    echo json_encode(['error' => 'Unauthorized']);
    exit;
}

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
            handlePost($pdo, (int) $userId);
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
    error_log('Targets API error: ' . $e->getMessage());
    echo json_encode(['error' => 'Database error']);
}

function handleGet(PDO $pdo): void
{
    $stmt = $pdo->query("
        SELECT target_id, name, base_url, target_type, description, origin_ip,
               wp_user, is_self, enabled, created_at, updated_at
        FROM blueteam.redteam_targets
        ORDER BY is_self DESC, target_id
    ");
    $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
    foreach ($rows as &$r) {
        $r['target_id'] = (int) $r['target_id'];
        $r['is_self']   = (bool) $r['is_self'];
        $r['enabled']   = (bool) $r['enabled'];
    }
    unset($r);
    echo json_encode(['targets' => $rows]);
}

function handlePost(PDO $pdo, int $userId): void
{
    $input = json_decode(file_get_contents('php://input'), true);
    if (!$input) {
        http_response_code(400);
        echo json_encode(['error' => 'Invalid JSON']);
        return;
    }

    $name       = trim($input['name'] ?? '');
    $baseUrl    = trim($input['base_url'] ?? '');
    $targetType = $input['target_type'] ?? 'app';
    $description = trim($input['description'] ?? '');
    $originIp   = trim($input['origin_ip'] ?? '');
    $wpUser     = trim($input['wp_user'] ?? '');
    $wpPass     = $input['wp_pass'] ?? '';

    if ($name === '' || $baseUrl === '') {
        http_response_code(400);
        echo json_encode(['error' => 'name and base_url are required']);
        return;
    }

    $validTypes = ['app', 'wordpress', 'generic'];
    if (!in_array($targetType, $validTypes, true)) {
        http_response_code(400);
        echo json_encode(['error' => 'target_type must be app, wordpress, or generic']);
        return;
    }

    // Validate URL scheme
    if (!preg_match('#^https?://#', $baseUrl)) {
        http_response_code(400);
        echo json_encode(['error' => 'base_url must start with http:// or https://']);
        return;
    }

    $wpPassEnc = $wpPass !== '' ? base64_encode($wpPass) : null;

    $stmt = $pdo->prepare("
        INSERT INTO blueteam.redteam_targets
            (name, base_url, target_type, description, origin_ip, wp_user, wp_pass_enc, is_self, enabled)
        VALUES
            (:name, :base_url, :target_type, :description, :origin_ip, :wp_user, :wp_pass_enc, FALSE, TRUE)
        RETURNING target_id
    ");
    $stmt->execute([
        ':name'        => $name,
        ':base_url'    => $baseUrl,
        ':target_type' => $targetType,
        ':description' => $description ?: null,
        ':origin_ip'   => $originIp ?: null,
        ':wp_user'     => $wpUser ?: null,
        ':wp_pass_enc' => $wpPassEnc,
    ]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    echo json_encode(['success' => true, 'target_id' => (int) $row['target_id']]);
}

function handlePut(PDO $pdo): void
{
    $input = json_decode(file_get_contents('php://input'), true);
    if (!$input || empty($input['target_id'])) {
        http_response_code(400);
        echo json_encode(['error' => 'target_id is required']);
        return;
    }

    $id = (int) $input['target_id'];

    // Prevent editing is_self / target_id
    $allowed = ['name', 'base_url', 'target_type', 'description', 'origin_ip', 'wp_user', 'enabled'];
    $sets = ['updated_at = NOW()'];
    $params = [':id' => $id];

    foreach ($allowed as $field) {
        if (!array_key_exists($field, $input)) continue;
        $val = $input[$field];
        if ($field === 'base_url' && !preg_match('#^https?://#', $val)) {
            http_response_code(400);
            echo json_encode(['error' => 'base_url must start with http:// or https://']);
            return;
        }
        if ($field === 'target_type' && !in_array($val, ['app', 'wordpress', 'generic'], true)) {
            http_response_code(400);
            echo json_encode(['error' => 'Invalid target_type']);
            return;
        }
        if ($field === 'enabled') $val = $val ? 'true' : 'false';
        $sets[] = "$field = :$field";
        $params[":$field"] = $val;
    }

    // Handle password separately
    if (isset($input['wp_pass']) && $input['wp_pass'] !== '') {
        $sets[] = 'wp_pass_enc = :wp_pass_enc';
        $params[':wp_pass_enc'] = base64_encode($input['wp_pass']);
    }

    $sql = 'UPDATE blueteam.redteam_targets SET ' . implode(', ', $sets) . ' WHERE target_id = :id';
    $stmt = $pdo->prepare($sql);
    $stmt->execute($params);

    if ($stmt->rowCount() === 0) {
        http_response_code(404);
        echo json_encode(['error' => 'Target not found']);
        return;
    }
    echo json_encode(['success' => true]);
}

function handleDelete(PDO $pdo): void
{
    $input = json_decode(file_get_contents('php://input'), true);
    $id = (int) ($input['target_id'] ?? $_GET['id'] ?? 0);
    if ($id <= 0) {
        http_response_code(400);
        echo json_encode(['error' => 'target_id is required']);
        return;
    }

    // Can't delete the self target
    $stmt = $pdo->prepare("SELECT is_self FROM blueteam.redteam_targets WHERE target_id = :id");
    $stmt->execute([':id' => $id]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    if (!$row) {
        http_response_code(404);
        echo json_encode(['error' => 'Target not found']);
        return;
    }
    if ($row['is_self']) {
        http_response_code(400);
        echo json_encode(['error' => 'Cannot delete the self target']);
        return;
    }

    $stmt = $pdo->prepare("DELETE FROM blueteam.redteam_targets WHERE target_id = :id");
    $stmt->execute([':id' => $id]);
    echo json_encode(['success' => true]);
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
