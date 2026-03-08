<?php
/**
 * Monitoring Status API
 * Returns real-time correlator service state and alert delivery status.
 */
header('Content-Type: application/json');

$userId = $_SERVER['HTTP_X_AUTH_USER_ID'] ?? null;
if (!$userId) {
    http_response_code(401);
    echo json_encode(['error' => 'Unauthorized']);
    exit;
}

// ---- Correlator service status via systemctl ----
$correlatorActive = false;
$correlatorPid    = null;
$correlatorUptime = null;

$output = shell_exec('systemctl show cyber-guardian-correlator --property=ActiveState,MainPID,ActiveEnterTimestamp 2>/dev/null');
if ($output) {
    foreach (explode("\n", trim($output)) as $line) {
        [$key, $val] = array_pad(explode('=', $line, 2), 2, '');
        $key = trim($key); $val = trim($val);
        if ($key === 'ActiveState')           $correlatorActive = ($val === 'active');
        if ($key === 'MainPID' && $val > 0)   $correlatorPid = (int) $val;
        if ($key === 'ActiveEnterTimestamp' && $val) {
            $ts = strtotime($val);
            if ($ts) {
                $secs = time() - $ts;
                if ($secs < 60)        $correlatorUptime = $secs . 's';
                elseif ($secs < 3600)  $correlatorUptime = floor($secs / 60) . 'm';
                elseif ($secs < 86400) $correlatorUptime = floor($secs / 3600) . 'h ' . floor(($secs % 3600) / 60) . 'm';
                else                   $correlatorUptime = floor($secs / 86400) . 'd ' . floor(($secs % 86400) / 3600) . 'h';
            }
        }
    }
}

// ---- Recent syslog alerts (last 30 days) ----
$syslogAlerts = 0;
$lastAlertTime = null;

$journalOut = shell_exec(
    'journalctl -t eqmon-blueteam --since "30 days ago" --no-pager -o short-iso 2>/dev/null | grep SECURITY_INCIDENT | tail -50'
);
if ($journalOut) {
    $lines = array_filter(explode("\n", trim($journalOut)));
    $syslogAlerts = count($lines);
    if (!empty($lines)) {
        // First field of each line is the ISO timestamp
        $lastLine = end($lines);
        $parts = explode(' ', $lastLine);
        if (!empty($parts[0])) {
            $ts = strtotime($parts[0]);
            if ($ts) $lastAlertTime = date('Y-m-d H:i', $ts);
        }
    }
}

// ---- Collectors status (check log readability) ----
$collectors = [];
$paths = [
    'nginx'  => '/var/log/nginx/access.log',
    'syslog' => '/var/log/syslog',
    'auth'   => '/var/log/auth.log',
];
foreach ($paths as $name => $path) {
    $collectors[$name] = [
        'path'     => $path,
        'readable' => is_readable($path),
    ];
}
$collectors['redteam'] = [
    'path'     => '/opt/claude-workspace/projects/cyber-guardian/reports',
    'readable' => is_dir('/opt/claude-workspace/projects/cyber-guardian/reports'),
];

// ---- Score calculation (mirrors JS modal logic) ----
$score = 80;
if ($correlatorActive) $score += 10;   // +10 for running correlator
if ($syslogAlerts > 0) $score += 10;   // +10 for confirmed alert delivery

echo json_encode([
    'score'      => $score,
    'correlator' => [
        'active'  => $correlatorActive,
        'pid'     => $correlatorPid,
        'uptime'  => $correlatorUptime,
    ],
    'alerts' => [
        'syslog_count_30d' => $syslogAlerts,
        'last_alert_at'    => $lastAlertTime,
    ],
    'collectors' => $collectors,
]);
