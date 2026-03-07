<?php
/**
 * NotificationProcessor - Core notification engine for Security Dashboard.
 * Processes post-scan findings, matches against subscriptions and emergency rules,
 * handles dedup, and dispatches email notifications.
 */

require_once __DIR__ . '/db.php';
require_once __DIR__ . '/SecurityMailer.php';

class NotificationProcessor
{
    private const DASHBOARD_URL = 'https://artemis.ecoeyetech.com/security-dashboard/#redteam';

    private const SEVERITY_LEVELS = [
        'info'     => 0,
        'low'      => 1,
        'medium'   => 2,
        'high'     => 3,
        'critical' => 4,
    ];

    private const SEVERITY_COLORS = [
        'critical' => '#cc0000',
        'high'     => '#ff4444',
        'medium'   => '#e67e22',
        'low'      => '#27ae60',
        'info'     => '#3498db',
    ];

    private const CATEGORY_MAP = [
        'ai_powered' => 'ai',
        'ai'         => 'ai',
        'api'        => 'api',
        'web'        => 'web',
        'compliance' => 'compliance',
    ];

    /**
     * Process notifications for a completed scan report.
     *
     * @param string $reportPath Absolute path to the JSON report file.
     * @return array Summary: total_findings, notifications_sent, notifications_skipped, errors
     */
    public static function processPostScanNotifications(string $reportPath): array
    {
        $result = [
            'total_findings'       => 0,
            'notifications_sent'   => 0,
            'notifications_skipped'=> 0,
            'errors'               => 0,
        ];

        // 1. Load report
        if (!is_file($reportPath) || !is_readable($reportPath)) {
            error_log("NotificationProcessor: report not found: {$reportPath}");
            return $result;
        }

        $reportJson = file_get_contents($reportPath);
        $report = json_decode($reportJson, true);
        if (!$report || empty($report['findings'])) {
            error_log("NotificationProcessor: no findings in report");
            return $result;
        }

        $findings = $report['findings'];
        $scanTimestamp = $report['generated'] ?? date('c');
        $scanDate = date('M j, Y g:i A', strtotime($scanTimestamp));
        $result['total_findings'] = count($findings);

        $pdo = getSecurityDb();

        // 2. Fetch enabled subscriptions
        $subs = $pdo->query("
            SELECT * FROM blueteam.notification_subscriptions WHERE enabled = true
        ")->fetchAll(PDO::FETCH_ASSOC);

        if (empty($subs)) {
            return $result;
        }

        // 3. Fetch enabled emergency rules
        $rules = $pdo->query("
            SELECT * FROM blueteam.emergency_rules WHERE enabled = true
        ")->fetchAll(PDO::FETCH_ASSOC);

        // 4. Process each finding and build per-user queues
        // queues[user_id] = [ ['finding' => ..., 'is_emergency' => bool, 'emergency_rule' => name], ... ]
        $queues = [];

        foreach ($findings as $finding) {
            $attack   = $finding['attack'] ?? '';
            $variant  = $finding['variant'] ?? '';
            $status   = strtolower($finding['status'] ?? '');
            $severity = strtolower($finding['severity'] ?? 'info');
            $details  = $finding['details'] ?? ($finding['evidence'] ?? '');
            $category = self::deriveCategory($attack);
            $fingerprint = $attack . '|' . $variant;

            // Check emergency rules for this finding
            $matchedEmergencyRule = self::matchEmergencyRules($rules, $severity, $status, $category, $attack);

            foreach ($subs as $sub) {
                $userId = (int) $sub['user_id'];
                $isEmergency = false;
                $emergencyRuleName = '';

                // Emergency bypass check
                if ($matchedEmergencyRule && $sub['emergency_alerts']) {
                    $isEmergency = true;
                    $emergencyRuleName = $matchedEmergencyRule;
                }

                if (!$isEmergency) {
                    // Status filter
                    if (!self::passesStatusFilter($sub, $status)) continue;

                    // Category filter
                    if (!self::passesCategoryFilter($sub, $category)) continue;

                    // Severity filter
                    if (!self::passesSeverityFilter($sub['min_severity'], $severity)) continue;
                }

                // Dedup check (skip for emergency if override_dedup)
                if (!$isEmergency && $sub['dedup_mode'] === 'first_only') {
                    if (self::alreadyNotified($pdo, $userId, $fingerprint)) {
                        $result['notifications_skipped']++;
                        continue;
                    }
                }

                if (!isset($queues[$userId])) {
                    $queues[$userId] = ['sub' => $sub, 'items' => []];
                }

                $queues[$userId]['items'][] = [
                    'finding'           => $finding,
                    'fingerprint'       => $fingerprint,
                    'category'          => $category,
                    'is_emergency'      => $isEmergency,
                    'emergency_rule'    => $emergencyRuleName,
                ];
            }
        }

        // 5. Dispatch emails per user
        foreach ($queues as $userId => $queue) {
            $sub   = $queue['sub'];
            $items = $queue['items'];
            $email = $sub['user_email'];
            $name  = $sub['user_name'] ?: 'User';

            if (empty($items) || empty($email)) continue;

            // Separate emergency and normal items
            $emergencyItems = array_filter($items, fn($i) => $i['is_emergency']);
            $normalItems    = array_filter($items, fn($i) => !$i['is_emergency']);

            // Send emergency alerts individually
            foreach ($emergencyItems as $item) {
                $f = $item['finding'];
                $severity = strtolower($f['severity'] ?? 'info');
                $ok = SecurityMailer::sendTemplate($email, 'security-emergency', [
                    'subject'             => 'EMERGENCY: ' . ($f['attack'] ?? 'Security Finding'),
                    'user_name'           => htmlspecialchars($name),
                    'emergency_rule_name' => htmlspecialchars($item['emergency_rule']),
                    'severity'            => strtoupper($severity),
                    'severity_color'      => self::SEVERITY_COLORS[$severity] ?? '#888',
                    'status'              => ucfirst($f['status'] ?? ''),
                    'attack_name'         => htmlspecialchars($f['attack'] ?? ''),
                    'variant'             => htmlspecialchars($f['variant'] ?? ''),
                    'category'            => strtoupper($item['category']),
                    'details'             => htmlspecialchars($f['details'] ?? $f['evidence'] ?? ''),
                    'dashboard_link'      => self::DASHBOARD_URL,
                    'scan_date'           => $scanDate,
                ]);

                self::recordHistory($pdo, $sub, $scanTimestamp, $item, $ok, true);
                if ($ok) $result['notifications_sent']++; else $result['errors']++;
            }

            // Send normal notifications: <=3 individual, >3 digest
            $normalItems = array_values($normalItems);
            if (count($normalItems) <= 3) {
                foreach ($normalItems as $item) {
                    $f = $item['finding'];
                    $severity = strtolower($f['severity'] ?? 'info');
                    $ok = SecurityMailer::sendTemplate($email, 'security-alert', [
                        'subject'        => 'Security Alert: ' . ($f['attack'] ?? 'Finding'),
                        'user_name'      => htmlspecialchars($name),
                        'severity'       => strtoupper($severity),
                        'severity_color' => self::SEVERITY_COLORS[$severity] ?? '#888',
                        'status'         => ucfirst($f['status'] ?? ''),
                        'attack_name'    => htmlspecialchars($f['attack'] ?? ''),
                        'variant'        => htmlspecialchars($f['variant'] ?? ''),
                        'category'       => strtoupper($item['category']),
                        'details'        => htmlspecialchars($f['details'] ?? $f['evidence'] ?? ''),
                        'dashboard_link' => self::DASHBOARD_URL,
                        'scan_date'      => $scanDate,
                    ]);

                    self::recordHistory($pdo, $sub, $scanTimestamp, $item, $ok, false);
                    if ($ok) $result['notifications_sent']++; else $result['errors']++;
                }
            } elseif (count($normalItems) > 0) {
                // Build digest
                $findingsTable = self::buildDigestTable($normalItems);
                $ok = SecurityMailer::sendTemplate($email, 'security-digest', [
                    'subject'        => 'Security Digest: ' . count($normalItems) . ' findings from ' . $scanDate,
                    'user_name'      => htmlspecialchars($name),
                    'finding_count'  => count($normalItems),
                    'scan_date'      => $scanDate,
                    'findings_table' => $findingsTable,
                    'dashboard_link' => self::DASHBOARD_URL,
                ]);

                // Record history for each finding in digest
                foreach ($normalItems as $item) {
                    self::recordHistory($pdo, $sub, $scanTimestamp, $item, $ok, false);
                }
                if ($ok) $result['notifications_sent']++; else $result['errors']++;
            }
        }

        return $result;
    }

    // ---- Category derivation ----

    private static function deriveCategory(string $attack): string
    {
        // Longest prefix match: "ai_powered.xxx" -> "ai", "api.xxx" -> "api"
        $lower = strtolower($attack);
        $bestMatch = 'web'; // default
        $bestLen = 0;

        foreach (self::CATEGORY_MAP as $prefix => $cat) {
            if (strpos($lower, $prefix) === 0 && strlen($prefix) > $bestLen) {
                $bestMatch = $cat;
                $bestLen = strlen($prefix);
            }
        }
        return $bestMatch;
    }

    // ---- Emergency rule matching ----

    /**
     * Returns the name of the first matching emergency rule, or null if none match.
     * All non-null conditions in a rule must match (AND). Within arrays, any value matching counts (OR).
     */
    private static function matchEmergencyRules(array $rules, string $severity, string $status, string $category, string $attack): ?string
    {
        foreach ($rules as $rule) {
            if (!$rule['enabled']) continue;

            // match_severity: if set, severity must be in the array
            if (!empty($rule['match_severity'])) {
                $arr = self::pgArrayToPhp($rule['match_severity']);
                if (!in_array($severity, $arr)) continue;
            }

            // match_status: if set, status must be in the array
            if (!empty($rule['match_status'])) {
                $arr = self::pgArrayToPhp($rule['match_status']);
                if (!in_array($status, $arr)) continue;
            }

            // match_category: if set, category must be in the array
            if (!empty($rule['match_category'])) {
                $arr = self::pgArrayToPhp($rule['match_category']);
                if (!in_array($category, $arr)) continue;
            }

            // match_attack: if set, regex match on attack name
            if (!empty($rule['match_attack'])) {
                $pattern = '/' . str_replace('/', '\/', $rule['match_attack']) . '/i';
                if (!@preg_match($pattern, $attack)) continue;
            }

            return $rule['name'];
        }
        return null;
    }

    /**
     * Parse PostgreSQL text array literal like {critical,high} into PHP array.
     */
    private static function pgArrayToPhp($val): array
    {
        if (is_array($val)) return $val;
        if (empty($val) || $val === '{}') return [];
        $inner = trim($val, '{}');
        return array_map('trim', explode(',', $inner));
    }

    // ---- Subscription filters ----

    private static function passesStatusFilter(array $sub, string $status): bool
    {
        switch ($status) {
            case 'vulnerable': return (bool) $sub['notify_vulnerable'];
            case 'partial':    return (bool) $sub['notify_partial'];
            case 'defended':   return (bool) $sub['notify_defended'];
            case 'error':      return (bool) $sub['notify_error'];
            default:           return false;
        }
    }

    private static function passesCategoryFilter(array $sub, string $category): bool
    {
        switch ($category) {
            case 'ai':         return (bool) $sub['cat_ai'];
            case 'api':        return (bool) $sub['cat_api'];
            case 'web':        return (bool) $sub['cat_web'];
            case 'compliance': return (bool) $sub['cat_compliance'];
            default:           return true; // unknown categories pass
        }
    }

    private static function passesSeverityFilter(string $minSeverity, string $findingSeverity): bool
    {
        $minLevel = self::SEVERITY_LEVELS[strtolower($minSeverity)] ?? 0;
        $findLevel = self::SEVERITY_LEVELS[strtolower($findingSeverity)] ?? 0;
        return $findLevel >= $minLevel;
    }

    // ---- Dedup ----

    private static function alreadyNotified(PDO $pdo, int $userId, string $fingerprint): bool
    {
        $stmt = $pdo->prepare("
            SELECT 1 FROM blueteam.notification_history
            WHERE user_id = :uid AND finding_fingerprint = :fp AND delivery_status = 'sent'
            LIMIT 1
        ");
        $stmt->execute([':uid' => $userId, ':fp' => $fingerprint]);
        return (bool) $stmt->fetch();
    }

    // ---- History recording ----

    private static function recordHistory(PDO $pdo, array $sub, string $scanTimestamp, array $item, bool $sent, bool $isEmergency): void
    {
        $f = $item['finding'];
        $stmt = $pdo->prepare("
            INSERT INTO blueteam.notification_history
                (subscription_id, user_id, scan_timestamp, finding_fingerprint, finding_severity,
                 finding_status, finding_category, finding_attack, finding_variant, finding_details,
                 email_subject, is_emergency, delivery_status, sent_at, created_at)
            VALUES
                (:sub_id, :user_id, :scan_ts, :fp, :sev, :status, :cat, :attack, :variant, :details,
                 :subject, :emergency, :delivery, :sent_at, NOW())
        ");

        $subjectPrefix = $isEmergency ? 'EMERGENCY: ' : 'Security Alert: ';
        $stmt->execute([
            ':sub_id'    => $sub['subscription_id'] ?? null,
            ':user_id'   => (int) $sub['user_id'],
            ':scan_ts'   => $scanTimestamp,
            ':fp'        => $item['fingerprint'],
            ':sev'       => strtolower($f['severity'] ?? 'info'),
            ':status'    => strtolower($f['status'] ?? ''),
            ':cat'       => $item['category'],
            ':attack'    => $f['attack'] ?? '',
            ':variant'   => $f['variant'] ?? '',
            ':details'   => mb_substr($f['details'] ?? $f['evidence'] ?? '', 0, 500),
            ':subject'   => $subjectPrefix . ($f['attack'] ?? 'Finding'),
            ':emergency' => $isEmergency ? 'true' : 'false',
            ':delivery'  => $sent ? 'sent' : 'failed',
            ':sent_at'   => $sent ? date('c') : null,
        ]);
    }

    // ---- Digest table builder ----

    private static function buildDigestTable(array $items): string
    {
        $html = '<table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%" style="margin: 0 0 20px 0; border-collapse: collapse; border: 1px solid #e0e0e0; border-radius: 6px; overflow: hidden;">';
        $html .= '<tr>';
        $html .= '<th style="padding: 10px 12px; background-color: #1a1a2e; color: #00ff00; font-size: 12px; text-align: left; font-weight: 600;">Attack</th>';
        $html .= '<th style="padding: 10px 12px; background-color: #1a1a2e; color: #00ff00; font-size: 12px; text-align: left; font-weight: 600;">Variant</th>';
        $html .= '<th style="padding: 10px 12px; background-color: #1a1a2e; color: #00ff00; font-size: 12px; text-align: center; font-weight: 600;">Severity</th>';
        $html .= '<th style="padding: 10px 12px; background-color: #1a1a2e; color: #00ff00; font-size: 12px; text-align: center; font-weight: 600;">Status</th>';
        $html .= '</tr>';

        foreach ($items as $i => $item) {
            $f = $item['finding'];
            $severity = strtolower($f['severity'] ?? 'info');
            $bgColor = $i % 2 === 0 ? '#ffffff' : '#f9f9f9';
            $sevColor = self::SEVERITY_COLORS[$severity] ?? '#888';

            $html .= '<tr>';
            $html .= '<td style="padding: 8px 12px; background-color: ' . $bgColor . '; border-bottom: 1px solid #e0e0e0; font-size: 13px; color: #333;">' . htmlspecialchars($f['attack'] ?? '') . '</td>';
            $html .= '<td style="padding: 8px 12px; background-color: ' . $bgColor . '; border-bottom: 1px solid #e0e0e0; font-size: 13px; color: #555;">' . htmlspecialchars($f['variant'] ?? '') . '</td>';
            $html .= '<td style="padding: 8px 12px; background-color: ' . $bgColor . '; border-bottom: 1px solid #e0e0e0; text-align: center;"><span style="display: inline-block; padding: 2px 8px; border-radius: 3px; background-color: ' . $sevColor . '; color: #fff; font-size: 11px; font-weight: 600;">' . strtoupper($severity) . '</span></td>';
            $html .= '<td style="padding: 8px 12px; background-color: ' . $bgColor . '; border-bottom: 1px solid #e0e0e0; text-align: center; font-size: 13px; color: #555;">' . ucfirst($f['status'] ?? '') . '</td>';
            $html .= '</tr>';
        }

        $html .= '</table>';
        return $html;
    }
}
