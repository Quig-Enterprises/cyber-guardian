-- Mitigation data import from Red Team Scan 2026-03-08
-- Generated: 2026-03-08 19:03:02

BEGIN;

-- Create mitigation project
INSERT INTO blueteam.mitigation_projects (name, description, scan_date, scan_report_path, status)
VALUES (
  'Red Team Scan - 2026-03-08',
  'AWS-compliant automated security scan - 44 vulnerable findings across API, Compliance, Web, DNS, Infrastructure, and Secrets categories',
  '2026-03-08',
  '/opt/claude-workspace/projects/cyber-guardian/redteam/reports/redteam-report-20260308_184540.json',
  'active'
);

-- Issue 1: MEDIUM - UNKNOWN - api.account_lockout_bypass
INSERT INTO blueteam.mitigation_issues
  (project_id, title, description, severity, category, attack_name, variant,
   status, priority, due_date, evidence)
VALUES (
  (SELECT id FROM blueteam.mitigation_projects WHERE scan_date = '2026-03-08' ORDER BY id DESC LIMIT 1),
  'api.account_lockout_bypass / rapid_attempts',
  '',
  'medium',
  'UNKNOWN',
  'api.account_lockout_bypass',
  'rapid_attempts',
  'not_started',
  3,
  CURRENT_DATE + INTERVAL '60 days',
  'Sent 10 attempts in 0.0s. Statuses: [404, 404, 404, 404, 404, 404, 404, 404, 404, 404]. Locked out: False'
);

-- Issue 2: LOW - UNKNOWN - api.account_lockout_bypass
INSERT INTO blueteam.mitigation_issues
  (project_id, title, description, severity, category, attack_name, variant,
   status, priority, due_date, evidence)
VALUES (
  (SELECT id FROM blueteam.mitigation_projects WHERE scan_date = '2026-03-08' ORDER BY id DESC LIMIT 1),
  'api.account_lockout_bypass / rate_limit_header_check',
  '',
  'low',
  'UNKNOWN',
  'api.account_lockout_bypass',
  'rate_limit_header_check',
  'not_started',
  4,
  CURRENT_DATE + INTERVAL '90 days',
  'Response headers checked. Rate limit headers found: none'
);

-- Issue 3: CRITICAL - UNKNOWN - api.auth_bypass
INSERT INTO blueteam.mitigation_issues
  (project_id, title, description, severity, category, attack_name, variant,
   status, priority, due_date, evidence)
VALUES (
  (SELECT id FROM blueteam.mitigation_projects WHERE scan_date = '2026-03-08' ORDER BY id DESC LIMIT 1),
  'api.auth_bypass / no_cookie',
  '',
  'critical',
  'UNKNOWN',
  'api.auth_bypass',
  'no_cookie',
  'not_started',
  1,
  CURRENT_DATE + INTERVAL '3 days',
  'Status: 404, Body: File not found.
'
);

-- Issue 4: CRITICAL - UNKNOWN - api.auth_bypass
INSERT INTO blueteam.mitigation_issues
  (project_id, title, description, severity, category, attack_name, variant,
   status, priority, due_date, evidence)
VALUES (
  (SELECT id FROM blueteam.mitigation_projects WHERE scan_date = '2026-03-08' ORDER BY id DESC LIMIT 1),
  'api.auth_bypass / expired_jwt',
  '',
  'critical',
  'UNKNOWN',
  'api.auth_bypass',
  'expired_jwt',
  'not_started',
  1,
  CURRENT_DATE + INTERVAL '3 days',
  'Status: 404, Body: File not found.
'
);

-- Issue 5: CRITICAL - UNKNOWN - api.auth_bypass
INSERT INTO blueteam.mitigation_issues
  (project_id, title, description, severity, category, attack_name, variant,
   status, priority, due_date, evidence)
VALUES (
  (SELECT id FROM blueteam.mitigation_projects WHERE scan_date = '2026-03-08' ORDER BY id DESC LIMIT 1),
  'api.auth_bypass / wrong_signing_key',
  '',
  'critical',
  'UNKNOWN',
  'api.auth_bypass',
  'wrong_signing_key',
  'not_started',
  1,
  CURRENT_DATE + INTERVAL '3 days',
  'Status: 404, Body: File not found.
'
);

-- Issue 6: CRITICAL - UNKNOWN - api.auth_bypass
INSERT INTO blueteam.mitigation_issues
  (project_id, title, description, severity, category, attack_name, variant,
   status, priority, due_date, evidence)
VALUES (
  (SELECT id FROM blueteam.mitigation_projects WHERE scan_date = '2026-03-08' ORDER BY id DESC LIMIT 1),
  'api.auth_bypass / none_algorithm',
  '',
  'critical',
  'UNKNOWN',
  'api.auth_bypass',
  'none_algorithm',
  'not_started',
  1,
  CURRENT_DATE + INTERVAL '3 days',
  'Status: 404, Body: File not found.
'
);

-- Issue 7: CRITICAL - UNKNOWN - api.auth_bypass
INSERT INTO blueteam.mitigation_issues
  (project_id, title, description, severity, category, attack_name, variant,
   status, priority, due_date, evidence)
VALUES (
  (SELECT id FROM blueteam.mitigation_projects WHERE scan_date = '2026-03-08' ORDER BY id DESC LIMIT 1),
  'api.auth_bypass / empty_cookie',
  '',
  'critical',
  'UNKNOWN',
  'api.auth_bypass',
  'empty_cookie',
  'not_started',
  1,
  CURRENT_DATE + INTERVAL '3 days',
  'Status: 404'
);

-- Issue 8: CRITICAL - UNKNOWN - api.auth_bypass
INSERT INTO blueteam.mitigation_issues
  (project_id, title, description, severity, category, attack_name, variant,
   status, priority, due_date, evidence)
VALUES (
  (SELECT id FROM blueteam.mitigation_projects WHERE scan_date = '2026-03-08' ORDER BY id DESC LIMIT 1),
  'api.auth_bypass / malformed_jwt',
  '',
  'critical',
  'UNKNOWN',
  'api.auth_bypass',
  'malformed_jwt',
  'not_started',
  1,
  CURRENT_DATE + INTERVAL '3 days',
  'Status: 404, Body: File not found.
'
);

-- Issue 9: MEDIUM - UNKNOWN - api.error_leakage
INSERT INTO blueteam.mitigation_issues
  (project_id, title, description, severity, category, attack_name, variant,
   status, priority, due_date, evidence)
VALUES (
  (SELECT id FROM blueteam.mitigation_projects WHERE scan_date = '2026-03-08' ORDER BY id DESC LIMIT 1),
  'api.error_leakage / trigger_pdo_exception',
  '',
  'medium',
  'UNKNOWN',
  'api.error_leakage',
  'trigger_pdo_exception',
  'not_started',
  3,
  CURRENT_DATE + INTERVAL '60 days',
  'Findings: ["BODY: Web server identity exposed (matched ''nginx'')", "HEADER: Web server identity exposed (matched ''nginx'')"], Status: 414, Body: <html>
<head><title>414 Request-URI Too Large</title></head>
<body>
<center><h1>414 Request-URI Too Large</h1></center>
<hr><center>nginx</center>
</body>
</html>
'
);

-- Issue 10: MEDIUM - UNKNOWN - api.error_leakage
INSERT INTO blueteam.mitigation_issues
  (project_id, title, description, severity, category, attack_name, variant,
   status, priority, due_date, evidence)
VALUES (
  (SELECT id FROM blueteam.mitigation_projects WHERE scan_date = '2026-03-08' ORDER BY id DESC LIMIT 1),
  'api.error_leakage / trigger_type_error',
  '',
  'medium',
  'UNKNOWN',
  'api.error_leakage',
  'trigger_type_error',
  'not_started',
  3,
  CURRENT_DATE + INTERVAL '60 days',
  'Findings: ["HEADER: Web server identity exposed (matched ''nginx'')"], Status: 404, Body: File not found.
'
);

-- Issue 11: MEDIUM - UNKNOWN - api.error_leakage
INSERT INTO blueteam.mitigation_issues
  (project_id, title, description, severity, category, attack_name, variant,
   status, priority, due_date, evidence)
VALUES (
  (SELECT id FROM blueteam.mitigation_projects WHERE scan_date = '2026-03-08' ORDER BY id DESC LIMIT 1),
  'api.error_leakage / internal_details_in_errors',
  '',
  'medium',
  'UNKNOWN',
  'api.error_leakage',
  'internal_details_in_errors',
  'not_started',
  3,
  CURRENT_DATE + INTERVAL '60 days',
  'Total findings: 1, Details: ["HEADER: Web server identity exposed (matched ''nginx'')"]'
);

-- Issue 12: CRITICAL - UNKNOWN - api.lateral_movement
INSERT INTO blueteam.mitigation_issues
  (project_id, title, description, severity, category, attack_name, variant,
   status, priority, due_date, evidence)
VALUES (
  (SELECT id FROM blueteam.mitigation_projects WHERE scan_date = '2026-03-08' ORDER BY id DESC LIMIT 1),
  'api.lateral_movement / api_to_admin_panel',
  '',
  'critical',
  'UNKNOWN',
  'api.lateral_movement',
  'api_to_admin_panel',
  'not_started',
  1,
  CURRENT_DATE + INTERVAL '3 days',
  'Auth source: login, Status: 200, Admin content detected: True, Body snippet: <!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - KEYSTONE</title>
    <link rel="stylesheet" href="css/style.css?v=2026020507">
</head>
<body class="login-page">
    <div class="login-cont'
);

-- Issue 13: MEDIUM - UNKNOWN - api.password_policy
INSERT INTO blueteam.mitigation_issues
  (project_id, title, description, severity, category, attack_name, variant,
   status, priority, due_date, evidence)
VALUES (
  (SELECT id FROM blueteam.mitigation_projects WHERE scan_date = '2026-03-08' ORDER BY id DESC LIMIT 1),
  'api.password_policy / short_password',
  '',
  'medium',
  'UNKNOWN',
  'api.password_policy',
  'short_password',
  'not_started',
  3,
  CURRENT_DATE + INTERVAL '60 days',
  'Status: 404, Body: File not found.
'
);

-- Issue 14: MEDIUM - UNKNOWN - api.password_policy
INSERT INTO blueteam.mitigation_issues
  (project_id, title, description, severity, category, attack_name, variant,
   status, priority, due_date, evidence)
VALUES (
  (SELECT id FROM blueteam.mitigation_projects WHERE scan_date = '2026-03-08' ORDER BY id DESC LIMIT 1),
  'api.password_policy / no_complexity',
  '',
  'medium',
  'UNKNOWN',
  'api.password_policy',
  'no_complexity',
  'not_started',
  3,
  CURRENT_DATE + INTERVAL '60 days',
  'Status: 404, Body: File not found.
'
);

-- Issue 15: MEDIUM - UNKNOWN - api.password_policy
INSERT INTO blueteam.mitigation_issues
  (project_id, title, description, severity, category, attack_name, variant,
   status, priority, due_date, evidence)
VALUES (
  (SELECT id FROM blueteam.mitigation_projects WHERE scan_date = '2026-03-08' ORDER BY id DESC LIMIT 1),
  'api.password_policy / common_password',
  '',
  'medium',
  'UNKNOWN',
  'api.password_policy',
  'common_password',
  'not_started',
  3,
  CURRENT_DATE + INTERVAL '60 days',
  'Status: 404, Body: File not found.
'
);

-- Issue 16: MEDIUM - UNKNOWN - api.rate_limiting
INSERT INTO blueteam.mitigation_issues
  (project_id, title, description, severity, category, attack_name, variant,
   status, priority, due_date, evidence)
VALUES (
  (SELECT id FROM blueteam.mitigation_projects WHERE scan_date = '2026-03-08' ORDER BY id DESC LIMIT 1),
  'api.rate_limiting / rapid_fire_50_gets',
  '',
  'medium',
  'UNKNOWN',
  'api.rate_limiting',
  'rapid_fire_50_gets',
  'not_started',
  3,
  CURRENT_DATE + INTERVAL '60 days',
  'Sent 50 requests in 0.1s. 429 count: 0, 200 count: 0'
);

-- Issue 17: HIGH - UNKNOWN - api.session_predictability
INSERT INTO blueteam.mitigation_issues
  (project_id, title, description, severity, category, attack_name, variant,
   status, priority, due_date, evidence)
VALUES (
  (SELECT id FROM blueteam.mitigation_projects WHERE scan_date = '2026-03-08' ORDER BY id DESC LIMIT 1),
  'api.session_predictability / csrf_token_predictability',
  '',
  'high',
  'UNKNOWN',
  'api.session_predictability',
  'csrf_token_predictability',
  'not_started',
  2,
  CURRENT_DATE + INTERVAL '30 days',
  'CSRF tokens collected: 3, unique: 1, from pages: [''/index.php'', ''/admin/index.php'', ''/admin/login.php'']'
);

-- Issue 18: HIGH - UNKNOWN - compliance.anomaly_detection_evasion
INSERT INTO blueteam.mitigation_issues
  (project_id, title, description, severity, category, attack_name, variant,
   status, priority, due_date, evidence)
VALUES (
  (SELECT id FROM blueteam.mitigation_projects WHERE scan_date = '2026-03-08' ORDER BY id DESC LIMIT 1),
  'compliance.anomaly_detection_evasion / failed_auth_flood',
  '',
  'high',
  'UNKNOWN',
  'compliance.anomaly_detection_evasion',
  'failed_auth_flood',
  'not_started',
  2,
  CURRENT_DATE + INTERVAL '30 days',
  'All 10 rapid failed login attempts to /api/auth/login.php completed without account lockout or throttling. Final attempt (attempt 10) returned HTTP 404. Response preview: File not found.
'
);

-- Issue 19: MEDIUM - UNKNOWN - compliance.cui_data_flow
INSERT INTO blueteam.mitigation_issues
  (project_id, title, description, severity, category, attack_name, variant,
   status, priority, due_date, evidence)
VALUES (
  (SELECT id FROM blueteam.mitigation_projects WHERE scan_date = '2026-03-08' ORDER BY id DESC LIMIT 1),
  'compliance.cui_data_flow / cui_in_cache_headers',
  '',
  'medium',
  'UNKNOWN',
  'compliance.cui_data_flow',
  'cui_in_cache_headers',
  'not_started',
  3,
  CURRENT_DATE + INTERVAL '60 days',
  '/api/ai_chat.php: Cache-Control='''' — missing ''no-store''. CUI responses may be cached by intermediaries.
/api/admin/settings.php: Cache-Control='''' — missing ''no-store''. CUI responses may be cached by intermediaries.'
);

-- Issue 20: MEDIUM - UNKNOWN - compliance.cui_data_flow
INSERT INTO blueteam.mitigation_issues
  (project_id, title, description, severity, category, attack_name, variant,
   status, priority, due_date, evidence)
VALUES (
  (SELECT id FROM blueteam.mitigation_projects WHERE scan_date = '2026-03-08' ORDER BY id DESC LIMIT 1),
  'compliance.cui_data_flow / export_no_marking',
  '',
  'medium',
  'UNKNOWN',
  'compliance.cui_data_flow',
  'export_no_marking',
  'not_started',
  3,
  CURRENT_DATE + INTERVAL '60 days',
  'Export tested: False, CUI markings found: False'
);

-- Issue 21: MEDIUM - UNKNOWN - compliance.cui_retention
INSERT INTO blueteam.mitigation_issues
  (project_id, title, description, severity, category, attack_name, variant,
   status, priority, due_date, evidence)
VALUES (
  (SELECT id FROM blueteam.mitigation_projects WHERE scan_date = '2026-03-08' ORDER BY id DESC LIMIT 1),
  'compliance.cui_retention / cache_headers_missing',
  '',
  'medium',
  'UNKNOWN',
  'compliance.cui_retention',
  'cache_headers_missing',
  'not_started',
  3,
  CURRENT_DATE + INTERVAL '60 days',
  '/api/ai_chat.php: Cache-Control='''', Pragma='''' — missing ''no-store''. CUI may persist in browser or proxy caches.
/api/admin/settings.php: Cache-Control='''', Pragma='''' — missing ''no-store''. CUI may persist in browser or proxy caches.
/api/admin/users.php: Cache-Control='''', Pragma='''' — missing ''no-store''. CUI may persist in browser or proxy caches.'
);

-- Issue 22: MEDIUM - UNKNOWN - compliance.cui_retention
INSERT INTO blueteam.mitigation_issues
  (project_id, title, description, severity, category, attack_name, variant,
   status, priority, due_date, evidence)
VALUES (
  (SELECT id FROM blueteam.mitigation_projects WHERE scan_date = '2026-03-08' ORDER BY id DESC LIMIT 1),
  'compliance.cui_retention / autocomplete_not_disabled',
  '',
  'medium',
  'UNKNOWN',
  'compliance.cui_retention',
  'autocomplete_not_disabled',
  'not_started',
  3,
  CURRENT_DATE + INTERVAL '60 days',
  '<input type=''email'' name/id=''email''> — autocomplete attribute missing. Browser may cache this value.
<input type=''password'' name/id=''password''> — autocomplete attribute missing. Browser may cache this value.'
);

-- Issue 23: HIGH - UNKNOWN - compliance.hipaa_encryption
INSERT INTO blueteam.mitigation_issues
  (project_id, title, description, severity, category, attack_name, variant,
   status, priority, due_date, evidence)
VALUES (
  (SELECT id FROM blueteam.mitigation_projects WHERE scan_date = '2026-03-08' ORDER BY id DESC LIMIT 1),
  'compliance.hipaa_encryption / backup_encryption',
  '',
  'high',
  'UNKNOWN',
  'compliance.hipaa_encryption',
  'backup_encryption',
  'not_started',
  2,
  CURRENT_DATE + INTERVAL '30 days',
  'unencrypted backups: 36; encrypted backups: 0; unencrypted files: [''/var/backups/dpkg.status.5.gz'', ''/var/backups/apt.extended_states.3.gz'', ''/var/backups/alternatives.tar.6.gz'', ''/var/backups/dpkg.status.6.gz'', ''/var/backups/alternatives.tar.5.gz'', ''/var/backups/dpkg.diversions.5.gz'', ''/var/backups/dpkg.statoverride.5.gz'', ''/var/backups/dpkg.status.2.gz'', ''/var/backups/alternatives.tar.4.gz'', ''/var/backups/apt.extended_states.1.gz'']; /etc/cron.daily/dpkg: backup script witho'
);

-- Issue 24: HIGH - UNKNOWN - compliance.mfa_absence
INSERT INTO blueteam.mitigation_issues
  (project_id, title, description, severity, category, attack_name, variant,
   status, priority, due_date, evidence)
VALUES (
  (SELECT id FROM blueteam.mitigation_projects WHERE scan_date = '2026-03-08' ORDER BY id DESC LIMIT 1),
  'compliance.mfa_absence / password_reset_no_mfa',
  '',
  'high',
  'UNKNOWN',
  'compliance.mfa_absence',
  'password_reset_no_mfa',
  'not_started',
  2,
  CURRENT_DATE + INTERVAL '30 days',
  'Status: 404, MFA prompted: False, Body: File not found.
'
);

-- Issue 25: HIGH - UNKNOWN - compliance.network_segmentation
INSERT INTO blueteam.mitigation_issues
  (project_id, title, description, severity, category, attack_name, variant,
   status, priority, due_date, evidence)
VALUES (
  (SELECT id FROM blueteam.mitigation_projects WHERE scan_date = '2026-03-08' ORDER BY id DESC LIMIT 1),
  'compliance.network_segmentation / internal_endpoints_exposed',
  '',
  'high',
  'UNKNOWN',
  'compliance.network_segmentation',
  'internal_endpoints_exposed',
  'not_started',
  2,
  CURRENT_DATE + INTERVAL '30 days',
  '/server-status: HTTP 200 — endpoint is publicly reachable. Body preview: <!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <tit'
);

-- Issue 26: CRITICAL - UNKNOWN - compliance.pci_access_control
INSERT INTO blueteam.mitigation_issues
  (project_id, title, description, severity, category, attack_name, variant,
   status, priority, due_date, evidence)
VALUES (
  (SELECT id FROM blueteam.mitigation_projects WHERE scan_date = '2026-03-08' ORDER BY id DESC LIMIT 1),
  'compliance.pci_access_control / default_deny_check',
  '',
  'critical',
  'UNKNOWN',
  'compliance.pci_access_control',
  'default_deny_check',
  'not_started',
  1,
  CURRENT_DATE + INTERVAL '3 days',
  'Denied: 0/4, Findings: [''GET /api/ai_chat.php returned 404 (expected 401/403)'', ''POST /api/ai_chat.php returned 404 (expected 401/403)'', ''PUT /api/ai_chat.php returned 404 (expected 401/403)'', ''DELETE /api/ai_chat.php returned 404 (expected 401/403)'']'
);

-- Issue 27: HIGH - UNKNOWN - compliance.pci_auth_controls
INSERT INTO blueteam.mitigation_issues
  (project_id, title, description, severity, category, attack_name, variant,
   status, priority, due_date, evidence)
VALUES (
  (SELECT id FROM blueteam.mitigation_projects WHERE scan_date = '2026-03-08' ORDER BY id DESC LIMIT 1),
  'compliance.pci_auth_controls / account_lockout',
  '',
  'high',
  'UNKNOWN',
  'compliance.pci_auth_controls',
  'account_lockout',
  'not_started',
  2,
  CURRENT_DATE + INTERVAL '30 days',
  'attempt 7: status=404, locked=False; attempt 8: status=404, locked=False; attempt 9: status=404, locked=False; attempt 10: status=404, locked=False; attempt 11: status=404, locked=False'
);

-- Issue 28: HIGH - UNKNOWN - compliance.pci_auth_controls
INSERT INTO blueteam.mitigation_issues
  (project_id, title, description, severity, category, attack_name, variant,
   status, priority, due_date, evidence)
VALUES (
  (SELECT id FROM blueteam.mitigation_projects WHERE scan_date = '2026-03-08' ORDER BY id DESC LIMIT 1),
  'compliance.pci_auth_controls / hardcoded_credentials',
  '',
  'high',
  'UNKNOWN',
  'compliance.pci_auth_controls',
  'hardcoded_credentials',
  'not_started',
  2,
  CURRENT_DATE + INTERVAL '30 days',
  '/etc/ImageMagick-6/delegates.xml:88: <delegate decode="pdf" encode="eps" mode="bi" command="&quot;gs&quot; -sstdout=%%stderr -dQUIET -dSAFER -dBATCH -dNOPAUS
/etc/ImageMagick-6/delegates.xml:89: <delegate decode="pdf" encode="ps" mode="bi" command="&quot;gs&quot; -sstdout=%%stderr -dQUIET -dSAFER -dBATCH -dNOPAUSE
/etc/samba/smb.conf:91: passwd chat = *Enter\snew\s*\spassword:* %n\n *Retype\snew\s*\spassword:* %n\n *password\supdated\ssuccessfully* .
/etc/profile.d/vte-2.91.sh:36: local pwd=''~''
);

-- Issue 29: HIGH - UNKNOWN - compliance.pci_data_protection
INSERT INTO blueteam.mitigation_issues
  (project_id, title, description, severity, category, attack_name, variant,
   status, priority, due_date, evidence)
VALUES (
  (SELECT id FROM blueteam.mitigation_projects WHERE scan_date = '2026-03-08' ORDER BY id DESC LIMIT 1),
  'compliance.pci_data_protection / encryption_algorithm',
  '',
  'high',
  'UNKNOWN',
  'compliance.pci_data_protection',
  'encryption_algorithm',
  'not_started',
  2,
  CURRENT_DATE + INTERVAL '30 days',
  '/var/www/html/wordpress/wp-content/plugins/worker/src/PHPSecLib/Net/SSH1.php: weak algorithm ''idea'' configured
/var/www/html/wordpress/wp-content/plugins/worker/src/PHPSecLib/Net/SSH1.php: weak algorithm ''des'' configured
/var/www/html/wordpress/wp-content/plugins/worker/src/PHPSecLib/Net/SSH1.php: weak algorithm ''3des'' configured
/var/www/html/wordpress/wp-content/plugins/worker/src/PHPSecLib/Net/SSH1.php: weak algorithm ''rc4'' configured
/var/www/html/wordpress/wp-content/plugins/worker/'
);

-- Issue 30: HIGH - UNKNOWN - compliance.pci_logging
INSERT INTO blueteam.mitigation_issues
  (project_id, title, description, severity, category, attack_name, variant,
   status, priority, due_date, evidence)
VALUES (
  (SELECT id FROM blueteam.mitigation_projects WHERE scan_date = '2026-03-08' ORDER BY id DESC LIMIT 1),
  'compliance.pci_logging / log_field_completeness',
  '',
  'high',
  'UNKNOWN',
  'compliance.pci_logging',
  'log_field_completeness',
  'not_started',
  2,
  CURRENT_DATE + INTERVAL '30 days',
  'Coverage: {''timestamp'': 15, ''event_type'': 0, ''outcome'': 1, ''source_ip'': 0, ''user'': 0}, sample_size: 15'
);

-- Issue 31: MEDIUM - UNKNOWN - dns.dnssec
INSERT INTO blueteam.mitigation_issues
  (project_id, title, description, severity, category, attack_name, variant,
   status, priority, due_date, evidence)
VALUES (
  (SELECT id FROM blueteam.mitigation_projects WHERE scan_date = '2026-03-08' ORDER BY id DESC LIMIT 1),
  'dns.dnssec / dnssec_enabled',
  '',
  'medium',
  'UNKNOWN',
  'dns.dnssec',
  'dnssec_enabled',
  'not_started',
  3,
  CURRENT_DATE + INTERVAL '60 days',
  'No RRSIG records found for 8qdj5it341kfv92u.brandonquig.com'
);

-- Issue 32: HIGH - UNKNOWN - dns.email_auth
INSERT INTO blueteam.mitigation_issues
  (project_id, title, description, severity, category, attack_name, variant,
   status, priority, due_date, evidence)
VALUES (
  (SELECT id FROM blueteam.mitigation_projects WHERE scan_date = '2026-03-08' ORDER BY id DESC LIMIT 1),
  'dns.email_auth / spf',
  '',
  'high',
  'UNKNOWN',
  'dns.email_auth',
  'spf',
  'not_started',
  2,
  CURRENT_DATE + INTERVAL '30 days',
  'No SPF record found for 8qdj5it341kfv92u.brandonquig.com'
);

-- Issue 33: HIGH - UNKNOWN - dns.email_auth
INSERT INTO blueteam.mitigation_issues
  (project_id, title, description, severity, category, attack_name, variant,
   status, priority, due_date, evidence)
VALUES (
  (SELECT id FROM blueteam.mitigation_projects WHERE scan_date = '2026-03-08' ORDER BY id DESC LIMIT 1),
  'dns.email_auth / dkim',
  '',
  'high',
  'UNKNOWN',
  'dns.email_auth',
  'dkim',
  'not_started',
  2,
  CURRENT_DATE + INTERVAL '30 days',
  'No DKIM records found for any of the common selectors on 8qdj5it341kfv92u.brandonquig.com'
);

-- Issue 34: HIGH - UNKNOWN - dns.email_auth
INSERT INTO blueteam.mitigation_issues
  (project_id, title, description, severity, category, attack_name, variant,
   status, priority, due_date, evidence)
VALUES (
  (SELECT id FROM blueteam.mitigation_projects WHERE scan_date = '2026-03-08' ORDER BY id DESC LIMIT 1),
  'dns.email_auth / dmarc',
  '',
  'high',
  'UNKNOWN',
  'dns.email_auth',
  'dmarc',
  'not_started',
  2,
  CURRENT_DATE + INTERVAL '30 days',
  'No DMARC record found at _dmarc.8qdj5it341kfv92u.brandonquig.com'
);

-- Issue 35: HIGH - UNKNOWN - infrastructure.file_permissions
INSERT INTO blueteam.mitigation_issues
  (project_id, title, description, severity, category, attack_name, variant,
   status, priority, due_date, evidence)
VALUES (
  (SELECT id FROM blueteam.mitigation_projects WHERE scan_date = '2026-03-08' ORDER BY id DESC LIMIT 1),
  'infrastructure.file_permissions / sensitive_configs',
  '',
  'high',
  'UNKNOWN',
  'infrastructure.file_permissions',
  'sensitive_configs',
  'not_started',
  2,
  CURRENT_DATE + INTERVAL '30 days',
  '1 sensitive file(s) with overly permissive permissions'
);

-- Issue 36: HIGH - UNKNOWN - infrastructure.file_permissions
INSERT INTO blueteam.mitigation_issues
  (project_id, title, description, severity, category, attack_name, variant,
   status, priority, due_date, evidence)
VALUES (
  (SELECT id FROM blueteam.mitigation_projects WHERE scan_date = '2026-03-08' ORDER BY id DESC LIMIT 1),
  'infrastructure.file_permissions / web_root_perms',
  '',
  'high',
  'UNKNOWN',
  'infrastructure.file_permissions',
  'web_root_perms',
  'not_started',
  2,
  CURRENT_DATE + INTERVAL '30 days',
  '6 permission issue(s) in web root'
);

-- Issue 37: HIGH - UNKNOWN - infrastructure.firewall_audit
INSERT INTO blueteam.mitigation_issues
  (project_id, title, description, severity, category, attack_name, variant,
   status, priority, due_date, evidence)
VALUES (
  (SELECT id FROM blueteam.mitigation_projects WHERE scan_date = '2026-03-08' ORDER BY id DESC LIMIT 1),
  'infrastructure.firewall_audit / unrestricted_input',
  '',
  'high',
  'UNKNOWN',
  'infrastructure.firewall_audit',
  'unrestricted_input',
  'not_started',
  2,
  CURRENT_DATE + INTERVAL '30 days',
  '3 unrestricted rule(s) on sensitive ports'
);

-- Issue 38: HIGH - UNKNOWN - infrastructure.ssh_audit
INSERT INTO blueteam.mitigation_issues
  (project_id, title, description, severity, category, attack_name, variant,
   status, priority, due_date, evidence)
VALUES (
  (SELECT id FROM blueteam.mitigation_projects WHERE scan_date = '2026-03-08' ORDER BY id DESC LIMIT 1),
  'infrastructure.ssh_audit / password_auth',
  '',
  'high',
  'UNKNOWN',
  'infrastructure.ssh_audit',
  'password_auth',
  'not_started',
  2,
  CURRENT_DATE + INTERVAL '30 days',
  'PasswordAuthentication not set (defaults to yes)'
);

-- Issue 39: CRITICAL - UNKNOWN - secrets.git_history
INSERT INTO blueteam.mitigation_issues
  (project_id, title, description, severity, category, attack_name, variant,
   status, priority, due_date, evidence)
VALUES (
  (SELECT id FROM blueteam.mitigation_projects WHERE scan_date = '2026-03-08' ORDER BY id DESC LIMIT 1),
  'secrets.git_history / git_directory_web',
  '',
  'critical',
  'UNKNOWN',
  'secrets.git_history',
  'git_directory_web',
  'not_started',
  1,
  CURRENT_DATE + INTERVAL '3 days',
  '/.git/HEAD returned HTTP 200 containing ''ref: ''. The .git directory is publicly accessible.'
);

-- Issue 40: MEDIUM - UNKNOWN - web.certificate
INSERT INTO blueteam.mitigation_issues
  (project_id, title, description, severity, category, attack_name, variant,
   status, priority, due_date, evidence)
VALUES (
  (SELECT id FROM blueteam.mitigation_projects WHERE scan_date = '2026-03-08' ORDER BY id DESC LIMIT 1),
  'web.certificate / cert_key_size',
  '',
  'medium',
  'UNKNOWN',
  'web.certificate',
  'cert_key_size',
  'not_started',
  3,
  CURRENT_DATE + INTERVAL '60 days',
  'Weak RSA key: 1024 bits'
);

-- Issue 41: LOW - UNKNOWN - web.server_fingerprint
INSERT INTO blueteam.mitigation_issues
  (project_id, title, description, severity, category, attack_name, variant,
   status, priority, due_date, evidence)
VALUES (
  (SELECT id FROM blueteam.mitigation_projects WHERE scan_date = '2026-03-08' ORDER BY id DESC LIMIT 1),
  'web.server_fingerprint / error_page_fingerprint',
  '',
  'low',
  'UNKNOWN',
  'web.server_fingerprint',
  'error_page_fingerprint',
  'not_started',
  4,
  CURRENT_DATE + INTERVAL '90 days',
  'Error page reveals technology: nginx'
);

-- Issue 42: HIGH - UNKNOWN - web.session
INSERT INTO blueteam.mitigation_issues
  (project_id, title, description, severity, category, attack_name, variant,
   status, priority, due_date, evidence)
VALUES (
  (SELECT id FROM blueteam.mitigation_projects WHERE scan_date = '2026-03-08' ORDER BY id DESC LIMIT 1),
  'web.session / httponly_flag',
  '',
  'high',
  'UNKNOWN',
  'web.session',
  'httponly_flag',
  'not_started',
  2,
  CURRENT_DATE + INTERVAL '30 days',
  'HttpOnly flag MISSING from Set-Cookie: '
);

-- Issue 43: MEDIUM - UNKNOWN - web.session
INSERT INTO blueteam.mitigation_issues
  (project_id, title, description, severity, category, attack_name, variant,
   status, priority, due_date, evidence)
VALUES (
  (SELECT id FROM blueteam.mitigation_projects WHERE scan_date = '2026-03-08' ORDER BY id DESC LIMIT 1),
  'web.session / secure_flag',
  '',
  'medium',
  'UNKNOWN',
  'web.session',
  'secure_flag',
  'not_started',
  3,
  CURRENT_DATE + INTERVAL '60 days',
  'Secure flag MISSING from Set-Cookie: '
);

-- Issue 44: MEDIUM - UNKNOWN - web.session
INSERT INTO blueteam.mitigation_issues
  (project_id, title, description, severity, category, attack_name, variant,
   status, priority, due_date, evidence)
VALUES (
  (SELECT id FROM blueteam.mitigation_projects WHERE scan_date = '2026-03-08' ORDER BY id DESC LIMIT 1),
  'web.session / samesite_attribute',
  '',
  'medium',
  'UNKNOWN',
  'web.session',
  'samesite_attribute',
  'not_started',
  3,
  CURRENT_DATE + INTERVAL '60 days',
  'SameSite attribute MISSING from Set-Cookie: '
);


COMMIT;

-- Summary: 44 vulnerable findings imported
-- By severity:
--   CRITICAL: 9
--   HIGH: 17
--   MEDIUM: 16
--   LOW: 2
