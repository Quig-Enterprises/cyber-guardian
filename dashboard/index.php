<?php
/**
 * Security Dashboard - Artemis Platform
 * Cybersecurity posture, compliance, incident, and red team overview
 */

// Session is validated by nginx auth_request against Keystone before this runs.
// User identity is injected as HTTP headers by nginx from Keystone's auth response.
$session = [
    'sub'   => (int) ($_SERVER['HTTP_X_AUTH_USER_ID'] ?? 0),
    'name'  => $_SERVER['HTTP_X_AUTH_USER'] ?? 'User',
    'email' => '',
    'super' => ($_SERVER['HTTP_X_AUTH_SUPER'] ?? '0') === '1',
];
if (!$session['sub']) {
    header('Location: /admin/login.php?redirect=' . urlencode($_SERVER['REQUEST_URI']));
    exit;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Dashboard - Artemis</title>
    <link rel="stylesheet" href="css/security.css?v=20260307e">
</head>
<body>
    <div class="dashboard-container">

        <!-- Header -->
        <header class="dashboard-header">
            <div class="header-left">
                <h1>SECURITY DASHBOARD</h1>
                <span class="header-subtitle">ARTEMIS PLATFORM</span>
            </div>
            <div class="header-right">
                <a href="/" class="nav-back">&larr; Artemis</a>
                <button class="notif-bell-btn" onclick="toggleNotifPanel()" title="Notification Settings">
                    <span class="notif-bell-icon">&#128276;</span>
                    <span class="notif-bell-dot" id="notif-bell-dot" style="display:none;"></span>
                </button>
                <div class="user-menu">
                    <button class="user-menu-trigger" onclick="toggleUserMenu()">
                        <span class="user-avatar"><?php echo strtoupper(substr($session['name'] ?? 'U', 0, 1)); ?></span>
                        <span class="user-name"><?php echo htmlspecialchars($session['name'] ?? 'User'); ?></span>
                        <span class="dropdown-arrow">&#9660;</span>
                    </button>
                    <div class="user-dropdown" id="user-dropdown">
                        <div class="dropdown-header">
                            <strong><?php echo htmlspecialchars($session['name'] ?? 'User'); ?></strong>
                            <?php if (!empty($session['super'])): ?>
                            <span class="badge badge-super">SUPER</span>
                            <?php endif; ?>
                        </div>
                        <a href="/admin/profile.php" class="dropdown-item">Profile</a>
                        <a href="/admin/change-password.php" class="dropdown-item">Change Password</a>
                        <div class="dropdown-divider"></div>
                        <a href="/admin/logout.php" class="dropdown-item dropdown-item-danger">Logout</a>
                    </div>
                </div>
            </div>
        </header>

        <!-- Tab Navigation -->
        <nav class="tab-nav">
            <a href="#posture" class="active">Posture</a>
            <a href="#compliance">Compliance</a>
            <a href="#incidents">Incidents</a>
            <a href="#redteam">Red Team</a>
            <a href="#malware">Malware</a>
        </nav>

        <!-- Notification Preferences Modal (requires positive close - no click-outside-to-dismiss) -->
        <div class="notif-modal-overlay" id="notif-modal" style="display:none;">
            <div class="notif-modal">
                <div class="notif-modal-header">
                    <h3>Notification Preferences</h3>
                </div>
                <div class="notif-modal-body">
                    <!-- Master Toggle -->
                    <div class="notif-section">
                        <div class="notif-toggle-row">
                            <label>Enable Notifications</label>
                            <label class="toggle-switch">
                                <input type="checkbox" id="notif-enabled" checked>
                                <span class="toggle-slider"></span>
                            </label>
                        </div>
                    </div>

                    <!-- Categories -->
                    <div class="notif-section">
                        <h4 class="notif-section-title">Categories</h4>
                        <div class="notif-toggle-row">
                            <label>AI Attacks</label>
                            <label class="toggle-switch"><input type="checkbox" id="notif-cat-ai" checked><span class="toggle-slider"></span></label>
                        </div>
                        <div class="notif-toggle-row">
                            <label>API Attacks</label>
                            <label class="toggle-switch"><input type="checkbox" id="notif-cat-api" checked><span class="toggle-slider"></span></label>
                        </div>
                        <div class="notif-toggle-row">
                            <label>Web Attacks</label>
                            <label class="toggle-switch"><input type="checkbox" id="notif-cat-web" checked><span class="toggle-slider"></span></label>
                        </div>
                        <div class="notif-toggle-row">
                            <label>Compliance</label>
                            <label class="toggle-switch"><input type="checkbox" id="notif-cat-compliance" checked><span class="toggle-slider"></span></label>
                        </div>
                    </div>

                    <!-- Severity -->
                    <div class="notif-section">
                        <h4 class="notif-section-title">Minimum Severity</h4>
                        <div class="notif-form-group">
                            <select id="notif-min-severity">
                                <option value="critical">Critical only</option>
                                <option value="high">High and above</option>
                                <option value="medium" selected>Medium and above</option>
                                <option value="low">Low and above</option>
                                <option value="info">All severities</option>
                            </select>
                        </div>
                    </div>

                    <!-- Status Filters -->
                    <div class="notif-section">
                        <h4 class="notif-section-title">Finding Status</h4>
                        <div class="notif-toggle-row">
                            <label>Vulnerable</label>
                            <label class="toggle-switch"><input type="checkbox" id="notif-status-vulnerable" checked><span class="toggle-slider"></span></label>
                        </div>
                        <div class="notif-toggle-row">
                            <label>Partial</label>
                            <label class="toggle-switch"><input type="checkbox" id="notif-status-partial" checked><span class="toggle-slider"></span></label>
                        </div>
                        <div class="notif-toggle-row">
                            <label>Defended</label>
                            <label class="toggle-switch"><input type="checkbox" id="notif-status-defended"><span class="toggle-slider"></span></label>
                        </div>
                        <div class="notif-toggle-row">
                            <label>Error</label>
                            <label class="toggle-switch"><input type="checkbox" id="notif-status-error"><span class="toggle-slider"></span></label>
                        </div>
                    </div>

                    <!-- Dedup Mode -->
                    <div class="notif-section">
                        <h4 class="notif-section-title">Duplicate Handling</h4>
                        <div class="notif-form-group">
                            <select id="notif-dedup-mode">
                                <option value="first_only" selected>Alert once per finding (recommended)</option>
                                <option value="every_scan">Alert every scan</option>
                            </select>
                        </div>
                    </div>

                    <!-- Emergency Alerts -->
                    <div class="notif-section">
                        <h4 class="notif-section-title">Emergency Alerts</h4>
                        <div class="notif-toggle-row">
                            <label>Receive emergency alerts</label>
                            <label class="toggle-switch"><input type="checkbox" id="notif-emergency" checked><span class="toggle-slider"></span></label>
                        </div>
                        <p class="notif-hint">Emergency alerts bypass all filters for critical findings.</p>
                    </div>

                    <?php if (!empty($session['super'])): ?>
                    <!-- Emergency Rules (super admin only) -->
                    <div class="notif-section">
                        <h4 class="notif-section-title">Emergency Rules <span class="badge badge-super">ADMIN</span></h4>
                        <div id="emergency-rules-list" class="emergency-rules-list">
                            <div class="empty-state">Loading rules...</div>
                        </div>
                        <button class="notif-add-rule-btn" onclick="openAddRuleForm()">+ Add Rule</button>
                        <div id="add-rule-form" style="display:none;" class="add-rule-form">
                            <div class="notif-form-group">
                                <label>Rule Name</label>
                                <input type="text" id="rule-name" placeholder="e.g. SQL Injection Alert">
                            </div>
                            <div class="notif-form-group">
                                <label>Description</label>
                                <input type="text" id="rule-description" placeholder="Optional description">
                            </div>
                            <div class="notif-form-group">
                                <label>Match Severity (comma-separated)</label>
                                <input type="text" id="rule-severity" placeholder="e.g. critical,high">
                            </div>
                            <div class="notif-form-group">
                                <label>Match Status (comma-separated)</label>
                                <input type="text" id="rule-status" placeholder="e.g. vulnerable,partial">
                            </div>
                            <div class="notif-form-group">
                                <label>Match Category (comma-separated)</label>
                                <input type="text" id="rule-category" placeholder="e.g. ai,api">
                            </div>
                            <div class="notif-form-group">
                                <label>Match Attack (regex pattern)</label>
                                <input type="text" id="rule-attack" placeholder="e.g. sql_injection.*">
                            </div>
                            <div class="add-rule-actions">
                                <button class="notif-btn notif-btn-cancel" onclick="closeAddRuleForm()">Cancel</button>
                                <button class="notif-btn notif-btn-save" onclick="saveNewRule()">Add Rule</button>
                            </div>
                        </div>
                    </div>
                    <?php endif; ?>
                </div>
                <div class="notif-modal-actions">
                    <button class="notif-btn notif-btn-cancel" onclick="closeNotifPanel()">Cancel</button>
                    <button class="notif-btn notif-btn-save" onclick="saveNotifPrefs()">Save</button>
                </div>
            </div>
        </div>

        <!-- Tab 1: Posture (default visible) -->
        <div id="tab-posture" class="tab-content active">
            <div id="dfars-banner" class="dfars-banner" style="display:none;">
                <span class="dfars-icon">&#9888;</span>
                <span id="dfars-banner-text">DFARS REPORTING OVERDUE</span>
            </div>

            <div class="posture-top">
                <div class="score-gauge">
                    <div class="score-ring" id="score-ring" title="Overall Posture score (0–100): weighted composite of Compliance (30%), Red Team (25%), Incident (20%), Monitoring (15%), and Malware Defense (10%). Green ≥80, Yellow ≥50, Red &lt;50">
                        <svg viewBox="0 0 120 120" class="score-svg">
                            <circle cx="60" cy="60" r="54" class="score-track"></circle>
                            <circle cx="60" cy="60" r="54" class="score-fill" id="score-circle"></circle>
                        </svg>
                        <div class="score-value" id="posture-score">--</div>
                        <div class="score-label">OVERALL POSTURE</div>
                    </div>
                </div>
                <div class="score-cards" id="score-cards">
                    <a href="#compliance" class="score-card score-card-compliance score-card-link" title="Compliance score (0–100): percentage of NIST 800-171 controls marked Implemented or Partially Implemented, weighted at 30% of overall posture — click to view Compliance tab">
                        <div class="score-card-value" id="score-compliance">--</div>
                        <div class="score-card-label">Compliance</div>
                        <div class="score-card-weight">30%</div>
                    </a>
                    <a href="#redteam" class="score-card score-card-redteam score-card-link" title="Red Team score (0–100): percentage of simulated attack scenarios successfully defended, weighted at 25% of overall posture — click to view Red Team tab">
                        <div class="score-card-value" id="score-redteam">--</div>
                        <div class="score-card-label">Red Team</div>
                        <div class="score-card-weight">25%</div>
                    </a>
                    <a href="#incidents" class="score-card score-card-incident score-card-link" title="Incident score (0–100): based on open incident count and severity. 100 = no open incidents. Weighted at 20% of overall posture — click to view Incidents tab">
                        <div class="score-card-value" id="score-incident">--</div>
                        <div class="score-card-label">Incident</div>
                        <div class="score-card-weight">20%</div>
                    </a>
                    <a href="#incidents" class="score-card score-card-monitoring score-card-link" title="Monitoring score (0–100): reflects coverage and freshness of active monitoring and alerting. Weighted at 15% of overall posture — click to view Incidents tab">
                        <div class="score-card-value" id="score-monitoring">--</div>
                        <div class="score-card-label">Monitoring</div>
                        <div class="score-card-weight">15%</div>
                    </a>
                    <a href="#malware" class="score-card score-card-malware score-card-link" title="Malware Defense score (0–100): based on scanner coverage, scan recency, and active detection count. Weighted at 10% of overall posture — click to view Malware tab">
                        <div class="score-card-value" id="score-malware">--</div>
                        <div class="score-card-label">Malware</div>
                        <div class="score-card-weight">10%</div>
                    </a>
                </div>
            </div>

            <div class="posture-details">
                <div class="detail-row">
                    <div class="card">
                        <div class="card-header">
                            <h2>Controls Progress</h2>
                            <span class="controls-count" id="controls-count">-- / -- Controls</span>
                        </div>
                        <div class="progress-bar-container" id="controls-bar">
                            <div class="progress-bar-fill" id="controls-bar-fill" style="width:0%"></div>
                        </div>

                        <!-- CMMC Level Breakdown -->
                        <div class="cmmc-levels">
                            <h3 class="cmmc-heading">CMMC LEVEL BREAKDOWN</h3>
                            <div class="cmmc-cards">
                                <div class="cmmc-card" data-cmmc-level="1" title="CMMC Level 1 (Foundational): 17 basic safeguarding practices. Percentage shown is controls implemented out of 17 required">
                                    <div class="cmmc-label">Level 1</div>
                                    <div class="cmmc-desc">Foundational</div>
                                    <div class="cmmc-ring-container">
                                        <svg viewBox="0 0 80 80" class="cmmc-ring-svg">
                                            <circle cx="40" cy="40" r="34" fill="none" class="cmmc-ring-track"></circle>
                                            <circle cx="40" cy="40" r="34" fill="none" class="cmmc-ring-fill cmmc-ring-l1" id="cmmc-ring-1"></circle>
                                        </svg>
                                        <div class="cmmc-pct" id="cmmc-pct-1">--</div>
                                    </div>
                                    <div class="cmmc-counts" id="cmmc-counts-1" title="Implemented controls / total required for Level 1">-- / 17</div>
                                </div>
                                <div class="cmmc-card" data-cmmc-level="2" title="CMMC Level 2 (Advanced): 110 practices aligned to NIST SP 800-171. Percentage shown is cumulative controls implemented through Level 2">
                                    <div class="cmmc-label">Level 2</div>
                                    <div class="cmmc-desc">Advanced</div>
                                    <div class="cmmc-ring-container">
                                        <svg viewBox="0 0 80 80" class="cmmc-ring-svg">
                                            <circle cx="40" cy="40" r="34" fill="none" class="cmmc-ring-track"></circle>
                                            <circle cx="40" cy="40" r="34" fill="none" class="cmmc-ring-fill cmmc-ring-l2" id="cmmc-ring-2"></circle>
                                        </svg>
                                        <div class="cmmc-pct" id="cmmc-pct-2">--</div>
                                    </div>
                                    <div class="cmmc-counts" id="cmmc-counts-2" title="Implemented controls / total required for Level 2 (cumulative)">-- / 110</div>
                                </div>
                                <div class="cmmc-card" data-cmmc-level="3" title="CMMC Level 3 (Expert): 134 practices based on NIST SP 800-172. Percentage shown is cumulative controls implemented through Level 3">
                                    <div class="cmmc-label">Level 3</div>
                                    <div class="cmmc-desc">Expert</div>
                                    <div class="cmmc-ring-container">
                                        <svg viewBox="0 0 80 80" class="cmmc-ring-svg">
                                            <circle cx="40" cy="40" r="34" fill="none" class="cmmc-ring-track"></circle>
                                            <circle cx="40" cy="40" r="34" fill="none" class="cmmc-ring-fill cmmc-ring-l3" id="cmmc-ring-3"></circle>
                                        </svg>
                                        <div class="cmmc-pct" id="cmmc-pct-3">--</div>
                                    </div>
                                    <div class="cmmc-counts" id="cmmc-counts-3" title="Implemented controls / total required for Level 3 (cumulative)">-- / 134</div>
                                </div>
                            </div>
                        </div>
                    </div>
                    <div class="card">
                        <div class="card-header"><h2>Active Incidents</h2></div>
                        <div class="incidents-summary" id="incidents-summary">
                            <a href="#incidents" class="incident-count incident-critical incident-link" data-inc-severity="critical" title="Click to view open Critical incidents"><span class="incident-num" id="inc-critical">0</span><span class="incident-sev">CRITICAL</span></a>
                            <a href="#incidents" class="incident-count incident-high incident-link" data-inc-severity="high" title="Click to view open High incidents"><span class="incident-num" id="inc-high">0</span><span class="incident-sev">HIGH</span></a>
                            <a href="#incidents" class="incident-count incident-medium incident-link" data-inc-severity="medium" title="Click to view open Medium incidents"><span class="incident-num" id="inc-medium">0</span><span class="incident-sev">MEDIUM</span></a>
                            <a href="#incidents" class="incident-count incident-low incident-link" data-inc-severity="low" title="Click to view open Low incidents"><span class="incident-num" id="inc-low">0</span><span class="incident-sev">LOW</span></a>
                        </div>
                    </div>
                </div>

                <div class="card">
                    <div class="card-header"><h2>Recent Alerts</h2></div>
                    <div class="alerts-feed" id="recent-alerts">
                        <div class="empty-state">Loading alerts...</div>
                    </div>
                </div>

                <div class="card">
                    <div class="card-header"><h2>Posture Trend</h2></div>
                    <div class="chart-container">
                        <canvas id="posture-chart" width="800" height="250"></canvas>
                    </div>
                </div>
            </div>
        </div>

        <!-- Tab 2: Compliance -->
        <div id="tab-compliance" class="tab-content">
            <div id="compliance-filter-banner" class="filter-banner" style="display:none;">
                <span id="filter-banner-text"></span>
                <button class="filter-clear-btn" id="filter-clear-btn">Clear Filter</button>
            </div>
            <div class="cmmc-filter-bar">
                <span class="cmmc-filter-label">FRAMEWORK</span>
                <button class="cmmc-filter-btn" data-framework-filter="nist_800_171">CMMC / NIST</button>
                <button class="cmmc-filter-btn" data-framework-filter="hipaa">HIPAA</button>
                <button class="cmmc-filter-btn" data-framework-filter="pci_dss_v4">PCI DSS</button>
                <span class="cmmc-filter-label" style="margin-left:12px;">CMMC LEVEL</span>
                <button class="cmmc-filter-btn" data-cmmc-filter="1">CMMC Level 1</button>
                <button class="cmmc-filter-btn" data-cmmc-filter="2">CMMC Level 2</button>
                <button class="cmmc-filter-btn" data-cmmc-filter="3">CMMC Level 3</button>
            </div>
            <div id="compliance-summary" class="compliance-summary">
                <div class="summary-pill pill-implemented" title="Controls fully implemented and verified"><span class="pill-num" id="comp-implemented">0</span> Implemented</div>
                <div class="summary-pill pill-partial" title="Controls that are partially implemented — some requirements met but not all"><span class="pill-num" id="comp-partial">0</span> Partial</div>
                <div class="summary-pill pill-not-assessed" title="Controls not yet evaluated — status unknown"><span class="pill-num" id="comp-not-assessed">0</span> Not Assessed</div>
                <div class="summary-pill pill-planned" title="Controls planned for implementation but not yet in place"><span class="pill-num" id="comp-planned">0</span> Planned</div>
                <div class="summary-pill pill-na" title="Controls marked Not Applicable — formally excluded from scope"><span class="pill-num" id="comp-na">0</span> N/A</div>
            </div>
            <div class="card">
                <table class="data-table" id="compliance-table">
                    <thead>
                        <tr>
                            <th></th>
                            <th>Family</th>
                            <th>Implemented</th>
                            <th>Partial</th>
                            <th>Not Assessed</th>
                            <th>N/A</th>
                            <th>Total</th>
                        </tr>
                    </thead>
                    <tbody id="compliance-body">
                        <tr><td colspan="7" class="empty-state">Loading compliance data...</td></tr>
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Tab 3: Incidents -->
        <div id="tab-incidents" class="tab-content">
            <div id="incident-filter-banner" class="filter-banner" style="display:none;">
                <span id="incident-filter-text"></span>
                <button class="filter-clear-btn" onclick="clearIncidentFilter()">Clear Filter</button>
            </div>
            <div id="dfars-countdown" class="dfars-countdown" style="display:none;">
                <span class="dfars-icon">&#9888;</span>
                <span id="dfars-countdown-text">DFARS reporting deadline approaching</span>
            </div>
            <div class="card">
                <table class="data-table" id="incidents-table">
                    <thead>
                        <tr>
                            <th>Severity</th>
                            <th>Status</th>
                            <th>Title</th>
                            <th>CUI</th>
                            <th>DFARS</th>
                            <th>Elapsed</th>
                        </tr>
                    </thead>
                    <tbody id="incidents-body">
                        <tr><td colspan="6" class="empty-state">Loading incidents...</td></tr>
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Tab 4: Red Team -->
        <div id="tab-redteam" class="tab-content">
            <div class="redteam-meta" id="redteam-meta"></div>
            <div class="redteam-meta" id="redteam-timing" style="display:none; color: var(--text-secondary); font-size: 0.85em; margin-top: 4px;"></div>

            <!-- Schedule Management Card -->
            <div class="card" id="schedule-card">
                <div class="card-header">
                    <h2>Scan Schedules</h2>
                    <?php if (!empty($session['super'])): ?>
                    <button class="schedule-add-btn" onclick="openScheduleModal()">+ Add Schedule</button>
                    <?php endif; ?>
                </div>
                <table class="data-table" id="schedule-table">
                    <thead>
                        <tr>
                            <th>Status</th>
                            <th>Name</th>
                            <th>Schedule</th>
                            <th>Category</th>
                            <th>Next Run</th>
                            <?php if (!empty($session['super'])): ?>
                            <th>Actions</th>
                            <?php endif; ?>
                        </tr>
                    </thead>
                    <tbody id="schedule-body">
                        <tr><td colspan="6" class="empty-state">Loading schedules...</td></tr>
                    </tbody>
                </table>
            </div>

            <?php if (!empty($session['super'])): ?>
            <!-- Schedule Modal (requires positive close - no click-outside-to-dismiss) -->
            <div class="schedule-modal-overlay" id="schedule-modal" style="display:none;">
                <div class="schedule-modal">
                    <div class="schedule-modal-header">
                        <h3 id="schedule-modal-title">Add Schedule</h3>
                    </div>
                    <form id="schedule-form" onsubmit="saveSchedule(event)">
                        <input type="hidden" id="sched-id" value="">
                        <div class="schedule-form-group">
                            <label for="sched-name">Name</label>
                            <input type="text" id="sched-name" required placeholder="e.g. Weekly Full Suite">
                        </div>
                        <div class="schedule-form-group">
                            <label for="sched-category">Category</label>
                            <select id="sched-category">
                                <option value="all">All Categories</option>
                                <option value="ai">AI</option>
                                <option value="api">API</option>
                                <option value="web">Web</option>
                                <option value="compliance">Compliance</option>
                            </select>
                        </div>
                        <div class="schedule-form-group">
                            <label for="sched-preset">Preset</label>
                            <select id="sched-preset" onchange="applyPreset(this.value)">
                                <option value="">Custom...</option>
                                <option value="0 2 * * 0">Weekly Sunday 2 AM</option>
                                <option value="0 3 * * *">Daily 3 AM</option>
                                <option value="0 0 * * *">Daily Midnight</option>
                                <option value="0 0 * * 1">Weekly Monday Midnight</option>
                                <option value="0 6 * * 1-5">Weekdays 6 AM</option>
                                <option value="0 0 1 * *">Monthly 1st Midnight</option>
                                <option value="0 */6 * * *">Every 6 Hours</option>
                            </select>
                        </div>
                        <div class="schedule-form-group">
                            <label for="sched-cron">Cron Expression</label>
                            <input type="text" id="sched-cron" required placeholder="0 2 * * 0" oninput="updateCronPreview()">
                            <div class="cron-preview" id="cron-preview">--</div>
                        </div>
                        <div class="schedule-form-group">
                            <label for="sched-args">Extra Arguments</label>
                            <input type="text" id="sched-args" placeholder="e.g. --category compliance">
                        </div>
                        <div class="schedule-form-group schedule-form-check">
                            <label>
                                <input type="checkbox" id="sched-enabled" checked>
                                Enabled
                            </label>
                        </div>
                        <div class="schedule-modal-actions">
                            <button type="button" class="schedule-btn schedule-btn-cancel" onclick="closeScheduleModal()">Cancel</button>
                            <button type="submit" class="schedule-btn schedule-btn-save">Save</button>
                        </div>
                    </form>
                </div>
            </div>
            <?php endif; ?>

            <div class="summary-cards" id="redteam-summary">
                <div class="summary-card" data-rt-filter="all" title="Total number of attack simulations executed in the most recent red team scan">
                    <div class="summary-card-value" id="rt-total-attacks">--</div>
                    <div class="summary-card-label">Total Attacks</div>
                </div>
                <div class="summary-card summary-card-green" data-rt-filter="defended" title="Percentage of attack simulations that were successfully blocked or detected (higher is better)">
                    <div class="summary-card-value" id="rt-defended-pct">--</div>
                    <div class="summary-card-label">Defended %</div>
                </div>
                <div class="summary-card summary-card-red" data-rt-filter="vulnerable" title="Number of attack simulations that succeeded — the target was fully vulnerable with no defense triggered">
                    <div class="summary-card-value" id="rt-vulnerable">--</div>
                    <div class="summary-card-label">Vulnerable</div>
                </div>
                <div class="summary-card summary-card-yellow" data-rt-filter="partial" title="Number of attack simulations with partial defense — some mitigations triggered but the attack was not fully blocked">
                    <div class="summary-card-value" id="rt-partial">--</div>
                    <div class="summary-card-label">Partial</div>
                </div>
                <div class="summary-card summary-card-gray" data-rt-filter="error" title="Number of attack simulations that could not be completed due to scanner or connectivity errors">
                    <div class="summary-card-value" id="rt-errors">--</div>
                    <div class="summary-card-label">Errors</div>
                </div>
            </div>

            <div id="rt-filter-banner" class="filter-banner" style="display:none;">
                <span id="rt-filter-banner-text"></span>
                <button class="filter-clear-btn" id="rt-filter-clear-btn">Clear Filter</button>
            </div>

            <div class="redteam-grid">
                <div class="card">
                    <div class="card-header"><h2>Category Breakdown</h2></div>
                    <table class="data-table" id="redteam-categories">
                        <thead>
                            <tr>
                                <th>Category</th>
                                <th>Attacks</th>
                                <th>Vulnerable</th>
                                <th>Partial</th>
                                <th>Defended</th>
                                <th>Errors</th>
                                <th>Duration</th>
                                <th>Defense Rate</th>
                            </tr>
                        </thead>
                        <tbody id="redteam-categories-body">
                            <tr><td colspan="8" class="empty-state">Loading...</td></tr>
                        </tbody>
                    </table>
                </div>

                <div class="card">
                    <div class="card-header"><h2>Severity Distribution</h2></div>
                    <div id="redteam-severity" class="severity-distribution"></div>
                </div>
            </div>

            <div class="card">
                <div class="card-header"><h2>Findings</h2></div>
                <div class="findings-list" id="redteam-findings">
                    <div class="empty-state">Loading findings...</div>
                </div>
            </div>

            <div class="card">
                <div class="card-header"><h2>Scan History</h2></div>
                <table class="data-table" id="scan-history-table">
                    <thead>
                        <tr>
                            <th>Date</th>
                            <th>Attacks</th>
                            <th>Variants</th>
                            <th>Vulnerable</th>
                            <th>Partial</th>
                            <th>Defended</th>
                            <th>Errors</th>
                            <th>Report</th>
                        </tr>
                    </thead>
                    <tbody id="scan-history-body">
                        <tr><td colspan="8" class="empty-state">Loading...</td></tr>
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Tab 5: Malware -->
        <div id="tab-malware" class="tab-content">
            <!-- Summary Cards -->
            <div class="malware-summary">
                <div class="summary-card summary-card-clickable" id="malware-score-card" onclick="openScoreModal()" title="Click to see how this score is calculated and how to improve it">
                    <div class="summary-icon">🛡️</div>
                    <div class="summary-value" id="malware-score-display">--</div>
                    <div class="summary-label">Malware Defense Score <span class="card-hint">&#9432;</span></div>
                </div>
                <div class="summary-card" title="Number of malware scanner runs completed in the last 24 hours">
                    <div class="summary-icon">🔍</div>
                    <div class="summary-value" id="total-scans-today">--</div>
                    <div class="summary-label">Scans Today</div>
                </div>
                <div class="summary-card summary-card-clickable" id="active-threats-card" onclick="scrollToDetections()" title="Click to view active threat detections">
                    <div class="summary-icon">⚠️</div>
                    <div class="summary-value" id="active-threats">--</div>
                    <div class="summary-label">Active Threats <span class="card-hint">&#8595;</span></div>
                </div>
                <div class="summary-card" title="Total number of individual files scanned across all scanners in the last 24 hours">
                    <div class="summary-icon">📁</div>
                    <div class="summary-value" id="files-scanned-24h">--</div>
                    <div class="summary-label">Files Scanned (24h)</div>
                </div>
            </div>

            <!-- Latest Scan Results -->
            <div class="card">
                <div class="card-header"><h2>Latest Scan Results</h2></div>
                <div class="scan-results-grid" id="scan-results-grid">
                    <div class="empty-state">Loading scan results...</div>
                </div>
            </div>

            <!-- Active Detections -->
            <div class="card" id="active-detections-card">
                <div class="card-header">
                    <h2>Active Detections</h2>
                    <span class="count-badge" id="detections-count">0</span>
                </div>
                <div class="table-container">
                    <table class="data-table" id="detections-table">
                        <thead>
                            <tr>
                                <th>Severity</th>
                                <th>File Path</th>
                                <th>Malware Signature</th>
                                <th>Detected</th>
                                <th>Scanner</th>
                                <th>Action</th>
                            </tr>
                        </thead>
                        <tbody id="detections-tbody">
                            <tr><td colspan="6" class="empty-state">No active detections</td></tr>
                        </tbody>
                    </table>
                </div>
            </div>

            <!-- Scanner Status -->
            <div class="card">
                <div class="card-header"><h2>Scanner Status</h2></div>
                <div class="scanner-status-grid" id="scanner-status-grid">
                    <div class="empty-state">Loading scanner status...</div>
                </div>
            </div>
        </div>

    </div>

    <!-- Malware Score Breakdown Modal -->
    <div class="score-modal-overlay" id="malware-score-modal" style="display:none;" onclick="closeScorekModal(event)">
        <div class="score-modal">
            <div class="score-modal-header">
                <h3>Malware Defense Score — How It's Calculated</h3>
                <button class="score-modal-close" onclick="closeScoreModal()">&#x2715;</button>
            </div>
            <div class="score-modal-body" id="score-modal-body">
                <div class="empty-state">Loading...</div>
            </div>
        </div>
    </div>

    <script>
    const AUTH = {
        userId: <?php echo (int)$session['sub']; ?>,
        name: <?php echo json_encode($session['name'] ?? 'User'); ?>,
        email: <?php echo json_encode($session['email'] ?? ''); ?>,
        isSuper: <?php echo !empty($session['super']) ? 'true' : 'false'; ?>
    };
    </script>
    <script>
    function toggleUserMenu() {
        document.getElementById('user-dropdown').classList.toggle('show');
    }
    document.addEventListener('click', function(e) {
        if (!e.target.closest('.user-menu')) {
            document.getElementById('user-dropdown')?.classList.remove('show');
        }
    });
    </script>
    <script src="js/security.js?v=20260307i"></script>
</body>
</html>
