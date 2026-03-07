/**
 * Security Dashboard - Artemis Platform
 * Vanilla JS: tab switching, API fetches, chart rendering
 *
 * Security note: All dynamic content is escaped via escapeHtml() before DOM insertion.
 * Data originates from authenticated server-side API endpoints only.
 */

(function () {
    'use strict';

    // ---- Constants ----
    var API_BASE = '/security-dashboard/api';
    var REFRESH_INTERVAL = 30000; // 30 seconds

    // ---- State ----
    var tabDataLoaded = {};
    var refreshTimer = null;
    var complianceCache = null;
    var activeFilter = null;
    var redteamCache = null;
    var activeRtFilter = null;
    var activeRtCategoryFilter = null;
    var activeRtSeverityFilter = null;

    // ---- Helpers ----

    /** Escape HTML entities to prevent XSS when building markup strings */
    function escapeHtml(str) {
        if (!str) return '';
        var div = document.createElement('div');
        div.appendChild(document.createTextNode(str));
        return div.innerHTML;
    }

    function formatDate(isoString) {
        if (!isoString) return '--';
        var d = new Date(isoString);
        if (isNaN(d.getTime())) return '--';
        var months = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
        var h = d.getHours();
        var m = d.getMinutes();
        var ampm = h >= 12 ? 'PM' : 'AM';
        h = h % 12 || 12;
        return months[d.getMonth()] + ' ' + d.getDate() + ', ' + h + ':' + (m < 10 ? '0' : '') + m + ' ' + ampm;
    }

    function formatElapsed(hours) {
        if (hours == null || isNaN(hours)) return '--';
        hours = Math.abs(hours);
        if (hours >= 24) {
            var d = Math.floor(hours / 24);
            var h = Math.floor(hours % 24);
            return d + 'd ' + h + 'h';
        }
        var hh = Math.floor(hours);
        var mm = Math.round((hours - hh) * 60);
        return hh + 'h ' + mm + 'm';
    }

    function severityClass(severity) {
        var s = (severity || '').toLowerCase();
        if (s === 'critical') return 'badge-critical';
        if (s === 'high') return 'badge-high';
        if (s === 'medium') return 'badge-medium';
        if (s === 'low') return 'badge-low';
        if (s === 'info') return 'badge-info';
        return '';
    }

    /** PICERL stage mapping for incident status badges */
    function statusBadgeMarkup(status) {
        var map = {
            'detected':   { label: 'P - DETECTED',   cls: 'status-detected' },
            'analyzing':  { label: 'I - ANALYZING',   cls: 'status-analyzing' },
            'contained':  { label: 'C - CONTAINED',   cls: 'status-contained' },
            'eradicated': { label: 'E - ERADICATED',  cls: 'status-eradicated' },
            'recovered':  { label: 'R - RECOVERED',   cls: 'status-recovered' },
            'closed':     { label: 'L - CLOSED',      cls: 'status-closed' }
        };
        var info = map[(status || '').toLowerCase()] || { label: escapeHtml(status), cls: '' };
        return '<span class="status-badge ' + info.cls + '">' + info.label + '</span>';
    }

    function complianceBadgeMarkup(status) {
        var cls = 'badge badge-' + (status || '').replace(/ /g, '_');
        var label = (status || '').replace(/_/g, ' ');
        return '<span class="' + cls + '">' + escapeHtml(label) + '</span>';
    }

    function scoreColorClass(score) {
        if (score < 50) return 'score-red';
        if (score < 80) return 'score-yellow';
        return 'score-green';
    }

    function getCategoryFromAttack(attack, categoryKeys) {
        if (!attack) return null;
        var sorted = categoryKeys.slice().sort(function(a, b) { return b.length - a.length; });
        for (var i = 0; i < sorted.length; i++) {
            if (attack === sorted[i] || attack.indexOf(sorted[i] + '.') === 0 || attack.indexOf(sorted[i] + '_') === 0) {
                return sorted[i];
            }
        }
        return null;
    }

    function apiFetch(endpoint) {
        return fetch(API_BASE + '/' + endpoint, {
            credentials: 'same-origin',
            headers: {
                'X-Auth-User-Id': AUTH.userId
            }
        }).then(function (res) {
            if (!res.ok) throw new Error('HTTP ' + res.status);
            return res.json();
        });
    }

    /**
     * Safe DOM builder: sets content on an element using textContent (no HTML parsing).
     * For cases where we need structured markup, we build it from escaped parts only.
     */
    function setText(id, text) {
        var el = document.getElementById(id);
        if (el) el.textContent = text;
    }

    // ---- Tab Switching ----

    var tabs = document.querySelectorAll('.tab-nav a');
    var contents = document.querySelectorAll('.tab-content');

    function switchTab(hash, pushHistory) {
        var target = hash.replace('#', '') || 'posture';
        tabs.forEach(function (t) {
            t.classList.toggle('active', t.getAttribute('href') === '#' + target);
        });
        contents.forEach(function (c) {
            c.classList.toggle('active', c.id === 'tab-' + target);
        });
        // Lazy load on first tab visit
        if (!tabDataLoaded[target]) {
            loadTabData(target);
            tabDataLoaded[target] = true;
        }
        if (pushHistory) {
            history.pushState(null, '', '#' + target);
        } else {
            history.replaceState(null, '', '#' + target);
        }
    }

    function loadTabData(tab) {
        if (tab === 'posture') {
            fetchPosture();
            fetchAlerts();
            // Also fetch compliance data for CMMC rings on posture tab
            if (!complianceCache) {
                apiFetch('compliance.php').then(function (data) {
                    complianceCache = data;
                    if (data.cmmc) renderCmmcLevels(data.cmmc);
                }).catch(function (err) {
                    console.error('CMMC data fetch error:', err);
                });
            } else if (complianceCache.cmmc) {
                renderCmmcLevels(complianceCache.cmmc);
            }
        } else if (tab === 'compliance') {
            fetchCompliance();
        } else if (tab === 'incidents') {
            fetchIncidents();
        } else if (tab === 'redteam') {
            fetchRedteam();
            fetchScanHistory();
            fetchSchedules();
        } else if (tab === 'malware') {
            loadMalwareData();
        }
    }

    // ---- Posture Tab ----

    function fetchPosture() {
        apiFetch('posture.php').then(function (data) {
            renderPosture(data);
        }).catch(function (err) {
            setText('posture-score', 'ERR');
            console.error('Posture fetch error:', err);
        });
    }

    function renderPosture(data) {
        var c = data.current || {};
        var overall = Math.round(c.overall || 0);

        // Score gauge
        setText('posture-score', overall);

        var ring = document.getElementById('score-ring');
        ring.className = 'score-ring ' + scoreColorClass(overall);

        // SVG circle animation (circumference = 2 * PI * r where r=54)
        var circle = document.getElementById('score-circle');
        var circumference = 2 * Math.PI * 54;
        var offset = circumference - (overall / 100) * circumference;
        circle.style.strokeDashoffset = offset;

        // Sub-scores
        ['compliance', 'redteam', 'incident', 'monitoring'].forEach(function (f) {
            setText('score-' + f, Math.round(c[f] || 0));
        });

        // Malware score
        if (c.malware != null) {
            var malwareEl = document.getElementById('score-malware');
            if (malwareEl) {
                malwareEl.textContent = Math.round(c.malware);
                malwareEl.className = 'score-card-value ' + scoreColorClass(c.malware);
            }
        }

        // Controls progress bar
        var impl = c.controls_implemented || 0;
        var total = c.controls_total || 0;
        setText('controls-count', impl + ' / ' + total + ' Controls');
        var pct = total > 0 ? Math.round((impl / total) * 100) : 0;
        document.getElementById('controls-bar-fill').style.width = pct + '%';

        // Active incidents by severity
        var inc = c.active_incidents || {};
        setText('inc-critical', inc.critical || 0);
        setText('inc-high', inc.high || 0);
        setText('inc-medium', inc.medium || 0);
        setText('inc-low', inc.low || 0);

        // DFARS posture banner
        var totalCrit = (inc.critical || 0) + (inc.high || 0);
        if (totalCrit > 0) {
            var banner = document.getElementById('dfars-banner');
            banner.style.display = 'flex';
            setText('dfars-banner-text',
                totalCrit + ' CRITICAL/HIGH INCIDENT' + (totalCrit > 1 ? 'S' : '') + ' ACTIVE - MONITOR DFARS COMPLIANCE');
        }

        // Trend chart
        if (data.history && data.history.length > 0) {
            renderPostureChart(data.history);
        }
    }

    // ---- Posture Chart (Canvas 2D - no external libraries) ----

    function renderPostureChart(history) {
        var canvas = document.getElementById('posture-chart');
        if (!canvas) return;
        var ctx = canvas.getContext('2d');

        // Handle high-DPI displays
        var dpr = window.devicePixelRatio || 1;
        var rect = canvas.parentElement.getBoundingClientRect();
        var w = rect.width || 800;
        var h = 250;
        canvas.width = w * dpr;
        canvas.height = h * dpr;
        canvas.style.width = w + 'px';
        canvas.style.height = h + 'px';
        ctx.scale(dpr, dpr);

        var pad = { top: 20, right: 20, bottom: 40, left: 50 };
        var chartW = w - pad.left - pad.right;
        var chartH = h - pad.top - pad.bottom;

        // Chronological order (API returns newest first)
        var points = history.slice().reverse();
        if (points.length < 2) return;

        ctx.clearRect(0, 0, w, h);

        // Horizontal grid lines and Y-axis labels
        ctx.strokeStyle = 'rgba(0, 255, 0, 0.08)';
        ctx.lineWidth = 1;
        for (var gy = 0; gy <= 100; gy += 20) {
            var yy = pad.top + chartH - (gy / 100) * chartH;
            ctx.beginPath();
            ctx.moveTo(pad.left, yy);
            ctx.lineTo(pad.left + chartW, yy);
            ctx.stroke();
            ctx.fillStyle = '#555';
            ctx.font = '10px "Courier New", monospace';
            ctx.textAlign = 'right';
            ctx.fillText(gy.toString(), pad.left - 8, yy + 4);
        }

        // X-axis date labels
        ctx.textAlign = 'center';
        ctx.fillStyle = '#555';
        var labelStep = Math.max(1, Math.floor(points.length / 6));
        for (var li = 0; li < points.length; li += labelStep) {
            var lx = pad.left + (li / (points.length - 1)) * chartW;
            var d = new Date(points[li].scored_at);
            var label = (d.getMonth() + 1) + '/' + d.getDate();
            ctx.fillText(label, lx, h - pad.bottom + 20);
        }

        // Draw line
        ctx.strokeStyle = '#00ff00';
        ctx.lineWidth = 2;
        ctx.shadowColor = 'rgba(0, 255, 0, 0.4)';
        ctx.shadowBlur = 6;
        ctx.beginPath();
        for (var i = 0; i < points.length; i++) {
            var x = pad.left + (i / (points.length - 1)) * chartW;
            var y = pad.top + chartH - ((points[i].overall_score || 0) / 100) * chartH;
            if (i === 0) ctx.moveTo(x, y);
            else ctx.lineTo(x, y);
        }
        ctx.stroke();
        ctx.shadowBlur = 0;

        // Fill area under the line
        ctx.lineTo(pad.left + chartW, pad.top + chartH);
        ctx.lineTo(pad.left, pad.top + chartH);
        ctx.closePath();
        var grad = ctx.createLinearGradient(0, pad.top, 0, pad.top + chartH);
        grad.addColorStop(0, 'rgba(0, 255, 0, 0.15)');
        grad.addColorStop(1, 'rgba(0, 255, 0, 0.01)');
        ctx.fillStyle = grad;
        ctx.fill();

        // Data point dots
        ctx.shadowColor = 'rgba(0, 255, 0, 0.6)';
        ctx.shadowBlur = 4;
        for (var di = 0; di < points.length; di++) {
            var dx = pad.left + (di / (points.length - 1)) * chartW;
            var dy = pad.top + chartH - ((points[di].overall_score || 0) / 100) * chartH;
            ctx.beginPath();
            ctx.arc(dx, dy, 3, 0, Math.PI * 2);
            ctx.fillStyle = '#00ff00';
            ctx.fill();
        }
        ctx.shadowBlur = 0;
    }

    // ---- Alerts Feed ----

    function fetchAlerts() {
        apiFetch('alerts.php').then(function (data) {
            renderAlerts(data);
        }).catch(function (err) {
            var el = document.getElementById('recent-alerts');
            el.textContent = '';
            var errDiv = document.createElement('div');
            errDiv.className = 'error-state';
            errDiv.textContent = 'Failed to load alerts';
            el.appendChild(errDiv);
            console.error('Alerts fetch error:', err);
        });
    }

    function renderAlerts(data) {
        var container = document.getElementById('recent-alerts');
        var alerts = (data.alerts || []).slice(0, 10);

        // Clear previous content
        container.textContent = '';

        if (alerts.length === 0) {
            var empty = document.createElement('div');
            empty.className = 'empty-state';
            empty.textContent = 'No recent alerts';
            container.appendChild(empty);
            return;
        }

        alerts.forEach(function (a) {
            var sev = (a.severity || 'info').toLowerCase();

            var item = document.createElement('div');
            item.className = 'alert-item alert-item-' + sev;

            var header = document.createElement('div');
            header.className = 'alert-header';

            var title = document.createElement('span');
            title.className = 'alert-title';
            title.textContent = a.title || '';
            header.appendChild(title);

            var time = document.createElement('span');
            time.className = 'alert-time';
            time.textContent = formatDate(a.created_at);
            header.appendChild(time);

            item.appendChild(header);

            if (a.description) {
                var desc = document.createElement('div');
                desc.className = 'alert-desc';
                desc.textContent = a.description;
                item.appendChild(desc);
            }

            if (a.acknowledged) {
                var ack = document.createElement('span');
                ack.className = 'alert-ack';
                ack.textContent = 'ACK';
                item.appendChild(ack);
            }

            container.appendChild(item);
        });
    }

    // ---- Compliance Tab ----

    function fetchCompliance() {
        apiFetch('compliance.php').then(function (data) {
            complianceCache = data;
            renderCompliance(data, activeFilter);
            if (data.cmmc) renderCmmcLevels(data.cmmc);
        }).catch(function (err) {
            document.getElementById('compliance-body').textContent = '';
            var tr = document.createElement('tr');
            var td = document.createElement('td');
            td.colSpan = 7;
            td.className = 'error-state';
            td.textContent = 'Failed to load compliance data';
            tr.appendChild(td);
            document.getElementById('compliance-body').appendChild(tr);
            console.error('Compliance fetch error:', err);
        });
    }

    function renderCompliance(data, filterLevel) {
        var controls = data.controls || [];

        // Apply CMMC level filter if set
        if (filterLevel === 'other') {
            controls = controls.filter(function (c) {
                return !c.cmmc_level;
            });
        } else if (filterLevel) {
            controls = controls.filter(function (c) {
                return (parseInt(c.cmmc_level, 10) || 2) <= filterLevel;
            });
        }

        // Recompute family map and totals from (possibly filtered) controls
        var familyMap = {};
        var totals = {
            implemented: 0,
            partially_implemented: 0,
            not_assessed: 0,
            not_applicable: 0,
            planned: 0,
            not_implemented: 0
        };

        controls.forEach(function (c) {
            var fid = c.family_id;
            if (!familyMap[fid]) {
                familyMap[fid] = {
                    name: c.family,
                    family_id: fid,
                    implemented: 0,
                    partially_implemented: 0,
                    not_assessed: 0,
                    not_applicable: 0,
                    planned: 0,
                    not_implemented: 0,
                    total: 0
                };
            }
            var status = c.status;
            if (familyMap[fid][status] !== undefined) familyMap[fid][status]++;
            familyMap[fid].total++;
            if (totals[status] !== undefined) totals[status]++;
        });

        var families = Object.keys(familyMap).sort().map(function (k) { return familyMap[k]; });

        // Summary pills
        setText('comp-implemented', totals.implemented || 0);
        setText('comp-partial', totals.partially_implemented || 0);
        setText('comp-not-assessed', totals.not_assessed || 0);
        setText('comp-planned', totals.planned || 0);
        setText('comp-na', totals.not_applicable || 0);

        // Filter banner
        var banner = document.getElementById('compliance-filter-banner');
        if (filterLevel === 'other') {
            setText('filter-banner-text', 'Showing controls without CMMC level (' + controls.length + ' controls)');
            banner.style.display = 'flex';
        } else if (filterLevel) {
            var levelNames = { 1: 'Level 1 — Foundational', 2: 'Level 2 — Advanced', 3: 'Level 3 — Expert' };
            setText('filter-banner-text', 'Showing CMMC ' + levelNames[filterLevel] + ' controls (' + controls.length + ' controls)');
            banner.style.display = 'flex';
        } else {
            banner.style.display = 'none';
        }

        // Sync CMMC filter button highlights
        document.querySelectorAll('.cmmc-filter-btn').forEach(function (btn) {
            var val = btn.getAttribute('data-cmmc-filter');
            btn.classList.toggle('active', val === String(filterLevel));
        });

        // Build family table
        var tbody = document.getElementById('compliance-body');
        tbody.textContent = '';

        if (families.length === 0) {
            var tr = document.createElement('tr');
            var td = document.createElement('td');
            td.colSpan = 7;
            td.className = 'empty-state';
            td.textContent = 'No compliance data available';
            tr.appendChild(td);
            tbody.appendChild(tr);
            return;
        }

        families.forEach(function (fam) {
            var fid = fam.family_id || '';

            var row = document.createElement('tr');
            row.className = 'clickable-row';
            row.setAttribute('data-family', fid);

            var tdIcon = document.createElement('td');
            var icon = document.createElement('span');
            icon.className = 'expand-icon';
            if (filterLevel) icon.classList.add('expanded');
            icon.textContent = '\u25B6';
            tdIcon.appendChild(icon);
            row.appendChild(tdIcon);

            var tdName = document.createElement('td');
            tdName.textContent = fam.name + ' (' + fid + ')';
            row.appendChild(tdName);

            var fields = ['implemented', 'partially_implemented', 'not_assessed', 'not_applicable', 'total'];
            fields.forEach(function (f) {
                var td = document.createElement('td');
                td.textContent = fam[f] || 0;
                row.appendChild(td);
            });

            row.addEventListener('click', function () {
                toggleFamily(fid, icon);
            });

            tbody.appendChild(row);

            // Detail row with sub-table
            var familyControls = controls.filter(function (c) { return c.family_id === fid; });
            if (familyControls.length > 0) {
                var detailRow = document.createElement('tr');
                // Auto-expand when filter is active
                detailRow.className = filterLevel ? 'detail-row-visible' : 'detail-row-hidden';
                detailRow.setAttribute('data-family-detail', fid);

                var detailTd = document.createElement('td');
                detailTd.colSpan = 7;
                detailTd.className = 'detail-cell';

                var subTable = document.createElement('table');
                subTable.className = 'detail-subtable';

                familyControls.forEach(function (ctrl) {
                    var subRow = document.createElement('tr');

                    var tdId = document.createElement('td');
                    tdId.className = 'ctrl-id';
                    var cid = ctrl.control_id || '';
                    var lvl = String(ctrl.cmmc_level || '');
                    var fid = ctrl.family_id || '';
                    tdId.textContent = (fid && lvl) ? fid + '.L' + lvl + '-' + cid : cid;
                    var farMap = {
                        '3.1.1':'b.1.i','3.1.2':'b.1.ii','3.1.20':'b.1.iii','3.1.22':'b.1.iv',
                        '3.5.1':'b.1.v','3.5.2':'b.1.vi','3.8.3':'b.1.vii','3.10.1':'b.1.viii',
                        '3.10.3':'b.1.ix','3.10.4':'b.1.ix','3.10.5':'b.1.ix',
                        '3.13.1':'b.1.x','3.13.5':'b.1.xi','3.14.1':'b.1.xii',
                        '3.14.2':'b.1.xiii','3.14.4':'b.1.xiv','3.14.5':'b.1.xv'
                    };
                    if (lvl === '1' && farMap[cid]) {
                        tdId.title = 'FAR 52.204-21 ' + farMap[cid] + ' / NIST SP 800-171 \u00A7' + cid;
                    } else if (lvl === '3' && cid.indexOf('e') !== -1) {
                        tdId.title = 'NIST SP 800-172 \u00A7' + cid;
                    } else if (lvl) {
                        tdId.title = 'NIST SP 800-171 Rev 2 \u00A7' + cid;
                    }
                    subRow.appendChild(tdId);

                    var tdStatus = document.createElement('td');
                    tdStatus.insertAdjacentHTML('beforeend', complianceBadgeMarkup(ctrl.status));
                    subRow.appendChild(tdStatus);

                    var tdReq = document.createElement('td');
                    tdReq.className = 'ctrl-req';
                    tdReq.textContent = ctrl.requirement || '';
                    subRow.appendChild(tdReq);

                    subTable.appendChild(subRow);
                });

                detailTd.appendChild(subTable);
                detailRow.appendChild(detailTd);
                tbody.appendChild(detailRow);
            }
        });
    }

    function toggleFamily(fid, iconEl) {
        var detailRow = document.querySelector('[data-family-detail="' + CSS.escape(fid) + '"]');
        if (!detailRow) return;

        var isVisible = detailRow.classList.contains('detail-row-visible');
        if (isVisible) {
            detailRow.classList.remove('detail-row-visible');
            detailRow.classList.add('detail-row-hidden');
            if (iconEl) iconEl.classList.remove('expanded');
        } else {
            detailRow.classList.remove('detail-row-hidden');
            detailRow.classList.add('detail-row-visible');
            if (iconEl) iconEl.classList.add('expanded');
        }
    }

    // ---- CMMC Level Rings ----

    function renderCmmcLevels(cmmc) {
        var levels = [
            { key: 'level1', num: 1, total: 17 },
            { key: 'level2', num: 2, total: 110 },
            { key: 'level3', num: 3, total: 134 }
        ];
        var circumference = 2 * Math.PI * 34; // r=34 from SVG

        levels.forEach(function (lv) {
            var data = cmmc[lv.key];
            if (!data) return;

            var completed = (data.implemented || 0) + (data.na || 0);
            var pct = data.total > 0 ? Math.round((completed / data.total) * 100) : 0;
            var offset = circumference - (pct / 100) * circumference;

            var ring = document.getElementById('cmmc-ring-' + lv.num);
            if (ring) ring.style.strokeDashoffset = offset;

            setText('cmmc-pct-' + lv.num, pct + '%');
            setText('cmmc-counts-' + lv.num, completed + ' / ' + data.total);
        });
    }

    function filterComplianceByLevel(level) {
        activeFilter = level;

        // Highlight the active CMMC card
        document.querySelectorAll('.cmmc-card').forEach(function (card) {
            card.classList.toggle('active-filter', parseInt(card.getAttribute('data-cmmc-level'), 10) === level);
        });

        // Switch to compliance tab (push history so back button returns to posture)
        switchTab('#compliance', true);

        // Force re-render with filter (compliance tab may already be loaded)
        if (complianceCache) {
            tabDataLoaded['compliance'] = true;
            renderCompliance(complianceCache, level);
        }
    }

    function clearComplianceFilter() {
        activeFilter = null;
        document.querySelectorAll('.cmmc-card').forEach(function (card) {
            card.classList.remove('active-filter');
        });
        if (complianceCache) {
            renderCompliance(complianceCache);
        }
    }

    // CMMC card click handlers
    document.querySelectorAll('.cmmc-card').forEach(function (card) {
        card.addEventListener('click', function () {
            var level = parseInt(this.getAttribute('data-cmmc-level'), 10);
            filterComplianceByLevel(level);
        });
    });

    // Filter clear button
    var clearBtn = document.getElementById('filter-clear-btn');
    if (clearBtn) {
        clearBtn.addEventListener('click', function () {
            clearComplianceFilter();
        });
    }

    // ---- Incidents Tab ----

    function fetchIncidents() {
        apiFetch('incidents.php').then(function (data) {
            renderIncidents(data);
        }).catch(function (err) {
            var tbody = document.getElementById('incidents-body');
            tbody.textContent = '';
            var tr = document.createElement('tr');
            var td = document.createElement('td');
            td.colSpan = 6;
            td.className = 'error-state';
            td.textContent = 'Failed to load incidents';
            tr.appendChild(td);
            tbody.appendChild(tr);
            console.error('Incidents fetch error:', err);
        });
    }

    function renderIncidents(data) {
        var incidents = data.incidents || [];
        var dfars = data.dfars || {};

        // DFARS countdown banner
        if (dfars.overdue > 0) {
            var countdown = document.getElementById('dfars-countdown');
            countdown.style.display = 'flex';
            setText('dfars-countdown-text',
                'DFARS OVERDUE: ' + dfars.overdue + ' incident(s) past 72-hour reporting deadline');
        } else if (dfars.pending > 0) {
            var countdown = document.getElementById('dfars-countdown');
            countdown.style.display = 'flex';
            countdown.style.borderColor = 'var(--warning-yellow)';
            countdown.style.background = 'rgba(255, 170, 0, 0.1)';
            countdown.style.color = 'var(--warning-yellow)';
            setText('dfars-countdown-text',
                'DFARS PENDING: ' + dfars.pending + ' incident(s) within 72-hour reporting window');
        }

        // Build incidents table with DOM methods
        var tbody = document.getElementById('incidents-body');
        tbody.textContent = '';

        if (incidents.length === 0) {
            var tr = document.createElement('tr');
            var td = document.createElement('td');
            td.colSpan = 6;
            td.className = 'empty-state';
            td.textContent = 'No active incidents';
            tr.appendChild(td);
            tbody.appendChild(tr);
            return;
        }

        incidents.forEach(function (inc) {
            var sev = (inc.severity || '').toLowerCase();
            var tr = document.createElement('tr');

            // Severity badge
            var tdSev = document.createElement('td');
            tdSev.insertAdjacentHTML('beforeend',
                '<span class="badge ' + severityClass(sev) + '">' + escapeHtml(inc.severity) + '</span>');
            tr.appendChild(tdSev);

            // PICERL status badge
            var tdStatus = document.createElement('td');
            tdStatus.insertAdjacentHTML('beforeend', statusBadgeMarkup(inc.status));
            tr.appendChild(tdStatus);

            // Title
            var tdTitle = document.createElement('td');
            tdTitle.style.color = 'var(--text-white)';
            tdTitle.textContent = inc.title || '';
            tr.appendChild(tdTitle);

            // CUI flag
            var tdCui = document.createElement('td');
            tdCui.className = inc.cui_involved ? 'flag-yes' : 'flag-no';
            tdCui.textContent = inc.cui_involved ? 'YES' : 'No';
            tr.appendChild(tdCui);

            // DFARS flag
            var tdDfars = document.createElement('td');
            tdDfars.className = inc.dfars_reportable ? 'flag-yes' : 'flag-no';
            tdDfars.textContent = inc.dfars_reportable ? 'YES' : 'No';
            tr.appendChild(tdDfars);

            // Elapsed
            var tdElapsed = document.createElement('td');
            tdElapsed.textContent = formatElapsed(inc.elapsed_hours);
            tr.appendChild(tdElapsed);

            tbody.appendChild(tr);
        });
    }

    // ---- Red Team Tab ----

    function fetchRedteam() {
        apiFetch('redteam.php').then(function (data) {
            renderRedteam(data);
        }).catch(function (err) {
            var el = document.getElementById('redteam-findings');
            el.textContent = '';
            var errDiv = document.createElement('div');
            errDiv.className = 'error-state';
            errDiv.textContent = 'Failed to load red team data';
            el.appendChild(errDiv);
            console.error('Red team fetch error:', err);
        });
    }

    function renderRedteam(data) {
        redteamCache = data;

        // Report meta
        if (data.generated) {
            setText('redteam-meta', 'Report generated: ' + formatDate(data.generated));
        }

        // Timing info
        var timingEl = document.getElementById('redteam-timing');
        if (timingEl && data.timing) {
            var t = data.timing;
            var durationSec = ((t.duration_ms || 0) / 1000).toFixed(1);
            timingEl.textContent = 'Run: ' + formatDate(t.start) + ' \u2014 ' + formatDate(t.end) + ' (' + durationSec + 's total)';
            timingEl.style.display = 'block';
        } else if (timingEl) {
            timingEl.style.display = 'none';
        }

        // Summary cards (safe: textContent)
        var totalVariants = data.total_variants || 1;
        var defendedPct = totalVariants > 0 ? Math.round((data.total_defended / totalVariants) * 100) : 0;
        setText('rt-total-attacks', data.total_attacks || 0);
        setText('rt-defended-pct', defendedPct + '%');
        setText('rt-vulnerable', data.total_vulnerable || 0);
        setText('rt-partial', data.total_partial || 0);
        setText('rt-errors', data.total_errors || 0);

        // Calculate per-category duration from findings
        var categoryKeys = Object.keys(data.by_category || {});
        var catDurations = {};
        (data.findings || []).forEach(function(f) {
            var cat = getCategoryFromAttack(f.attack, categoryKeys);
            if (cat) {
                catDurations[cat] = (catDurations[cat] || 0) + (f.duration_ms || 0);
            }
        });

        // Category breakdown table
        renderRedteamCategories(data.by_category || {}, catDurations);

        // Severity distribution bars
        renderSeverityDistribution(data.by_severity || {});

        // Findings list (apply active filter if set)
        renderRedteamFindings(data.findings || [], activeRtFilter);
    }

    function fetchScanHistory() {
        apiFetch('reports-list.php').then(function (data) {
            renderScanHistory(data);
        }).catch(function (err) {
            var body = document.getElementById('scan-history-body');
            if (body) body.innerHTML = '<tr><td colspan="8" class="empty-state">Failed to load scan history</td></tr>';
            console.error('Scan history fetch error:', err);
        });
    }

    function renderScanHistory(reports) {
        var body = document.getElementById('scan-history-body');
        if (!body || !Array.isArray(reports) || reports.length === 0) {
            if (body) body.innerHTML = '<tr><td colspan="8" class="empty-state">No historical reports found</td></tr>';
            return;
        }

        var html = '';
        reports.forEach(function (r, idx) {
            var rowClass = idx === 0 ? ' class="scan-history-current"' : '';
            var reportLink = r.has_html
                ? '<a href="api/report-view.php?t=' + escapeHtml(r.timestamp) + '" target="_blank" class="scan-history-link">View Report</a>'
                : '<span class="scan-history-no-report">JSON Only</span>';

            html += '<tr' + rowClass + '>'
                + '<td>' + escapeHtml(formatDate(r.generated)) + '</td>'
                + '<td>' + (r.total_attacks || 0) + '</td>'
                + '<td>' + (r.total_variants || 0) + '</td>'
                + '<td>' + (r.total_vulnerable || 0) + '</td>'
                + '<td>' + (r.total_partial || 0) + '</td>'
                + '<td>' + (r.total_defended || 0) + '</td>'
                + '<td>' + (r.total_errors || 0) + '</td>'
                + '<td>' + reportLink + '</td>'
                + '</tr>';
        });

        body.innerHTML = html;
    }

    function filterRedteamByStatus(status) {
        activeRtFilter = status;
        activeRtCategoryFilter = null;
        activeRtSeverityFilter = null;

        document.querySelectorAll('#redteam-summary .summary-card').forEach(function (card) {
            card.classList.toggle('active-filter', card.getAttribute('data-rt-filter') === status);
        });

        updateRtFilterBanner();
        renderRedteamFindings(redteamCache.findings || [], status);
        document.getElementById('redteam-findings').scrollIntoView({ behavior: 'smooth', block: 'start' });
    }

    function clearRtFilter() {
        activeRtFilter = null;
        activeRtCategoryFilter = null;
        activeRtSeverityFilter = null;
        document.querySelectorAll('#redteam-summary .summary-card').forEach(function (card) {
            card.classList.remove('active-filter');
        });
        document.getElementById('rt-filter-banner').style.display = 'none';
        if (redteamCache) {
            renderRedteamFindings(redteamCache.findings || [], null);
        }
    }

    function filterByCategory(category) {
        activeRtCategoryFilter = category;
        activeRtSeverityFilter = null;
        activeRtFilter = null;
        document.querySelectorAll('#redteam-summary .summary-card').forEach(function(card) {
            card.classList.remove('active-filter');
        });
        updateRtFilterBanner();
        renderRedteamFindings(redteamCache.findings || [], null);
        document.getElementById('redteam-findings').scrollIntoView({ behavior: 'smooth', block: 'start' });
    }

    function filterByCategoryAndStatus(category, status) {
        activeRtCategoryFilter = category;
        activeRtSeverityFilter = null;
        activeRtFilter = status;
        document.querySelectorAll('#redteam-summary .summary-card').forEach(function(card) {
            card.classList.toggle('active-filter', card.getAttribute('data-rt-filter') === status);
        });
        updateRtFilterBanner();
        renderRedteamFindings(redteamCache.findings || [], status);
        document.getElementById('redteam-findings').scrollIntoView({ behavior: 'smooth', block: 'start' });
    }

    function filterBySeverity(severity) {
        activeRtSeverityFilter = severity;
        activeRtCategoryFilter = null;
        activeRtFilter = null;
        document.querySelectorAll('#redteam-summary .summary-card').forEach(function(card) {
            card.classList.remove('active-filter');
        });
        updateRtFilterBanner();
        renderRedteamFindings(redteamCache.findings || [], null);
        document.getElementById('redteam-findings').scrollIntoView({ behavior: 'smooth', block: 'start' });
    }

    function updateRtFilterBanner() {
        var banner = document.getElementById('rt-filter-banner');
        var bannerText = document.getElementById('rt-filter-banner-text');
        var parts = [];
        if (activeRtFilter) parts.push(activeRtFilter.charAt(0).toUpperCase() + activeRtFilter.slice(1));
        if (activeRtCategoryFilter) parts.push(activeRtCategoryFilter.toUpperCase() + ' category');
        if (activeRtSeverityFilter) parts.push(activeRtSeverityFilter.charAt(0).toUpperCase() + activeRtSeverityFilter.slice(1) + ' severity');

        if (parts.length === 0) {
            banner.style.display = 'none';
            return;
        }

        // Count filtered results
        var findings = redteamCache.findings || [];
        var categoryKeys = Object.keys(redteamCache.by_category || {});
        var count = findings.filter(function(f) {
            if (activeRtFilter && f.status !== activeRtFilter) return false;
            if (activeRtCategoryFilter && getCategoryFromAttack(f.attack, categoryKeys) !== activeRtCategoryFilter) return false;
            if (activeRtSeverityFilter && (f.severity || 'info').toLowerCase() !== activeRtSeverityFilter) return false;
            return true;
        }).length;

        banner.style.display = 'flex';
        bannerText.textContent = 'Showing ' + parts.join(' + ') + ' findings (' + count + ' results)';
    }

    function renderRedteamCategories(cats, catDurations) {
        var catBody = document.getElementById('redteam-categories-body');
        catBody.textContent = '';
        var catKeys = Object.keys(cats);

        if (catKeys.length === 0) {
            var tr = document.createElement('tr');
            var td = document.createElement('td');
            td.colSpan = 8;
            td.className = 'empty-state';
            td.textContent = 'No category data';
            tr.appendChild(td);
            catBody.appendChild(tr);
            return;
        }

        catKeys.forEach(function (key) {
            var c = cats[key];
            var catTotal = (c.vulnerable || 0) + (c.partial || 0) + (c.defended || 0) + (c.errors || 0);
            var defRate = catTotal > 0 ? Math.round(((c.defended || 0) / catTotal) * 100) : 0;

            var tr = document.createElement('tr');

            var tdCat = document.createElement('td');
            tdCat.style.color = 'var(--primary-cyan)';
            tdCat.style.textTransform = 'uppercase';
            tdCat.style.letterSpacing = '1px';
            tdCat.textContent = key;
            tdCat.style.cursor = 'pointer';
            tdCat.title = 'Filter findings by ' + key;
            tdCat.classList.add('clickable-cell');
            tdCat.addEventListener('click', (function(category) {
                return function() { filterByCategory(category); };
            })(key));
            tr.appendChild(tdCat);

            var tdAttacks = document.createElement('td');
            tdAttacks.textContent = c.attacks || 0;
            if ((c.attacks || 0) > 0) {
                tdAttacks.style.cursor = 'pointer';
                tdAttacks.title = 'Filter findings by ' + key;
                tdAttacks.classList.add('clickable-cell');
                tdAttacks.addEventListener('click', (function(category) {
                    return function() { filterByCategory(category); };
                })(key));
            }
            tr.appendChild(tdAttacks);

            var tdVuln = document.createElement('td');
            tdVuln.style.color = 'var(--severity-critical)';
            tdVuln.textContent = c.vulnerable || 0;
            if ((c.vulnerable || 0) > 0) {
                tdVuln.style.cursor = 'pointer';
                tdVuln.title = 'Show vulnerable findings in ' + key;
                tdVuln.classList.add('clickable-cell');
                tdVuln.addEventListener('click', (function(cat) {
                    return function() { filterByCategoryAndStatus(cat, 'vulnerable'); };
                })(key));
            }
            tr.appendChild(tdVuln);

            var tdPartial = document.createElement('td');
            tdPartial.style.color = 'var(--warning-yellow)';
            tdPartial.textContent = c.partial || 0;
            if ((c.partial || 0) > 0) {
                tdPartial.style.cursor = 'pointer';
                tdPartial.title = 'Show partial findings in ' + key;
                tdPartial.classList.add('clickable-cell');
                tdPartial.addEventListener('click', (function(cat) {
                    return function() { filterByCategoryAndStatus(cat, 'partial'); };
                })(key));
            }
            tr.appendChild(tdPartial);

            var tdDef = document.createElement('td');
            tdDef.style.color = 'var(--success-green)';
            tdDef.textContent = c.defended || 0;
            if ((c.defended || 0) > 0) {
                tdDef.style.cursor = 'pointer';
                tdDef.title = 'Show defended findings in ' + key;
                tdDef.classList.add('clickable-cell');
                tdDef.addEventListener('click', (function(cat) {
                    return function() { filterByCategoryAndStatus(cat, 'defended'); };
                })(key));
            }
            tr.appendChild(tdDef);

            var tdErr = document.createElement('td');
            tdErr.textContent = c.errors || 0;
            if ((c.errors || 0) > 0) {
                tdErr.style.cursor = 'pointer';
                tdErr.title = 'Show error findings in ' + key;
                tdErr.classList.add('clickable-cell');
                tdErr.addEventListener('click', (function(cat) {
                    return function() { filterByCategoryAndStatus(cat, 'error'); };
                })(key));
            }
            tr.appendChild(tdErr);

            // Duration
            var tdDur = document.createElement('td');
            tdDur.style.color = 'var(--primary-cyan)';
            var durMs = catDurations && catDurations[key] || 0;
            var durSec = durMs / 1000;
            if (durSec >= 3600) {
                tdDur.textContent = (durSec / 3600).toFixed(1) + 'h';
            } else if (durSec >= 60) {
                tdDur.textContent = (durSec / 60).toFixed(1) + 'm';
            } else {
                tdDur.textContent = durSec.toFixed(1) + 's';
            }
            tr.appendChild(tdDur);

            // Defense rate bar
            var tdRate = document.createElement('td');
            var barContainer = document.createElement('div');
            barContainer.style.display = 'flex';
            barContainer.style.alignItems = 'center';
            barContainer.style.gap = '8px';

            var bar = document.createElement('div');
            bar.className = 'defense-rate-bar';
            var barFill = document.createElement('div');
            barFill.className = 'defense-rate-fill';
            barFill.style.width = defRate + '%';
            bar.appendChild(barFill);
            barContainer.appendChild(bar);

            var rateLabel = document.createElement('span');
            rateLabel.style.fontSize = '0.75em';
            rateLabel.style.color = 'var(--text-secondary)';
            rateLabel.textContent = defRate + '%';
            barContainer.appendChild(rateLabel);

            tdRate.appendChild(barContainer);
            tr.appendChild(tdRate);

            catBody.appendChild(tr);
        });
    }

    function renderSeverityDistribution(sev) {
        var container = document.getElementById('redteam-severity');
        container.textContent = '';

        // Handle both flat (count) and nested ({vulnerable:N, partial:N, ...}) formats
        function getCount(val) {
            if (typeof val === 'number') return val;
            if (val && typeof val === 'object') {
                return (val.vulnerable || 0) + (val.partial || 0) + (val.defended || 0) + (val.error || 0);
            }
            return 0;
        }

        var counts = {};
        ['critical', 'high', 'medium', 'low', 'info'].forEach(function(s) {
            counts[s] = getCount(sev[s]);
        });

        var maxSev = Math.max(counts.critical, counts.high, counts.medium, counts.low, counts.info, 1);

        ['critical', 'high', 'medium', 'low', 'info'].forEach(function (s) {
            var count = counts[s];
            var pct = Math.round((count / maxSev) * 100);

            var row = document.createElement('div');
            row.className = 'severity-bar-row';
            row.style.cursor = 'pointer';
            row.title = 'Filter findings by ' + s + ' severity';

            // Click handler
            row.addEventListener('click', (function(severity) {
                return function() { filterBySeverity(severity); };
            })(s));

            var label = document.createElement('span');
            label.className = 'severity-bar-label';
            label.textContent = s;
            row.appendChild(label);

            var track = document.createElement('div');
            track.className = 'severity-bar-track';
            var fill = document.createElement('div');
            fill.className = 'severity-bar-fill severity-bar-fill-' + s;
            fill.style.width = pct + '%';
            track.appendChild(fill);
            row.appendChild(track);

            var countEl = document.createElement('span');
            countEl.className = 'severity-bar-count';
            countEl.textContent = count;
            row.appendChild(countEl);

            container.appendChild(row);
        });
    }

    /** Render a labeled block (label + monospace content) */
    function renderDetailBlock(parent, label, content, cls) {
        if (!content) return;
        var block = document.createElement('div');
        block.className = 'chat-msg ' + (cls || '');
        var lbl = document.createElement('div');
        lbl.className = 'chat-msg-label';
        lbl.textContent = label;
        block.appendChild(lbl);
        var txt = document.createElement('div');
        txt.className = 'chat-msg-text';
        txt.textContent = String(content).trim();
        block.appendChild(txt);
        parent.appendChild(block);
    }

    /** Format a request/response object as readable key-value lines, skipping noisy keys */
    function formatObjReadable(obj, skipKeys) {
        if (!obj || typeof obj !== 'object') return String(obj || '');
        var skip = skipKeys || {};
        var lines = [];
        Object.keys(obj).forEach(function (k) {
            if (skip[k]) return;
            var v = obj[k];
            if (v === null || v === undefined || v === '') return;
            if (Array.isArray(v)) {
                if (v.length === 0) return;
                lines.push(k + ': ' + (typeof v[0] === 'object' ? JSON.stringify(v, null, 2) : v.join(', ')));
            } else if (typeof v === 'object') {
                lines.push(k + ': ' + JSON.stringify(v, null, 2));
            } else {
                lines.push(k + ': ' + String(v));
            }
        });
        return lines.join('\n');
    }

    function renderRedteamFindings(findings, statusFilter) {
        var container = document.getElementById('redteam-findings');
        container.textContent = '';

        var categoryKeys = Object.keys(redteamCache && redteamCache.by_category || {});
        var filtered = findings;
        if (statusFilter) {
            filtered = filtered.filter(function (f) { return f.status === statusFilter; });
        }
        if (activeRtCategoryFilter) {
            var catFilter = activeRtCategoryFilter;
            filtered = filtered.filter(function (f) {
                return getCategoryFromAttack(f.attack, categoryKeys) === catFilter;
            });
        }
        if (activeRtSeverityFilter) {
            var sevFilter = activeRtSeverityFilter;
            filtered = filtered.filter(function (f) {
                return (f.severity || 'info').toLowerCase() === sevFilter;
            });
        }

        if (filtered.length === 0) {
            var empty = document.createElement('div');
            empty.className = 'empty-state';
            var parts = [];
            if (statusFilter) parts.push(statusFilter);
            if (activeRtCategoryFilter) parts.push(activeRtCategoryFilter);
            if (activeRtSeverityFilter) parts.push(activeRtSeverityFilter + ' severity');
            empty.textContent = parts.length > 0 ? 'No findings matching: ' + parts.join(' + ') : 'No findings in latest report';
            container.appendChild(empty);
            return;
        }

        filtered.forEach(function (f) {
            var statusCls = 'finding-card-' + (f.status || 'error');
            var isAI = (f.attack || '').indexOf('ai.') === 0;

            var card = document.createElement('div');
            card.className = 'finding-card ' + statusCls;

            // Header row
            var header = document.createElement('div');
            header.className = 'finding-header';

            var attack = document.createElement('span');
            attack.className = 'finding-attack';
            attack.textContent = (f.attack || '') + ' / ' + (f.variant || '');
            header.appendChild(attack);

            var badges = document.createElement('div');
            badges.className = 'finding-badges';
            badges.insertAdjacentHTML('beforeend',
                '<span class="badge ' + severityClass(f.severity) + '">' + escapeHtml(f.severity) + '</span>');
            badges.insertAdjacentHTML('beforeend',
                '<span class="badge badge-' + escapeHtml(f.status || '') + '">' + escapeHtml(f.status) + '</span>');
            header.appendChild(badges);

            card.appendChild(header);

            // Details text
            if (f.details) {
                var details = document.createElement('div');
                details.className = 'finding-details';
                details.textContent = f.details;
                card.appendChild(details);
            }

            // Leaked fragments warning
            var leaked = f.response && f.response.leaked_fragments;
            if (leaked && leaked.length > 0) {
                var leakDiv = document.createElement('div');
                leakDiv.className = 'leaked-fragments';
                var leakLabel = document.createElement('span');
                leakLabel.className = 'leaked-label';
                leakLabel.textContent = 'LEAKED: ';
                leakDiv.appendChild(leakLabel);
                leaked.forEach(function (frag) {
                    var tag = document.createElement('span');
                    tag.className = 'leaked-tag';
                    tag.textContent = frag;
                    leakDiv.appendChild(tag);
                });
                card.appendChild(leakDiv);
            }

            // Expandable evidence section
            var evidence = document.createElement('div');
            evidence.className = 'finding-evidence';

            var req = f.request || {};
            var resp = f.response || {};

            if (isAI && resp.conversation && Array.isArray(resp.conversation)) {
                // Multi-turn AI conversation
                var chatLog = document.createElement('div');
                chatLog.className = 'chat-log';
                resp.conversation.forEach(function (turn) {
                    renderDetailBlock(chatLog, 'TURN ' + turn.turn + ' — ATTACKER', turn.user, 'chat-msg-attacker');
                    renderDetailBlock(chatLog, 'TURN ' + turn.turn + ' — AI RESPONSE', turn.assistant || turn.error, 'chat-msg-ai');
                });
                evidence.appendChild(chatLog);
            } else if (isAI && req.message) {
                // Single-turn AI
                var chatLog = document.createElement('div');
                chatLog.className = 'chat-log';
                renderDetailBlock(chatLog, 'ATTACKER PROMPT', req.message, 'chat-msg-attacker');
                var respLabel = 'AI RESPONSE' + (resp.model ? ' (' + escapeHtml(resp.model) + ')' : '');
                renderDetailBlock(chatLog, respLabel, resp.text, 'chat-msg-ai');
                evidence.appendChild(chatLog);
            } else {
                // API / Web / other findings — structured request & response
                var reproLog = document.createElement('div');
                reproLog.className = 'chat-log';

                // Request details
                var reqSkip = { session_id: 1 };
                var reqText = formatObjReadable(req, reqSkip);
                if (reqText) {
                    renderDetailBlock(reproLog, 'REQUEST', reqText, 'chat-msg-attacker');
                }

                // Response details
                var respSkip = { leaked_fragments: 1 };
                var respText = formatObjReadable(resp, respSkip);
                if (respText) {
                    renderDetailBlock(reproLog, 'RESPONSE', respText, 'chat-msg-ai');
                }

                // Evidence text if different from response
                if (f.evidence && !resp.text) {
                    renderDetailBlock(reproLog, 'EVIDENCE', f.evidence, '');
                }

                evidence.appendChild(reproLog);
            }

            // Metadata footer
            var meta = document.createElement('div');
            meta.className = 'chat-meta';
            var metaParts = [];
            if (req.session_id) metaParts.push('Session: ' + req.session_id);
            if (resp.model) metaParts.push('Model: ' + resp.model);
            if (f.duration_ms) metaParts.push('Duration: ' + Math.round(f.duration_ms) + 'ms');
            if (metaParts.length > 0) {
                meta.textContent = metaParts.join(' | ');
                evidence.appendChild(meta);
            }

            card.appendChild(evidence);

            // Click to toggle evidence
            card.addEventListener('click', function () {
                evidence.classList.toggle('visible');
            });

            container.appendChild(card);
        });
    }

    // ---- Malware Tab ----

    function loadMalwareData() {
        if (tabDataLoaded['malware']) return;
        tabDataLoaded['malware'] = true;

        apiFetch('malware.php').then(function (data) {
            malwareDataCache = data;

            // Update posture score card
            var malwareScoreEl = document.getElementById('score-malware');
            if (malwareScoreEl) {
                malwareScoreEl.textContent = Math.round(data.malware_score || 0);
                malwareScoreEl.className = 'score-card-value ' + scoreColorClass(data.malware_score || 0);
            }

            // Update malware tab summary cards
            document.getElementById('malware-score-display').textContent = Math.round(data.malware_score || 0);

            var totalThreats = (data.severity_counts?.critical || 0) +
                              (data.severity_counts?.high || 0) +
                              (data.severity_counts?.medium || 0) +
                              (data.severity_counts?.low || 0);
            document.getElementById('active-threats').textContent = totalThreats;

            // Update active threats card styling
            var threatsCard = document.getElementById('active-threats-card');
            if (threatsCard) {
                if (totalThreats === 0) {
                    threatsCard.className = 'summary-card summary-card-clickable';
                } else {
                    threatsCard.className = 'summary-card summary-card-clickable summary-card-danger';
                }
            }

            // Calculate scans and files scanned in the last 24 hours (rolling window)
            var scansToday = 0;
            var filesScanned24h = 0;
            var cutoff24h = new Date(Date.now() - 24 * 60 * 60 * 1000);

            if (data.recent_scans && Array.isArray(data.recent_scans)) {
                data.recent_scans.forEach(function(scan) {
                    var scanDate = new Date(scan.scan_date);
                    if (scanDate >= cutoff24h) {
                        scansToday++;
                        filesScanned24h += scan.files_scanned || 0;
                    }
                });
            }

            document.getElementById('total-scans-today').textContent = scansToday;
            document.getElementById('files-scanned-24h').textContent = filesScanned24h.toLocaleString();

            // Render scan results grid
            renderScanResults(data.latest_scans || []);

            // Render active detections table
            renderDetectionsTable(data.active_detections || [], data.severity_counts || {});

            // Render scanner status
            renderScannerStatus(data.latest_scans || [], data.last_scan_days || {});

        }).catch(function (err) {
            console.error('Failed to load malware data:', err);
            document.getElementById('scan-results-grid').innerHTML = '<div class="empty-state error">Failed to load malware data</div>';
        });
    }

    function renderScanResults(scans) {
        var grid = document.getElementById('scan-results-grid');
        if (!scans || scans.length === 0) {
            grid.innerHTML = '<div class="empty-state">No scan results available</div>';
            return;
        }

        var html = scans.map(function(scan) {
            var scanType = escapeHtml(scan.scan_type || 'unknown');
            var status = scan.status || 'unknown';
            var filesScanned = (scan.files_scanned || 0).toLocaleString();
            var infections = scan.infections_found || 0;
            var duration = scan.scan_duration_seconds || 0;
            var scanDate = formatDate(scan.scan_date);

            var durationMin = Math.floor(duration / 60);
            var durationSec = duration % 60;
            var durationStr = durationMin > 0 ? durationMin + 'm ' + durationSec + 's' : durationSec + 's';

            return '<div class="scan-result-card scan-' + escapeHtml(status) + '">' +
                '<div class="scan-header">' +
                    '<span class="scan-type">' + scanType.toUpperCase() + '</span>' +
                    '<span class="scan-status status-' + escapeHtml(status) + '">' + escapeHtml(status) + '</span>' +
                '</div>' +
                '<div class="scan-metrics">' +
                    '<div class="metric">' +
                        '<span class="metric-value">' + filesScanned + '</span>' +
                        '<span class="metric-label">Files Scanned</span>' +
                    '</div>' +
                    '<div class="metric">' +
                        '<span class="metric-value">' + infections + '</span>' +
                        '<span class="metric-label">Infections</span>' +
                    '</div>' +
                    '<div class="metric">' +
                        '<span class="metric-value">' + durationStr + '</span>' +
                        '<span class="metric-label">Duration</span>' +
                    '</div>' +
                    '<div class="metric">' +
                        '<span class="metric-value">' + scanDate + '</span>' +
                        '<span class="metric-label">Last Scan</span>' +
                    '</div>' +
                '</div>' +
            '</div>';
        }).join('');

        grid.innerHTML = html;
    }

    function renderDetectionsTable(detections, severityCounts) {
        var tbody = document.getElementById('detections-tbody');
        var countBadge = document.getElementById('detections-count');

        var totalDetections = detections.length;
        countBadge.textContent = totalDetections;
        countBadge.className = totalDetections === 0 ? 'count-badge count-zero' : 'count-badge';

        if (!detections || detections.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" class="empty-state">No active detections - All clear!</td></tr>';
            return;
        }

        var html = detections.map(function(det) {
            var severity = det.severity || 'low';
            var filePath = escapeHtml(det.file_path || 'Unknown');
            var signature = escapeHtml(det.malware_signature || 'Unknown');
            var detected = formatDate(det.detected_at);
            var scanner = escapeHtml((det.scan_type || 'unknown').toUpperCase());
            var action = escapeHtml(det.action_taken || 'reported');

            return '<tr>' +
                '<td><span class="badge ' + severityClass(severity) + '">' + escapeHtml(severity) + '</span></td>' +
                '<td><code class="file-path">' + filePath + '</code></td>' +
                '<td>' + signature + '</td>' +
                '<td>' + detected + '</td>' +
                '<td>' + scanner + '</td>' +
                '<td>' + action + '</td>' +
            '</tr>';
        }).join('');

        tbody.innerHTML = html;
    }

    // ---- Malware Score Modal ----

    var malwareDataCache = null;

    function openScoreModal() {
        document.getElementById('malware-score-modal').style.display = 'flex';
        if (malwareDataCache) {
            renderScoreModal(malwareDataCache);
        }
    }

    function closeScoreModal() {
        document.getElementById('malware-score-modal').style.display = 'none';
    }

    // typo-safe alias (onclick in HTML has a typo closeScorekModal)
    window.closeScorekModal = function(event) {
        if (event.target === document.getElementById('malware-score-modal')) {
            closeScoreModal();
        }
    };
    window.closeScoreModal = closeScoreModal;
    window.openScoreModal = openScoreModal;

    function scrollToDetections() {
        var el = document.getElementById('active-detections-card');
        if (el) {
            el.scrollIntoView({ behavior: 'smooth', block: 'start' });
            el.classList.add('card-highlight');
            setTimeout(function() { el.classList.remove('card-highlight'); }, 1800);
        }
    }
    window.scrollToDetections = scrollToDetections;

    function renderScoreModal(data) {
        var body = document.getElementById('score-modal-body');
        var score = Math.round(data.malware_score || 0);
        var sc = data.severity_counts || {};
        var critical = sc.critical || 0;
        var high = sc.high || 0;
        var medium = sc.medium || 0;
        var low = sc.low || 0;

        // Deductions per the DB formula: critical*30 + high*20 + medium*10 + low*5
        var deductCritical = critical * 30;
        var deductHigh = high * 20;
        var deductMedium = medium * 10;
        var deductLow = low * 5;
        var totalDeduction = deductCritical + deductHigh + deductMedium + deductLow;

        function deductRow(label, count, each, total, cls) {
            var row = count === 0
                ? '<span class="score-factor-zero">0 detections &mdash; no penalty</span>'
                : '<span class="score-factor-bad">' + count + ' &times; ' + each + ' pts = &minus;' + total + '</span>';
            return '<tr class="' + (count > 0 ? 'factor-active' : 'factor-clear') + '">' +
                '<td><span class="badge ' + cls + '">' + label + '</span></td>' +
                '<td>' + row + '</td>' +
                '<td class="factor-action">' + (count > 0 ? 'Remediate ' + count + ' detection' + (count > 1 ? 's' : '') : '&#10003;') + '</td>' +
                '</tr>';
        }

        var html = '<div class="score-formula-summary">' +
            '<div class="score-formula-result ' + scoreColorClass(score) + '">' + score + '<span class="score-formula-denom">/100</span></div>' +
            '<div class="score-formula-label">Current Score</div>' +
            '</div>' +

            '<p class="score-formula-desc">Score starts at <strong>100</strong> and deductions are applied for each unresolved malware detection, weighted by severity:</p>' +

            '<table class="score-factors-table">' +
            '<thead><tr><th>Severity</th><th>Calculation</th><th>Action to Recover Points</th></tr></thead>' +
            '<tbody>' +
            deductRow('CRITICAL', critical, 30, deductCritical, 'badge-critical') +
            deductRow('HIGH', high, 20, deductHigh, 'badge-high') +
            deductRow('MEDIUM', medium, 10, deductMedium, 'badge-medium') +
            deductRow('LOW', low, 5, deductLow, 'badge-low') +
            '</tbody>' +
            '<tfoot><tr>' +
            '<td colspan="2"><strong>Total deduction: &minus;' + totalDeduction + ' pts</strong></td>' +
            '<td><strong>Score: 100 &minus; ' + totalDeduction + ' = ' + score + '</strong></td>' +
            '</tr></tfoot>' +
            '</table>' +

            '<div class="score-improve-section">' +
            '<h4>How to improve this score</h4>' +
            '<ul class="score-improve-list">' +
            '<li>Resolve active detections shown in the <a href="#" onclick="closeScoreModal(); scrollToDetections(); return false;">Active Detections</a> table below.</li>' +
            '<li>Each resolved Critical detection recovers 30 points.</li>' +
            '<li>Each resolved High detection recovers 20 points.</li>' +
            '<li>Each resolved Medium detection recovers 10 points.</li>' +
            '<li>Each resolved Low detection recovers 5 points.</li>' +
            '<li>A score of 100 means no unresolved detections across all scanners.</li>' +
            '</ul>' +
            '</div>';

        body.innerHTML = html;
    }

    function renderScannerStatus(latestScans, lastScanDays) {
        var grid = document.getElementById('scanner-status-grid');
        var scanners = ['clamav', 'maldet', 'rkhunter', 'chkrootkit'];

        var html = scanners.map(function(scanner) {
            var scan = latestScans.find(function(s) { return s.scan_type === scanner; });
            var daysSince = lastScanDays[scanner];
            var statusClass = 'scanner-status-card';
            var statusText = 'Never run';

            if (daysSince != null) {
                if (daysSince < 1) {
                    statusClass += ' status-active';
                    statusText = 'Active (< 1 day)';
                } else if (daysSince < 7) {
                    statusClass += ' status-active';
                    statusText = daysSince.toFixed(1) + ' days ago';
                } else {
                    statusClass += ' status-stale';
                    statusText = daysSince.toFixed(0) + ' days ago (stale)';
                }
            }

            return '<div class="' + statusClass + '">' +
                '<div class="scanner-name">' + escapeHtml(scanner).toUpperCase() + '</div>' +
                '<div class="last-scan">Last scan: <span class="last-scan-value">' + statusText + '</span></div>' +
            '</div>';
        }).join('');

        grid.innerHTML = html;
    }

    // ---- Schedule Management ----

    var schedulesCache = null;

    function apiWrite(endpoint, method, data) {
        return fetch(API_BASE + '/' + endpoint, {
            method: method,
            credentials: 'same-origin',
            headers: {
                'Content-Type': 'application/json',
                'X-Auth-User-Id': String(AUTH.userId),
                'X-Auth-Super': AUTH.isSuper ? 'true' : 'false'
            },
            body: JSON.stringify(data)
        }).then(function (res) {
            return res.json().then(function (json) {
                if (!res.ok) throw new Error(json.error || 'HTTP ' + res.status);
                return json;
            });
        });
    }

    function fetchSchedules() {
        apiFetch('schedules.php').then(function (data) {
            schedulesCache = data.schedules || [];
            renderSchedules(schedulesCache);
        }).catch(function (err) {
            var tbody = document.getElementById('schedule-body');
            if (tbody) {
                tbody.textContent = '';
                var tr = document.createElement('tr');
                var td = document.createElement('td');
                td.colSpan = 6;
                td.className = 'empty-state';
                td.textContent = 'Failed to load schedules';
                tr.appendChild(td);
                tbody.appendChild(tr);
            }
            console.error('Schedules fetch error:', err);
        });
    }

    function renderSchedules(schedules) {
        var tbody = document.getElementById('schedule-body');
        if (!tbody) return;
        tbody.textContent = '';

        var isSuper = typeof AUTH !== 'undefined' && AUTH.isSuper;
        var colSpan = isSuper ? 6 : 5;

        if (!schedules || schedules.length === 0) {
            var tr = document.createElement('tr');
            var td = document.createElement('td');
            td.colSpan = colSpan;
            td.className = 'empty-state';
            td.textContent = 'No schedules configured';
            tr.appendChild(td);
            tbody.appendChild(tr);
            return;
        }

        schedules.forEach(function (s) {
            var tr = document.createElement('tr');

            // Status dot
            var tdStatus = document.createElement('td');
            var dot = document.createElement('span');
            dot.className = 'schedule-status-dot ' + (s.enabled ? 'dot-active' : 'dot-inactive');
            dot.title = s.enabled ? 'Enabled' : 'Disabled';
            tdStatus.appendChild(dot);
            tr.appendChild(tdStatus);

            // Name
            var tdName = document.createElement('td');
            tdName.style.color = 'var(--text-white)';
            tdName.textContent = s.name;
            tr.appendChild(tdName);

            // Schedule (human-readable)
            var tdSched = document.createElement('td');
            tdSched.textContent = s.human_cron || s.cron_expr;
            tdSched.title = s.cron_expr;
            tr.appendChild(tdSched);

            // Category
            var tdCat = document.createElement('td');
            tdCat.style.textTransform = 'uppercase';
            tdCat.style.letterSpacing = '1px';
            tdCat.style.color = 'var(--primary-cyan)';
            tdCat.textContent = s.category;
            tr.appendChild(tdCat);

            // Next Run
            var tdNext = document.createElement('td');
            tdNext.textContent = s.enabled ? formatDate(s.next_run_at) : '--';
            tdNext.style.color = 'var(--text-secondary)';
            tr.appendChild(tdNext);

            // Actions (super admin only)
            if (isSuper) {
                var tdActions = document.createElement('td');
                tdActions.className = 'schedule-actions';

                // Toggle button
                var toggleBtn = document.createElement('button');
                toggleBtn.className = 'schedule-action-btn ' + (s.enabled ? 'btn-disable' : 'btn-enable');
                toggleBtn.textContent = s.enabled ? 'Disable' : 'Enable';
                toggleBtn.onclick = (function (id, enabled) {
                    return function (e) {
                        e.stopPropagation();
                        toggleSchedule(id, !enabled);
                    };
                })(s.schedule_id, s.enabled);
                tdActions.appendChild(toggleBtn);

                // Edit button
                var editBtn = document.createElement('button');
                editBtn.className = 'schedule-action-btn btn-edit';
                editBtn.textContent = 'Edit';
                editBtn.onclick = (function (sched) {
                    return function (e) {
                        e.stopPropagation();
                        openScheduleModal(sched);
                    };
                })(s);
                tdActions.appendChild(editBtn);

                // Delete button
                var delBtn = document.createElement('button');
                delBtn.className = 'schedule-action-btn btn-delete';
                delBtn.textContent = 'Del';
                delBtn.onclick = (function (id, name) {
                    return function (e) {
                        e.stopPropagation();
                        deleteSchedule(id, name);
                    };
                })(s.schedule_id, s.name);
                tdActions.appendChild(delBtn);

                tr.appendChild(tdActions);
            }

            tbody.appendChild(tr);
        });
    }

    // Expose modal functions to global scope for onclick handlers in PHP-rendered HTML
    window.openScheduleModal = function (schedule) {
        var modal = document.getElementById('schedule-modal');
        if (!modal) return;
        modal.style.display = 'flex';

        var form = document.getElementById('schedule-form');
        if (form) form.reset();

        if (schedule) {
            document.getElementById('schedule-modal-title').textContent = 'Edit Schedule';
            document.getElementById('sched-id').value = schedule.schedule_id;
            document.getElementById('sched-name').value = schedule.name;
            document.getElementById('sched-category').value = schedule.category;
            document.getElementById('sched-cron').value = schedule.cron_expr;
            document.getElementById('sched-args').value = schedule.extra_args || '';
            document.getElementById('sched-enabled').checked = schedule.enabled;
            // Match preset if applicable
            var presetSelect = document.getElementById('sched-preset');
            presetSelect.value = '';
            for (var i = 0; i < presetSelect.options.length; i++) {
                if (presetSelect.options[i].value === schedule.cron_expr) {
                    presetSelect.value = schedule.cron_expr;
                    break;
                }
            }
        } else {
            document.getElementById('schedule-modal-title').textContent = 'Add Schedule';
            document.getElementById('sched-id').value = '';
            document.getElementById('sched-enabled').checked = true;
        }
        updateCronPreview();
    };

    window.closeScheduleModal = function () {
        var modal = document.getElementById('schedule-modal');
        if (modal) modal.style.display = 'none';
    };

    window.saveSchedule = function (e) {
        e.preventDefault();
        var id = document.getElementById('sched-id').value;
        var data = {
            name: document.getElementById('sched-name').value,
            cron_expr: document.getElementById('sched-cron').value,
            category: document.getElementById('sched-category').value,
            extra_args: document.getElementById('sched-args').value,
            enabled: document.getElementById('sched-enabled').checked
        };

        if (id) {
            data.schedule_id = parseInt(id, 10);
            apiWrite('schedules.php', 'PUT', data).then(function () {
                closeScheduleModal();
                fetchSchedules();
            }).catch(function (err) {
                alert('Failed to update schedule: ' + err.message);
            });
        } else {
            apiWrite('schedules.php', 'POST', data).then(function () {
                closeScheduleModal();
                fetchSchedules();
            }).catch(function (err) {
                alert('Failed to create schedule: ' + err.message);
            });
        }
    };

    function deleteSchedule(id, name) {
        if (!confirm('Delete schedule "' + name + '"? This will remove it from the crontab.')) return;
        apiWrite('schedules.php', 'DELETE', { schedule_id: id }).then(function () {
            fetchSchedules();
        }).catch(function (err) {
            alert('Failed to delete schedule: ' + err.message);
        });
    }

    function toggleSchedule(id, enabled) {
        apiWrite('schedules.php', 'PUT', { schedule_id: id, enabled: enabled }).then(function () {
            fetchSchedules();
        }).catch(function (err) {
            alert('Failed to toggle schedule: ' + err.message);
        });
    }

    window.applyPreset = function (value) {
        if (value) {
            document.getElementById('sched-cron').value = value;
            updateCronPreview();
        }
    };

    window.updateCronPreview = function () {
        var expr = (document.getElementById('sched-cron').value || '').trim();
        var preview = document.getElementById('cron-preview');
        if (!preview) return;
        if (!expr) {
            preview.textContent = '--';
            return;
        }
        preview.textContent = cronToHumanJS(expr);
    };

    function cronToHumanJS(expr) {
        var map = {
            '0 2 * * 0':    'Every Sunday at 2:00 AM',
            '0 3 * * *':    'Every day at 3:00 AM',
            '0 0 * * *':    'Every day at midnight',
            '0 * * * *':    'Every hour',
            '*/5 * * * *':  'Every 5 minutes',
            '*/15 * * * *': 'Every 15 minutes',
            '*/30 * * * *': 'Every 30 minutes',
            '0 0 * * 0':    'Every Sunday at midnight',
            '0 0 * * 1':    'Every Monday at midnight',
            '0 0 1 * *':    'First of every month at midnight',
            '0 6 * * 1-5':  'Weekdays at 6:00 AM',
            '0 */6 * * *':  'Every 6 hours'
        };
        if (map[expr]) return map[expr];

        var parts = expr.split(/\s+/);
        if (parts.length !== 5) return expr;

        var min = parts[0], hour = parts[1], dom = parts[2], mon = parts[3], dow = parts[4];
        var dayNames = ['Sunday','Monday','Tuesday','Wednesday','Thursday','Friday','Saturday'];
        var result = '';

        if (dow !== '*') {
            var d = parseInt(dow, 10);
            if (!isNaN(d) && dayNames[d]) {
                result += 'Every ' + dayNames[d];
            } else {
                result += 'DOW ' + dow;
            }
        } else if (dom !== '*') {
            result += 'Day ' + dom + ' of month';
        } else {
            result += 'Every day';
        }

        var h = parseInt(hour, 10);
        var m = parseInt(min, 10);
        if (!isNaN(h) && !isNaN(m)) {
            var ampm = h >= 12 ? 'PM' : 'AM';
            var h12 = h % 12 || 12;
            result += ' at ' + h12 + ':' + (m < 10 ? '0' : '') + m + ' ' + ampm;
        } else if (hour === '*' && min === '0') {
            result = 'Every hour';
        } else if (hour === '*') {
            var stepMatch = min.match(/^\*\/(\d+)$/);
            if (stepMatch) result = 'Every ' + stepMatch[1] + ' minutes';
        } else {
            var hourStep = hour.match(/^\*\/(\d+)$/);
            if (hourStep && min === '0') result = 'Every ' + hourStep[1] + ' hours';
        }

        return result || expr;
    }

    // ---- Auto Refresh ----

    function startAutoRefresh() {
        if (refreshTimer) clearInterval(refreshTimer);
        refreshTimer = setInterval(function () {
            // Refresh posture + alerts on every tick (always relevant)
            fetchPosture();
            fetchAlerts();
        }, REFRESH_INTERVAL);
    }

    // ---- Init ----

    document.addEventListener('DOMContentLoaded', function () {
        // Tab click handlers
        tabs.forEach(function (tab) {
            tab.addEventListener('click', function (e) {
                e.preventDefault();
                switchTab(this.getAttribute('href'), true);
            });
        });

        // Red team summary card click handlers
        document.querySelectorAll('#redteam-summary .summary-card[data-rt-filter]').forEach(function (card) {
            card.addEventListener('click', function () {
                var filter = this.getAttribute('data-rt-filter');
                if (!redteamCache) return;
                if (filter === 'all') {
                    clearRtFilter();
                } else {
                    filterRedteamByStatus(filter);
                }
            });
        });

        // Red team filter clear button
        var rtClearBtn = document.getElementById('rt-filter-clear-btn');
        if (rtClearBtn) {
            rtClearBtn.addEventListener('click', function (e) {
                e.stopPropagation();
                clearRtFilter();
            });
        }

        // CMMC filter button click handlers (Compliance tab)
        document.querySelectorAll('.cmmc-filter-btn').forEach(function (btn) {
            btn.addEventListener('click', function () {
                var val = this.getAttribute('data-cmmc-filter');
                var level = val === 'other' ? 'other' : parseInt(val, 10);
                if (activeFilter === level) {
                    clearComplianceFilter();
                } else {
                    activeFilter = level;
                    document.querySelectorAll('.cmmc-card').forEach(function (card) {
                        card.classList.remove('active-filter');
                    });
                    if (complianceCache) renderCompliance(complianceCache, level);
                }
            });
        });

        // Read hash or default to posture
        var hash = window.location.hash || '#posture';
        switchTab(hash);

        // Start auto-refresh
        startAutoRefresh();
    });

    // Handle browser back/forward navigation
    window.addEventListener('popstate', function () {
        var hash = window.location.hash || '#posture';
        switchTab(hash);
        // Clear CMMC filter when navigating back to posture
        if (hash === '#posture' || hash === '') {
            activeFilter = null;
            document.querySelectorAll('.cmmc-card').forEach(function (card) {
                card.classList.remove('active-filter');
            });
        }
        // Re-render compliance without filter when navigating back to compliance tab directly
        if (hash === '#compliance' && activeFilter && complianceCache) {
            activeFilter = null;
            document.querySelectorAll('.cmmc-card').forEach(function (card) {
                card.classList.remove('active-filter');
            });
            renderCompliance(complianceCache);
        }
    });

    // ---- Notification Panel ----

    window.toggleNotifPanel = function () {
        var modal = document.getElementById('notif-modal');
        if (modal.style.display === 'none' || !modal.style.display) {
            window.openNotifPanel();
        } else {
            window.closeNotifPanel();
        }
    };

    window.openNotifPanel = function () {
        document.getElementById('notif-modal').style.display = 'flex';
        loadNotifPrefs();
        if (typeof AUTH !== 'undefined' && AUTH.isSuper) {
            loadEmergencyRules();
        }
    };

    window.closeNotifPanel = function () {
        document.getElementById('notif-modal').style.display = 'none';
    };

    function loadNotifPrefs() {
        fetch(API_BASE + '/notifications.php', {
            headers: {
                'X-Auth-User-Id': AUTH.userId,
                'X-Auth-Email': AUTH.email || '',
                'X-Auth-Name': AUTH.name || ''
            }
        })
        .then(function (r) { return r.json(); })
        .then(function (data) {
            var sub = data.subscription;
            if (sub) {
                document.getElementById('notif-enabled').checked = sub.enabled;
                document.getElementById('notif-cat-ai').checked = sub.cat_ai;
                document.getElementById('notif-cat-api').checked = sub.cat_api;
                document.getElementById('notif-cat-web').checked = sub.cat_web;
                document.getElementById('notif-cat-compliance').checked = sub.cat_compliance;
                document.getElementById('notif-min-severity').value = sub.min_severity;
                document.getElementById('notif-dedup-mode').value = sub.dedup_mode;
                document.getElementById('notif-status-vulnerable').checked = sub.notify_vulnerable;
                document.getElementById('notif-status-partial').checked = sub.notify_partial;
                document.getElementById('notif-status-defended').checked = sub.notify_defended;
                document.getElementById('notif-status-error').checked = sub.notify_error;
                document.getElementById('notif-emergency').checked = sub.emergency_alerts;
            }
            updateBellDot(sub ? sub.enabled : false);
        })
        .catch(function (err) {
            console.error('Failed to load notification prefs:', err);
        });
    }

    window.saveNotifPrefs = function () {
        var payload = {
            enabled: document.getElementById('notif-enabled').checked,
            cat_ai: document.getElementById('notif-cat-ai').checked,
            cat_api: document.getElementById('notif-cat-api').checked,
            cat_web: document.getElementById('notif-cat-web').checked,
            cat_compliance: document.getElementById('notif-cat-compliance').checked,
            min_severity: document.getElementById('notif-min-severity').value,
            dedup_mode: document.getElementById('notif-dedup-mode').value,
            notify_vulnerable: document.getElementById('notif-status-vulnerable').checked,
            notify_partial: document.getElementById('notif-status-partial').checked,
            notify_defended: document.getElementById('notif-status-defended').checked,
            notify_error: document.getElementById('notif-status-error').checked,
            emergency_alerts: document.getElementById('notif-emergency').checked
        };

        fetch(API_BASE + '/notifications.php', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-Auth-User-Id': AUTH.userId,
                'X-Auth-Email': AUTH.email || '',
                'X-Auth-Name': AUTH.name || '',
                'X-Auth-Super': AUTH.isSuper ? 'true' : 'false'
            },
            body: JSON.stringify(payload)
        })
        .then(function (r) { return r.json(); })
        .then(function (data) {
            if (data.success) {
                updateBellDot(payload.enabled);
                window.closeNotifPanel();
            } else {
                alert('Failed to save: ' + (data.error || 'Unknown error'));
            }
        })
        .catch(function (err) {
            alert('Network error saving preferences');
            console.error(err);
        });
    };

    function updateBellDot(enabled) {
        var dot = document.getElementById('notif-bell-dot');
        if (dot) {
            dot.style.display = enabled ? 'block' : 'none';
        }
    }

    // ---- Emergency Rules (super admin) ----

    function loadEmergencyRules() {
        var container = document.getElementById('emergency-rules-list');
        if (!container) return;

        fetch(API_BASE + '/emergency-rules.php', {
            headers: { 'X-Auth-User-Id': AUTH.userId }
        })
        .then(function (r) { return r.json(); })
        .then(function (data) {
            var rules = data.rules || [];
            if (rules.length === 0) {
                container.innerHTML = '<div class="empty-state">No emergency rules configured</div>';
                return;
            }
            var html = '';
            rules.forEach(function (rule) {
                var matchParts = [];
                if (rule.match_severity) matchParts.push('Severity: ' + rule.match_severity.join(', '));
                if (rule.match_status) matchParts.push('Status: ' + rule.match_status.join(', '));
                if (rule.match_category) matchParts.push('Category: ' + rule.match_category.join(', '));
                if (rule.match_attack) matchParts.push('Attack: ' + escapeHtml(rule.match_attack));

                html += '<div class="emergency-rule-item' + (rule.is_default ? ' rule-default' : '') + '">';
                html += '<div class="rule-info">';
                html += '<span class="rule-name">' + escapeHtml(rule.name) + '</span>';
                if (rule.is_default) html += ' <span class="badge badge-default">DEFAULT</span>';
                if (!rule.enabled) html += ' <span class="badge badge-disabled">DISABLED</span>';
                html += '<div class="rule-match">' + escapeHtml(matchParts.join(' | ')) + '</div>';
                html += '</div>';
                if (!rule.is_default) {
                    html += '<button class="rule-delete-btn" onclick="deleteEmergencyRule(' + rule.rule_id + ')" title="Delete rule">&times;</button>';
                } else {
                    html += '<label class="toggle-switch toggle-small"><input type="checkbox" ' + (rule.enabled ? 'checked' : '') + ' onchange="toggleDefaultRule(' + rule.rule_id + ', this.checked)"><span class="toggle-slider"></span></label>';
                }
                html += '</div>';
            });
            container.innerHTML = html;
        })
        .catch(function (err) {
            container.innerHTML = '<div class="empty-state">Failed to load rules</div>';
            console.error(err);
        });
    }

    window.openAddRuleForm = function () {
        document.getElementById('add-rule-form').style.display = 'block';
    };

    window.closeAddRuleForm = function () {
        document.getElementById('add-rule-form').style.display = 'none';
        // Clear form
        ['rule-name', 'rule-description', 'rule-severity', 'rule-status', 'rule-category', 'rule-attack'].forEach(function (id) {
            var el = document.getElementById(id);
            if (el) el.value = '';
        });
    };

    window.saveNewRule = function () {
        var name = document.getElementById('rule-name').value.trim();
        if (!name) { alert('Rule name is required'); return; }

        var csvToArray = function (val) {
            if (!val || !val.trim()) return null;
            return val.split(',').map(function (s) { return s.trim().toLowerCase(); }).filter(Boolean);
        };

        var payload = {
            name: name,
            description: document.getElementById('rule-description').value.trim(),
            match_severity: csvToArray(document.getElementById('rule-severity').value),
            match_status: csvToArray(document.getElementById('rule-status').value),
            match_category: csvToArray(document.getElementById('rule-category').value),
            match_attack: document.getElementById('rule-attack').value.trim() || null,
            enabled: true,
            override_dedup: true
        };

        fetch(API_BASE + '/emergency-rules.php', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-Auth-User-Id': AUTH.userId,
                'X-Auth-Super': 'true'
            },
            body: JSON.stringify(payload)
        })
        .then(function (r) { return r.json(); })
        .then(function (data) {
            if (data.success) {
                window.closeAddRuleForm();
                loadEmergencyRules();
            } else {
                alert('Failed: ' + (data.error || 'Unknown error'));
            }
        })
        .catch(function (err) {
            alert('Network error');
            console.error(err);
        });
    };

    window.deleteEmergencyRule = function (ruleId) {
        if (!confirm('Delete this emergency rule?')) return;
        fetch(API_BASE + '/emergency-rules.php', {
            method: 'DELETE',
            headers: {
                'Content-Type': 'application/json',
                'X-Auth-User-Id': AUTH.userId,
                'X-Auth-Super': 'true'
            },
            body: JSON.stringify({ rule_id: ruleId })
        })
        .then(function (r) { return r.json(); })
        .then(function () { loadEmergencyRules(); })
        .catch(function (err) { console.error(err); });
    };

    window.toggleDefaultRule = function (ruleId, enabled) {
        fetch(API_BASE + '/emergency-rules.php', {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
                'X-Auth-User-Id': AUTH.userId,
                'X-Auth-Super': 'true'
            },
            body: JSON.stringify({ rule_id: ruleId, enabled: enabled })
        })
        .then(function (r) { return r.json(); })
        .catch(function (err) { console.error(err); });
    };

    // Load bell dot status on page load
    (function initNotifBell() {
        if (typeof AUTH === 'undefined') return;
        fetch(API_BASE + '/notifications.php', {
            headers: { 'X-Auth-User-Id': AUTH.userId }
        })
        .then(function (r) { return r.json(); })
        .then(function (data) {
            updateBellDot(data.subscription ? data.subscription.enabled : false);
        })
        .catch(function () {});
    })();

})();
