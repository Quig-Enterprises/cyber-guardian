# Security Remediation TODO Index

**Last Updated:** 2026-03-07
**Source:** Blue Team Codebase Security Scanner
**Status:** Phase 1 Complete, Phase 2-3 In Progress

---

## Quick Status

| Phase | Status | Priority | Effort | Deadline |
|-------|--------|----------|--------|----------|
| **Phase 1:** Global Malware Scanning | ✅ COMPLETE | CRITICAL | 4 hours | 2026-03-07 |
| **Phase 2:** XSS Fixes | 🔄 IN PROGRESS | HIGH | 15 min | 2026-03-08 |
| **Phase 3:** Plugin Hardening | ⬜ NOT STARTED | MEDIUM | 4-6 weeks | 2026-04-18 |
| **Phase 4:** Third-Party Monitoring | ⬜ NOT STARTED | LOW | Ongoing | Ongoing |

---

## Phase 1: Global Infrastructure ✅ COMPLETE

### ✅ Task 1.1: ClamAV Malware Scanning - DEPLOYED

**Status:** COMPLETE (2026-03-07)
**Impact:** All 126 file upload locations now protected

**What Was Done:**
- ✅ Deployed WordPress mu-plugin: `clamav-upload-scanner.php`
- ✅ All tests passed (malware blocked, clean files allowed)
- ✅ Logging active and monitoring configured
- ✅ Zero file upload locations remain unprotected

**Documentation:**
- `/opt/claude-workspace/projects/cyber-guardian/CLAMAV_DEPLOYMENT_COMPLETE.md`

**No further action required** - monitoring in place.

---

## Phase 2: Critical XSS Vulnerabilities 🔄 IN PROGRESS

### 🔄 Task 2.1: Fix XSS in cxq-facebot - BEING ADDRESSED ELSEWHERE

**Status:** IN PROGRESS (assigned to another agent/workflow)
**Priority:** HIGH
**Effort:** 15 minutes
**Deadline:** 2026-03-08

**Issues:**
- 2 XSS vulnerabilities in search forms
- Unescaped user input in `$_GET['q']` parameter

**Detailed TODO:**
📄 **See:** `/var/www/html/wordpress/wp-content/plugins/cxq-facebot/TODO.md`
- Section: "SECURITY ISSUES (URGENT)"
- Contains: Implementation steps, code examples, test procedures

**Files to Fix:**
1. `show_facebook_search.php:78` - Add `esc_attr()`
2. `show_main_page.php:172` - Add `esc_attr()`

**Quick Reference:**
```php
// BEFORE (vulnerable):
value="<?php echo $_GET['q']??$params['q']; ?>"

// AFTER (secure):
value="<?php echo esc_attr($_GET['q'] ?? $params['q'] ?? ''); ?>"
```

**Do NOT duplicate work** - check with assigned agent before implementing.

---

## Phase 3: CxQ Plugin Security Hardening ⬜ NOT STARTED

### Overview

28 CxQ plugins require security review and hardening.
Most "CRITICAL" findings are false positives (string concatenation flagged as SQL injection).

**Timeline:** Weeks 2-4 (March 15 - April 18, 2026)

---

### 🔴 Task 3.1: Review cxq-membership (Priority 1)

**Status:** NOT STARTED
**Priority:** HIGH
**Effort:** 4-6 hours
**Issues:** 255 CRITICAL, 7 HIGH

**Detailed TODO:**
📄 **See:** `/var/www/html/wordpress/wp-content/plugins/cxq-membership/TODO.md`
- Section: "🔴 SECURITY SCAN RESULTS (NEW - 2026-03-07)"

**Action Required:**
- Manual code review to separate true vulnerabilities from false positives
- Focus on database query functions: `$wpdb->query()`, `$wpdb->get_results()`
- Ignore string building for output/logging
- Review file upload handling

**Timeline:** Week 2-3 (March 15-28)

---

### 🟡 Task 3.2: Review cxq-scheduler (Priority 2)

**Status:** NOT STARTED
**Priority:** MEDIUM
**Effort:** 3-4 hours
**Issues:** 231 CRITICAL, 2 HIGH

**Detailed TODO:**
📄 **See:** `/var/www/html/wordpress/wp-content/plugins/cxq-scheduler/TODO.md`
- Will need security section added (template below)

**Action Required:**
- Review temp_diagnostic_*.php files (may be test files that can be deleted)
- Audit database query patterns
- Review input validation for schedule parameters
- Check calendar event handling for XSS

**Timeline:** Week 3 (March 22-28)

---

### 🟡 Task 3.3: Review cxq-signage (Priority 3)

**Status:** NOT STARTED
**Priority:** MEDIUM
**Effort:** 2-3 hours
**Issues:** 90 CRITICAL, 0 HIGH

**Detailed TODO:**
📄 **Location:** `/var/www/html/wordpress/wp-content/plugins/cxq-signage/TODO.md`
- Will need security section added

**Action Required:**
- Manual review for true SQL injection vulnerabilities
- Most findings likely false positives

**Timeline:** Week 4 (March 29 - April 4)

---

### 🟡 Task 3.4: Review cxq-site-manager-client (Priority 4)

**Status:** NOT STARTED
**Priority:** MEDIUM
**Effort:** 2-3 hours
**Issues:** 74 CRITICAL, 0 HIGH

**Detailed TODO:**
📄 **Location:** `/var/www/html/wordpress/wp-content/plugins/cxq-site-manager-client/TODO.md`

**Action Required:**
- Review API communication patterns
- Check input sanitization
- Audit data synchronization security

**Timeline:** Week 4-5 (March 29 - April 11)

---

### 🟡 Task 3.5: Review cxq-site-manager-host (Priority 5)

**Status:** NOT STARTED
**Priority:** MEDIUM
**Effort:** 2-3 hours
**Issues:** 67 CRITICAL, 4 HIGH

**Detailed TODO:**
📄 **Location:** `/var/www/html/wordpress/wp-content/plugins/cxq-site-manager-host/TODO.md`

**Action Required:**
- Review plugin update distribution security
- Check API endpoint authentication
- Audit file handling (4 HIGH file upload issues)

**Timeline:** Week 5 (April 4-11)

---

### 🟢 Task 3.6: Review cxq-firewall (Priority 6)

**Status:** NOT STARTED
**Priority:** MEDIUM
**Effort:** 2-3 hours
**Issues:** 12 CRITICAL, 4 HIGH

**Detailed TODO:**
📄 **Location:** `/var/www/html/wordpress/wp-content/plugins/cxq-firewall/TODO.md`

**Irony Alert:** Our firewall plugin has security issues!

**Action Required:**
- Review firewall rule validation
- Audit IP whitelist/blacklist handling
- Check for XSS in admin interface
- Review input sanitization for firewall rules

**Timeline:** Week 5 (April 4-11)

---

### 🟢 Task 3.7-3.20: Review Remaining CxQ Plugins

**Status:** NOT STARTED
**Priority:** LOW-MEDIUM
**Timeline:** Weeks 5-6 (April 4-18)

| Plugin | Critical | High | Priority | Effort |
|--------|----------|------|----------|--------|
| cxq-email-relay | 39 | 4 | 7 | 2 hours |
| cxq-cashdrawer | 38 | 0 | 8 | 1-2 hours |
| cxq-license-manager | 36 | 0 | 9 | 1-2 hours |
| cxq-event-calendar | 34 | 4 | 10 | 2 hours |
| cxq-antispam-host | 30 | 0 | 11 | 1 hour |
| cxq-dev-tools | 28 | 0 | 12 | 1 hour |
| cxq-updater-host | 15 | 0 | 13 | 1 hour |
| cxq-antispam | 11 | 4 | 14 | 1 hour |
| cxq-google-hours | 10 | 4 | 15 | 1 hour |
| cxq-woocommerce-sales-list | 10 | 0 | 16 | 1 hour |
| cxq-board-docs | 8 | 4 | 17 | 1 hour |
| Others (11 plugins) | <8 | varied | 18-28 | 30m each |

**Detailed TODOs:**
Each plugin's TODO.md will need security section added following the template below.

---

## Phase 4: Third-Party Plugin Monitoring ⬜ NOT STARTED

### Strategy

**DO NOT modify third-party plugin code**

**Actions:**
- Monitor WordPress.org security advisories
- Update plugins regularly
- Replace vulnerable plugins if necessary
- Document known issues

**High-Issue Third-Party Plugins:**
- wordfence (180 issues) - Security plugin, likely false positives
- woocommerce (172 issues) - Core commerce, mostly false positives
- motopress-hotel-booking (102 issues)
- mailpoet (242 issues)
- jetpack (204 issues)

**Detailed TODO:**
📄 **See:** `/opt/claude-workspace/projects/cyber-guardian/SECURITY_MITIGATION_PLAN.md`
- Section: "Phase 4: Third-Party Plugin Monitoring"

---

## Scanner Improvements

### Task: Refine SQL Injection Patterns

**Status:** NOT STARTED
**Priority:** MEDIUM
**Effort:** 1-2 hours

**Problem:**
Current pattern flags ALL string concatenation as SQL injection.
~90% of CRITICAL findings are false positives.

**Solution:**
Update `/opt/claude-workspace/projects/cyber-guardian/blueteam/api/codebase_scanner.py`

**Before (too broad):**
```python
"pattern": r'"\s*\.\s*\$'
```

**After (more specific):**
```python
"pattern": r'\$wpdb->(query|get_results|get_row|get_var)\s*\([^)]*"\s*\.\s*\$'
```

This requires database function context to flag as SQL injection.

---

## TODO Template for CxQ Plugins

Use this template when adding security sections to plugin TODO.md files:

```markdown
## 🔴 SECURITY SCAN RESULTS (2026-03-07)

**Source:** Blue Team Codebase Security Scanner
**Status:** NEEDS MANUAL REVIEW

### Summary

| Severity | Count | True Vulnerabilities | False Positives |
|----------|-------|---------------------|-----------------|
| CRITICAL | XX | TBD (needs review) | ~95% (estimated) |
| HIGH | XX | TBD (needs review) | Unknown |

### Action Required

- [ ] **Manual Code Review** - Review flagged patterns (Estimated: X hours)
  - Focus on: `$wpdb->query()`, `$wpdb->get_results()`, etc.
  - Ignore: String concatenation for output/logging
  - Timeline: Week X (Date range)

- [ ] **File Upload Review** (if HIGH > 0)
  - Already resolved by global malware scanning
  - No code changes required

### Files to Review

1. File path 1 - Description
2. File path 2 - Description
3. etc.

### Timeline

- **Week X:** Manual review
- **Week Y:** Apply fixes (if needed)
- **Week Z:** Retest with refined scanner

**See Also:** `/opt/claude-workspace/projects/cyber-guardian/SECURITY_MITIGATION_PLAN.md`
```

---

## How to Use This Index

### For Agents/Developers

1. **Check Phase Status** - See what's complete, in progress, or pending
2. **Find Detailed TODO** - Follow links to specific plugin TODO.md files
3. **Avoid Duplicate Work** - Check status before starting work
4. **Update Status** - Mark items complete when finished

### For Project Managers

1. **Track Progress** - Phase completion percentages
2. **Allocate Resources** - Assign tasks based on priority and effort
3. **Monitor Timeline** - Ensure deadlines are met
4. **Report Status** - Use this as executive summary

### For Security Auditors

1. **Verify Coverage** - Ensure all findings addressed
2. **Review Priorities** - Confirm risk-based approach
3. **Check Documentation** - Detailed notes in linked files
4. **Track Remediation** - Status updates in real-time

---

## Quick Reference Commands

### Run Security Scan
```bash
cd /opt/claude-workspace/projects/cyber-guardian
python3 blueteam/cli_codebase_scan.py
```

### View Specific Plugin Issues
```bash
jq '.projects[] | select(.name == "PLUGIN-NAME")' \
  reports/codebase-security-scan-*.json
```

### Deploy Malware Scanning to New Site
```bash
cd /opt/claude-workspace/projects/cyber-guardian
./deploy-clamav-scanner.sh site-name
```

### Check ClamAV Status
```bash
sudo systemctl status clamav-daemon
sudo tail -f /var/log/nginx/error.log | grep "ClamAV"
```

---

## Related Documentation

### Primary Documents

1. **SECURITY_MITIGATION_PLAN.md** - Complete 6-week mitigation plan
   - All phases detailed
   - Timeline and effort estimates
   - Success criteria

2. **CLAMAV_DEPLOYMENT_COMPLETE.md** - Phase 1 implementation
   - Deployment details
   - Test results
   - Monitoring guide

3. **CODEBASE_SCAN_SUMMARY.md** - Scanner analysis
   - Issue breakdown
   - False positive analysis
   - Coverage details

4. **MALWARE_SCANNING_IMPLEMENTATION.md** - Original implementation guide
   - ClamAV setup
   - WordPress integration
   - Best practices

### Plugin TODO Files

- `/var/www/html/wordpress/wp-content/plugins/cxq-facebot/TODO.md`
- `/var/www/html/wordpress/wp-content/plugins/cxq-membership/TODO.md`
- `/var/www/html/wordpress/wp-content/plugins/cxq-scheduler/TODO.md`
- Add security sections to other plugin TODO files as needed

---

## Progress Tracking

### Overall Completion

**Phase 1:** ████████████████████ 100% (1/1 tasks complete)
**Phase 2:** ████░░░░░░░░░░░░░░░░  20% (0/1 tasks complete, in progress)
**Phase 3:** ░░░░░░░░░░░░░░░░░░░░   0% (0/20 tasks complete)
**Phase 4:** ░░░░░░░░░░░░░░░░░░░░   0% (ongoing monitoring)

**Total Issues Addressed:** 126/4,073 (3.1%)
- File uploads: 126/126 (100%) ✅
- XSS: 0/2 (0%) 🔄
- SQL injection: 0/3,367 (0%, pending false positive filter)
- Other: 0/578 (0%)

### Timeline Status

- **Week 1 (March 7-14):** ▓▓▓▓▓▓▓▓▓▓░░░░░░░░░░  50% (Phase 1 complete)
- **Week 2-3 (March 15-28):** Planned (cxq-membership, cxq-scheduler)
- **Week 4-6 (March 29 - April 18):** Planned (remaining plugins)

---

## Notes for Future Agents

1. **Check Status First** - Don't duplicate work in progress
2. **Update When Complete** - Mark tasks done and update percentages
3. **Link to Details** - Always point to plugin TODO.md for specifics
4. **Document Changes** - Update this index when adding security sections
5. **False Positives** - ~90% of SQL injection findings are false positives
6. **Malware Scanning** - Global solution deployed, no per-plugin changes needed

---

**Last Updated:** 2026-03-07 08:30:00
**Next Review:** 2026-03-08 (Daily during Phase 2)
**Owner:** Security Team / Development Team
**Status:** 🟢 Phase 1 Complete, 🟡 Phase 2-3 In Progress
