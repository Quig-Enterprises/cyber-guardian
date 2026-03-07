# Security Mitigation Plan

**Created:** 2026-03-07
**Scanner:** Blue Team Codebase Security Scanner
**Scope:** All CxQ plugins and WordPress installations

---

## Executive Summary

The Blue Team codebase scanner identified **4,073 security issues** across **64 projects**. This plan prioritizes mitigation by:

1. **Severity** (CRITICAL > HIGH > MEDIUM)
2. **Ownership** (CxQ code > third-party plugins)
3. **Impact** (number of sites affected)
4. **Effort** (quick wins first)

---

## Mitigation Strategy

### Phase 1: Global Infrastructure (HIGHEST PRIORITY)
**Timeline:** Week 1
**Effort:** 2-4 hours
**Impact:** Protects ALL WordPress sites

#### Task 1.1: Implement ClamAV Malware Scanning
- **Priority:** CRITICAL
- **Issues Affected:** 126 file upload vulnerabilities
- **Implementation:** Deploy WordPress mu-plugin with ClamAV integration
- **Guide:** See `MALWARE_SCANNING_IMPLEMENTATION.md`
- **Status:** ✅ **COMPLETE** (2026-03-07)

**Action Items:**
- [x] Install ClamAV on alfred server - **ALREADY INSTALLED** (ClamAV 1.4.3)
- [x] Deploy clamav-upload-scanner.php to mu-plugins - **DEPLOYED**
- [x] Test on staging (sandbox.quigs.com) - **ALL TESTS PASS**
- [x] Deploy to production sites - **DEPLOYED** (10.153.2.6)
- [x] Configure monitoring and alerts - **LOGGING ACTIVE**

**Expected Outcome:** ✅ All file uploads scanned for malware before reaching permanent storage

**Deployment Results:**
- Plugin: `/var/www/html/wordpress/wp-content/mu-plugins/clamav-upload-scanner.php`
- Test Results: All tests PASSED (malware blocked, clean files allowed)
- See: `CLAMAV_DEPLOYMENT_COMPLETE.md` for details

---

### Phase 2: Critical XSS Vulnerabilities (HIGH PRIORITY)
**Timeline:** Week 1
**Effort:** 30 minutes
**Impact:** 2 XSS vulnerabilities fixed

#### Task 2.1: Fix XSS in cxq-facebot
- **Priority:** HIGH
- **Files Affected:**
  - `show_facebook_search.php:78`
  - `show_main_page.php:172`
- **Fix:** Add `esc_attr()` wrapper to user input
- **Status:** ⬜ Not started

**Action Items:**
- [ ] Review cxq-facebot XSS vulnerabilities
- [ ] Apply esc_attr() fixes
- [ ] Test search functionality
- [ ] Deploy to production
- [ ] Verify fix with security scan

---

### Phase 3: CxQ Plugin Security Hardening (MEDIUM PRIORITY)
**Timeline:** Weeks 2-4
**Effort:** 2-3 days per plugin
**Impact:** 28 CxQ plugins hardened

#### Priority Order (by critical/high count):

| Plugin | Critical | High | Priority | Effort |
|--------|----------|------|----------|--------|
| cxq-membership | 255 | 7 | 1 | High |
| cxq-scheduler | 231 | 2 | 2 | High |
| cxq-signage | 90 | 0 | 3 | Medium |
| cxq-site-manager-client | 74 | 0 | 4 | Medium |
| cxq-site-manager-host | 67 | 4 | 5 | Medium |
| cxq-facebot | 57 | 6 | 6 | Low (XSS already fixed in Phase 2) |
| cxq-autocomplete-awsc-form | 48 | 0 | 7 | Medium |
| cxq-woocommerce-sales-listx | 40 | 0 | 8 | Low |
| cxq-email-relay | 39 | 4 | 9 | Medium |
| cxq-cashdrawer | 38 | 0 | 10 | Low |
| cxq-license-manager | 36 | 0 | 11 | Low |
| cxq-event-calendar | 34 | 4 | 12 | Medium |
| cxq-antispam-host | 30 | 0 | 13 | Low |
| cxq-dev-tools | 28 | 0 | 14 | Low |
| cxq-updater-host | 15 | 0 | 15 | Low |
| cxq-firewall | 12 | 4 | 16 | Medium |
| cxq-antispam | 11 | 4 | 17 | Low |
| cxq-google-hours | 10 | 4 | 18 | Low |
| cxq-woocommerce-sales-list | 10 | 0 | 19 | Low |
| cxq-board-docs | 8 | 4 | 20 | Low |

**Note:** Many "CRITICAL" SQL injection findings are false positives (string concatenation, not SQL). Each plugin requires manual review to identify true vulnerabilities.

---

### Phase 4: Third-Party Plugin Monitoring (LOW PRIORITY)
**Timeline:** Ongoing
**Effort:** Monitor only
**Impact:** Awareness of third-party vulnerabilities

#### Strategy:
- **Do NOT modify third-party plugin code**
- Monitor for security updates
- Replace vulnerable plugins if necessary
- Document known issues

**High-Issue Third-Party Plugins:**
- wordfence (180 issues) - Security plugin, likely false positives
- woocommerce (172 issues) - Core commerce plugin, mostly false positives
- motopress-hotel-booking (102 issues)
- mailpoet (242 issues)

**Action:** Review WordPress.org security advisories and update regularly

---

## Detailed Mitigation Tasks

### CxQ-Facebot (Priority: HIGH)

**Location:** `/var/www/html/wordpress/wp-content/plugins/cxq-facebot/`

**Issues:**
1. **XSS Vulnerability (HIGH)** - 2 instances
   - File: `show_facebook_search.php:78`
   - File: `show_main_page.php:172`
   - Current: `<?php echo $_GET['q']; ?>`
   - Fix: `<?php echo esc_attr($_GET['q'] ?? ''); ?>`

2. **File Upload (HIGH)** - 4 instances
   - Vendor library issues (cxq-app-data-importer)
   - Will be resolved by Phase 1 global malware scanning

**TODO Created:** `cxq-facebot/TODO.md`

---

### CxQ-Membership (Priority: HIGH)

**Location:** `/var/www/html/wordpress/wp-content/plugins/cxq-membership/`

**Issues:**
- 255 CRITICAL (mostly false positive SQL injection flags)
- 7 HIGH (file upload and other issues)

**Action Required:**
1. Manual review to separate true vulnerabilities from false positives
2. Focus on actual database query patterns
3. Review file upload handling in forms
4. Audit input validation and sanitization

**TODO Created:** `cxq-membership/TODO.md`

---

### CxQ-Scheduler (Priority: HIGH)

**Location:** `/var/www/html/wordpress/wp-content/plugins/cxq-scheduler/`

**Issues:**
- 231 CRITICAL (needs review for false positives)
- 2 HIGH

**Action Required:**
1. Review temp_diagnostic_*.php files (may be test files)
2. Audit database query patterns
3. Review input validation for schedule parameters
4. Check calendar event handling for XSS

**TODO Created:** `cxq-scheduler/TODO.md`

---

### CxQ-Email-Relay (Priority: MEDIUM)

**Location:** `/var/www/html/wordpress/wp-content/plugins/cxq-email-relay/`

**Issues:**
- 39 CRITICAL (mostly false positives in PDF parser string concatenation)
- 4 HIGH (file upload issues)

**Action Required:**
1. Verify PDF parser issues are false positives (not SQL related)
2. Review email attachment handling
3. Implement malware scanning for email attachments
4. Audit email header injection vulnerabilities

**TODO Created:** `cxq-email-relay/TODO.md`

---

### CxQ-Firewall (Priority: MEDIUM)

**Location:** `/var/www/html/wordpress/wp-content/plugins/cxq-firewall/`

**Issues:**
- 12 CRITICAL
- 4 HIGH

**Irony Alert:** Our firewall plugin has security issues that need fixing!

**Action Required:**
1. Review firewall rule validation
2. Audit IP whitelist/blacklist handling
3. Check for XSS in admin interface
4. Review input sanitization for firewall rules

**TODO Created:** `cxq-firewall/TODO.md`

---

## Mitigation Workflow

### For Each CxQ Plugin:

1. **Review Scan Report**
   ```bash
   jq '.projects[] | select(.name == "cxq-PLUGIN-NAME")' \
     reports/codebase-security-scan-*.json
   ```

2. **Identify True Vulnerabilities**
   - Separate false positives (string concatenation) from real SQL injection
   - Verify file upload issues are actual security concerns
   - Confirm XSS vulnerabilities with manual testing

3. **Create Fix Branch**
   ```bash
   cd /var/www/html/wordpress/wp-content/plugins/cxq-PLUGIN-NAME
   git checkout -b security/fix-ISSUE-TYPE
   ```

4. **Implement Fixes**
   - Apply security patches
   - Add input validation
   - Implement output escaping
   - Update tests

5. **Test Fixes**
   - Run security scan again
   - Test functionality
   - Verify no regressions

6. **Deploy**
   - Test on staging
   - Deploy to production
   - Update TODO.md

7. **Document**
   - Update plugin version
   - Document fixes in CHANGELOG
   - Update security scan report

---

## Scanner Pattern Refinement

### Known False Positive: SQL Injection Pattern

**Current Problem:**
Pattern `"\s*\.\s*\$` matches ANY string concatenation, not just SQL queries.

**Examples of False Positives:**
```php
// NOT SQL injection - just string building:
$output .= "Event ID: " . $data['event_id'] . "\n";
$html .= "Name: " . $name . "<br>";
$message = "Hello " . $user . "!";
```

**Fix Needed:**
Update pattern to require database function context:
```python
# BEFORE (too broad):
"pattern": r'"\s*\.\s*\$'

# AFTER (more specific):
"pattern": r'\$wpdb->(query|get_results|get_row|get_var)\s*\([^)]*"\s*\.\s*\$'
```

**TODO:** Update `blueteam/api/codebase_scanner.py` with refined patterns

---

## Success Metrics

### Phase 1 Success (Global Protection):
- [ ] ClamAV installed and running
- [ ] All file uploads scanned for malware
- [ ] Zero malware files in uploads directory
- [ ] Monitoring alerts configured

### Phase 2 Success (XSS Fixes):
- [ ] cxq-facebot XSS vulnerabilities fixed
- [ ] Security scan shows 0 HIGH XSS issues in CxQ plugins
- [ ] Manual XSS testing passes

### Phase 3 Success (Plugin Hardening):
- [ ] Top 10 CxQ plugins reviewed and hardened
- [ ] True SQL injection vulnerabilities identified and fixed
- [ ] Input validation implemented across plugins
- [ ] Security scan shows <100 CRITICAL issues

### Overall Success:
- [ ] Scanner false positive rate <10%
- [ ] Zero exploitable vulnerabilities in CxQ code
- [ ] All WordPress sites protected by malware scanning
- [ ] Regular security scans automated (weekly)

---

## Timeline

### Week 1 (March 7-14):
- [ ] Phase 1: Deploy ClamAV malware scanning
- [ ] Phase 2: Fix cxq-facebot XSS vulnerabilities
- [ ] Refine scanner SQL injection patterns

### Week 2-3 (March 15-28):
- [ ] Phase 3: Review and fix cxq-membership (highest issue count)
- [ ] Phase 3: Review and fix cxq-scheduler
- [ ] Phase 3: Review and fix cxq-signage

### Week 4-6 (March 29 - April 18):
- [ ] Phase 3: Review remaining high-priority CxQ plugins
- [ ] Implement automated weekly security scans
- [ ] Document security best practices for development

### Ongoing:
- [ ] Monitor third-party plugin security advisories
- [ ] Run weekly security scans
- [ ] Update ClamAV virus definitions daily
- [ ] Review new code for security issues before deployment

---

## Resources Required

### Infrastructure:
- [x] ClamAV installation on alfred server (~500MB-1GB RAM)
- [ ] Scheduled cron job for weekly security scans
- [ ] Log storage for security scan results (~100MB/month)

### Personnel:
- Developer time: ~40 hours (spread over 6 weeks)
  - Week 1: 4 hours (malware scanning + XSS fixes)
  - Weeks 2-6: ~6 hours/week (plugin reviews)

### Tools:
- [x] Blue Team codebase scanner (completed)
- [ ] Automated security testing in CI/CD
- [ ] Security vulnerability tracking system

---

## Risk Assessment

### If Not Addressed:

**CRITICAL Risks:**
- Malware uploaded to WordPress sites
- Server compromise via file upload exploits
- Data exfiltration through XSS attacks

**HIGH Risks:**
- SQL injection attacks on custom plugins
- Credential theft via XSS
- Path traversal attacks

**MEDIUM Risks:**
- Hardcoded credentials discovered by attackers
- Weak cryptography leading to password compromise
- Third-party plugin vulnerabilities

**Impact:**
- Site defacement
- Data breach (customer information, payment data)
- SEO spam injection
- Server resource abuse
- Legal/compliance issues (GDPR, PCI-DSS)

---

## Compliance Considerations

### NIST 800-171 Controls:
- **3.14.1** - Identify and manage information system flaws ✅ (scanner implemented)
- **3.14.2** - Identify and manage malicious code ⬜ (ClamAV pending)
- **3.14.6** - Monitor, control, and protect communications ⬜ (plugin hardening ongoing)

### PCI-DSS Requirements:
- **6.1** - Establish process to identify security vulnerabilities ✅ (scanner operational)
- **6.2** - Protect all systems against malware ⬜ (ClamAV pending)
- **6.5.7** - Cross-site scripting (XSS) ⬜ (fixes pending)

---

## Appendix: Quick Reference Commands

### Run Security Scan:
```bash
cd /opt/claude-workspace/projects/cyber-guardian
python3 blueteam/cli_codebase_scan.py
```

### View Issues for Specific Plugin:
```bash
jq '.projects[] | select(.name == "cxq-PLUGIN-NAME")' \
  reports/codebase-security-scan-*.json
```

### Find All XSS Vulnerabilities:
```bash
jq -r '.projects[].issues[] | select(.category == "xss") |
  "\(.severity)|\(.file):\(.line)|\(.code_snippet)"' \
  reports/codebase-security-scan-*.json
```

### Check ClamAV Status:
```bash
sudo systemctl status clamav-daemon
sudo clamdscan --version
```

### Monitor Upload Scans:
```bash
sudo tail -f /var/log/nginx/error.log | grep "ClamAV Upload Scanner"
```

---

**Next Review:** 2026-03-14 (1 week)
**Document Owner:** Blue Team
**Status:** 🟡 In Progress (Phase 1 pending)
