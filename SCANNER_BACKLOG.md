# Cyber-Guardian Scanner Backlog
**Version:** 1.0.0
**Date:** 2026-03-11
**Status:** Active Development

---

## ✅ Completed Scanners (2026-03-11)

1. **Malware Scanning** - 4 scanners (ClamAV, Maldet, RKHunter, Chkrootkit)
2. **Compliance Scanning** - OS, SSH, firewall, Docker, AWS, MailCow
3. **Lynis CIS Auditing** - System hardening (200+ tests)
4. **WordPress Log Exposure** - 18+ log path security checks
5. **WordPress Vulnerability Scanning** - Core/plugin/theme CVE detection ⭐ NEW
6. **Container Image Scanning** - Trivy integration for Docker CVEs ⭐ NEW
7. **Network Security Scanning** - Port exposure & service analysis ⭐ NEW

---

## 🚧 In Progress

None - All HIGH priority scanners completed!

---

## 📋 Backlog (Prioritized)

### 1. Database Security Auditing
**Priority:** HIGH  
**Impact:** High  
**Effort:** Medium (60 min)  
**Affected:** Peter (44 WordPress databases), Willie (MailCow DB)

**Description:**  
Comprehensive MySQL/MariaDB/PostgreSQL security assessment including password strength, privilege escalation, remote access configuration.

**Implementation:**
- Script: `scripts/database-security-scanner.py`
- Check: `mysql_secure_installation` compliance
- Audit: User privileges, password policies, remote access
- Test: Common misconfigurations (root@%, weak passwords)

**Database Checks:**
- [ ] Remote root access disabled
- [ ] Anonymous users removed
- [ ] Test database removed
- [ ] Password complexity requirements
- [ ] Privilege escalation risks
- [ ] Bind address configuration
- [ ] SSL/TLS for connections
- [ ] Query logging enabled
- [ ] Slow query detection

**Acceptance Criteria:**
- [ ] Scan all MySQL instances on Peter
- [ ] Check MailCow PostgreSQL on Willie
- [ ] Identify weak database passwords
- [ ] Verify no remote root access
- [ ] Store findings in blueteam.database_security_findings
- [ ] Matrix notification for HIGH+ findings

---

### 2. SSL/TLS Configuration Audit
**Priority:** MEDIUM  
**Impact:** Medium  
**Effort:** Low (30 min)  
**Affected:** Peter (44 sites), Willie (MailCow)

**Description:**  
Deep SSL/TLS analysis beyond certificate expiration. Evaluates cipher suites, protocol versions, certificate chains, HSTS, OCSP stapling.

**Implementation:**
- Script: `scripts/ssl-security-scanner.py`
- Tool: testssl.sh or Python ssl module
- Test: Cipher strength, protocol versions, vulnerabilities

**Checks:**
- [ ] TLS 1.2+ only (no TLS 1.0/1.1)
- [ ] Strong cipher suites only
- [ ] Perfect Forward Secrecy (PFS)
- [ ] HSTS header present
- [ ] Certificate chain validity
- [ ] OCSP stapling enabled
- [ ] Heartbleed vulnerability
- [ ] POODLE vulnerability
- [ ] BEAST vulnerability
- [ ] CRIME vulnerability

**Acceptance Criteria:**
- [ ] Scan all HTTPS endpoints (Peter: 44 sites, Willie: MailCow)
- [ ] Grade each site (A+ to F)
- [ ] Identify weak ciphers
- [ ] Check for deprecated protocols
- [ ] Store results in blueteam.ssl_scans
- [ ] Matrix notification for grades below B

---

### 3. Web Server Configuration Security
**Priority:** MEDIUM  
**Impact:** Medium  
**Effort:** Medium (45 min)  
**Affected:** Peter (Nginx)

**Description:**  
Nginx/Apache hardening verification including security headers, directory listing, server info disclosure, rate limiting.

**Implementation:**
- Script: `scripts/webserver-security-scanner.py`
- Check: Security headers, configuration best practices
- Test: Info disclosure, directory traversal

**Checks:**
- [ ] Server version disclosure
- [ ] Directory listing disabled
- [ ] Security headers (CSP, X-Frame-Options, X-Content-Type-Options)
- [ ] HTTP/2 enabled
- [ ] Gzip compression configured
- [ ] Rate limiting configured
- [ ] Request size limits
- [ ] Timeout configurations
- [ ] Log format compliance
- [ ] Error page customization

**Acceptance Criteria:**
- [ ] Scan Nginx on Peter
- [ ] Test all 44 WordPress sites
- [ ] Verify security headers present
- [ ] Check for info disclosure
- [ ] Store findings in blueteam.webserver_security_findings
- [ ] Generate hardening recommendations

---

### 4. Dependency Vulnerability Scanning
**Priority:** MEDIUM-LOW  
**Impact:** Medium  
**Effort:** High (90 min)  
**Affected:** Peter (PHP/Composer), Alfred (Python/pip, Node/npm)

**Description:**  
Application-level dependency CVE detection for Python, PHP, and Node.js packages.

**Implementation:**
- Script: `scripts/dependency-vulnerability-scanner.py`
- Tools: Safety (Python), npm audit, composer audit
- Scan: requirements.txt, composer.json, package.json

**Checks:**
- [ ] Python package CVEs (Safety/pip-audit)
- [ ] PHP package CVEs (composer audit)
- [ ] Node.js package CVEs (npm audit)
- [ ] Outdated dependencies
- [ ] License compliance
- [ ] Supply chain risks

**Acceptance Criteria:**
- [ ] Scan all Python projects
- [ ] Scan all PHP projects (WordPress plugins)
- [ ] Scan all Node.js projects
- [ ] Store CVE findings in blueteam.dependency_vulnerabilities
- [ ] Generate update recommendations
- [ ] Matrix notification for CRITICAL findings

---

### 5. File Integrity Monitoring (AIDE Integration)
**Priority:** LOW  
**Impact:** Low  
**Effort:** Medium (60 min)  
**Affected:** Peter (AIDE already installed)

**Description:**  
Monitor and alert on unauthorized file system changes using AIDE (Advanced Intrusion Detection Environment).

**Implementation:**
- Script: `scripts/aide-monitor.py`
- Parse: AIDE reports from Peter
- Alert: Unauthorized changes to critical files

**Monitored Paths:**
- [ ] /etc/ (system configuration)
- [ ] /usr/bin/, /usr/sbin/ (system binaries)
- [ ] WordPress core files (wp-admin/, wp-includes/)
- [ ] Plugin files (detect backdoors)
- [ ] Web server configs (/etc/nginx/)

**Acceptance Criteria:**
- [ ] Parse AIDE daily reports
- [ ] Store changes in blueteam.file_integrity_changes
- [ ] Classify changes (expected vs. suspicious)
- [ ] Matrix notification for unauthorized changes
- [ ] Weekly baseline update workflow

---

### 6. API Security Scanning
**Priority:** LOW  
**Impact:** Low  
**Effort:** Medium (60 min)  
**Affected:** Alfred (Project Keystone APIs)

**Description:**  
REST API endpoint security testing including authentication, authorization, rate limiting, input validation.

**Implementation:**
- Script: `scripts/api-security-scanner.py`
- Test: OWASP API Security Top 10
- Check: Authentication bypass, injection, rate limiting

**Checks:**
- [ ] Authentication required on all endpoints
- [ ] Authorization properly enforced
- [ ] Rate limiting configured
- [ ] Input validation
- [ ] SQL injection protection
- [ ] XSS protection
- [ ] CSRF tokens
- [ ] API versioning
- [ ] Error message sanitization
- [ ] CORS configuration

---

### 7. Backup Verification & Testing
**Priority:** LOW  
**Impact:** Medium  
**Effort:** Low (30 min)  
**Affected:** Willie (MailCow), Peter (WordPress)

**Description:**  
Verify backups exist, are accessible, and can be restored. Test backup integrity.

**Implementation:**
- Script: `scripts/backup-verification-scanner.py`
- Check: Backup age, size, accessibility
- Test: Sample restoration

**Checks:**
- [ ] Backup exists within SLA (24h for daily)
- [ ] Backup size reasonable (not 0 bytes)
- [ ] Backup accessible/readable
- [ ] Backup encryption status
- [ ] Offsite backup verification
- [ ] Restoration test (monthly)
- [ ] RPO/RTO compliance
- [ ] Backup retention policy

---

### 8. Password Policy Auditing
**Priority:** LOW  
**Impact:** Low  
**Effort:** Low (20 min)  
**Affected:** Peter (WordPress users)

**Description:**  
Audit WordPress user passwords against common password lists, check password age, enforce complexity.

**Implementation:**
- Script: `scripts/password-audit-scanner.py`
- Check: Password strength, common passwords, reuse
- Test: Against leaked password databases (Have I Been Pwned)

**Checks:**
- [ ] No common passwords (password, admin, 123456)
- [ ] Minimum length enforcement
- [ ] Complexity requirements
- [ ] Password expiration policy
- [ ] Password history (no reuse)
- [ ] Multi-factor authentication enabled
- [ ] Session timeout configured
- [ ] Failed login lockout

---

### 9. Supply Chain Security
**Priority:** LOW  
**Impact:** Medium  
**Effort:** High (120 min)  
**Affected:** All servers

**Description:**  
Verify software supply chain integrity including package signatures, repository trust, SBOM generation.

**Implementation:**
- Script: `scripts/supply-chain-scanner.py`
- Check: Package signatures, GPG keys, repository trust
- Generate: Software Bill of Materials (SBOM)

**Checks:**
- [ ] APT repository signatures verified
- [ ] Docker image signatures (Notary/Cosign)
- [ ] Composer package signatures
- [ ] npm package integrity
- [ ] Git commit signatures
- [ ] SBOM generation (CycloneDX/SPDX)
- [ ] License compliance
- [ ] Dependency graph analysis

---

## 🎯 Quick-Win Priorities (Next 2 Weeks)

1. **Database Security Audit** (60 min) - High-risk exposure on Peter
2. **SSL/TLS Quality Check** (30 min) - Quick cipher strength verification
3. **Install Trivy** (5 min) - Enable container scanning on Willie
4. **Test new scanners** (30 min) - WordPress, Container, Network scans

---

## 📊 Implementation Metrics

**Target Coverage:**
- Infrastructure: 100% (Willie, Peter, Alfred)
- Applications: 100% (44 WordPress sites, MailCow, Keystone)
- Network: 100% (All exposed services)
- Data: 100% (Databases, backups, file integrity)

**Target Detection:**
- CVEs: Real-time (within 24h of disclosure)
- Misconfigurations: Weekly scans
- Anomalies: Real-time (AIDE, logs)
- Compliance: Weekly + on-demand

**Target Response:**
- CRITICAL: Matrix notification immediate
- HIGH: Matrix notification within 1h
- MEDIUM: Weekly summary report
- LOW: Monthly review

---

## 📝 Notes

**Database Schema:**
- All scanners use `blueteam` schema
- Consistent naming: `{type}_scans`, `{type}_vulnerabilities`, `{type}_findings`
- All views prefixed: `v_{type}_vulnerabilities`

**Matrix Integration:**
- All CRITICAL/HIGH findings auto-sent to #eqmon:artemis-matrix.ecoeyetech.com
- Threshold configurable per scanner
- Bot: @alfred-bot:alfred-matrix.quigs.com

**Automation:**
- Weekly scans: Mondays 2:00 AM
- Daily scans: Malware (2-4 AM)
- Hourly: Codebase security scan
- Real-time: Log monitoring, AIDE

---

**Last Updated:** 2026-03-11
**Next Review:** 2026-03-18
