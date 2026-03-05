# CMMC Compliance Checklists — EQMON (Apollo)

> **Scope:** Server-internal controls only. Controls requiring physical security, personnel policies,
> or organizational procedures outside the server boundary are marked **SKIPPED**.
>
> **System:** EQMON bearing expert AI chat platform (CUI for NAVSEA/DoD maritime predictive maintenance)
> **Target:** CMMC Level 2 (with Level 3 aspirational tracking)

---

## Status Legend

| Status | Meaning |
|--------|---------|
| `[ ]` | Not started |
| `[~]` | Partially implemented |
| `[x]` | Fully implemented |
| `[SKIP]` | Not server-internal — organizational/physical policy |
| `[N/A]` | Not applicable to this system |

---

# CMMC Level 1 — Basic Safeguarding (FCI)

**Source:** FAR 52.204-21, 17 practices
**Requirement:** Self-assessment, annual affirmation

| # | NIST Ref | Practice | Status | Notes |
|---|----------|----------|--------|-------|
| L1-1 | 3.1.1 | Limit system access to authorized users | `[~]` | JWT auth + RBAC implemented; admin/settings.php gap (BT-01 fix) |
| L1-2 | 3.1.2 | Limit system access to authorized transactions/functions | `[~]` | 5-tier RBAC enforced; privilege escalation gaps found by red team |
| L1-3 | 3.1.20 | Verify/control connections to external systems | `[~]` | Nginx reverse proxy; no egress filtering for AI API calls |
| L1-4 | 3.1.22 | Control information posted to publicly accessible systems | `[x]` | ResponseGuardrail filters AI output; no public-facing data endpoints |
| L1-5 | 3.3.1 | Create/retain system audit logs | `[ ]` | Only syslog auth events; no API audit logging (BT-02/03/04) |
| L1-6 | 3.3.2 | Ensure actions can be traced to individual users | `[~]` | JWT identifies user; no comprehensive audit trail yet |
| L1-7 | 3.5.1 | Identify system users/processes/devices | `[~]` | JWT auth identifies users; no device/process identification |
| L1-8 | 3.5.2 | Authenticate users/processes/devices | `[~]` | Email+password auth; no MFA (CRITICAL gap — BT-13) |
| L1-9 | 3.5.7 | Enforce minimum password complexity | `[ ]` | No server-side password policy enforcement |
| L1-10 | 3.5.8 | Prohibit password reuse | `[ ]` | No password history tracking |
| L1-11 | 3.8.3 | Sanitize/destroy media before disposal/reuse | `[SKIP]` | Physical media handling — organizational policy |
| L1-12 | 3.10.1 | Limit physical access to authorized individuals | `[SKIP]` | Physical security — Artemis server room |
| L1-13 | 3.10.3 | Escort visitors and monitor visitor activity | `[SKIP]` | Physical security — organizational policy |
| L1-14 | 3.10.4 | Maintain audit logs of physical access | `[SKIP]` | Physical security — organizational policy |
| L1-15 | 3.10.5 | Control/manage physical access devices | `[SKIP]` | Physical security — organizational policy |
| L1-16 | 3.13.1 | Monitor/control/protect communications at boundaries | `[~]` | Nginx TLS + security headers; no IDS/IPS |
| L1-17 | 3.13.5 | Implement subnetworks for publicly accessible components | `[~]` | Nginx reverse proxy separates PHP-FPM; no DMZ |

### Level 1 Summary

| Status | Count |
|--------|-------|
| Implemented `[x]` | 1 |
| Partial `[~]` | 7 |
| Not started `[ ]` | 4 |
| Skipped `[SKIP]` | 5 |
| **Actionable total** | **12** |

---

# CMMC Level 2 — Advanced (CUI Protection)

**Source:** NIST SP 800-171 Rev 2, 110 controls across 14 families
**Requirement:** Third-party assessment (C3PAO), triennial

## 3.1 — Access Control (22 controls)

| # | Control | Description | Status | Notes |
|---|---------|-------------|--------|-------|
| 1 | 3.1.1 | Limit system access to authorized users | `[~]` | JWT auth; admin/settings.php unauthenticated (BT-01) |
| 2 | 3.1.2 | Limit access to authorized transactions/functions | `[~]` | 5-tier RBAC; privilege escalation gaps |
| 3 | 3.1.3 | Control CUI flow per authorizations | `[ ]` | No CUI flow controls; data accessible across boundaries |
| 4 | 3.1.4 | Separate duties to reduce risk | `[~]` | Role separation exists; no dual-authorization for critical ops |
| 5 | 3.1.5 | Employ least privilege | `[~]` | RBAC tiers; some endpoints over-permissioned |
| 6 | 3.1.6 | Use non-privileged accounts for non-security functions | `[~]` | Viewer role exists; admin accounts used for routine tasks |
| 7 | 3.1.7 | Prevent non-privileged users from executing privileged functions | `[~]` | RBAC enforced; vertical escalation gaps found by red team |
| 8 | 3.1.8 | Limit unsuccessful logon attempts | `[x]` | RateLimiter.php with token bucket; file-based state |
| 9 | 3.1.9 | Provide privacy/security notices before granting access | `[ ]` | No login banner/notice |
| 10 | 3.1.10 | Use session lock after inactivity | `[ ]` | No session timeout; JWT valid 24h (BT-13 session_timeout) |
| 11 | 3.1.11 | Terminate session after defined conditions | `[ ]` | No session termination on inactivity |
| 12 | 3.1.12 | Monitor/control remote access sessions | `[~]` | All access is remote (web app); basic logging only |
| 13 | 3.1.13 | Employ cryptographic mechanisms for remote access | `[x]` | TLS 1.2+ via nginx; HSTS enabled |
| 14 | 3.1.14 | Route remote access via managed access control points | `[x]` | All traffic through nginx reverse proxy |
| 15 | 3.1.15 | Authorize remote execution of privileged commands | `[ ]` | No explicit authorization for admin API calls |
| 16 | 3.1.16 | Authorize wireless access | `[SKIP]` | Network infrastructure — not server-internal |
| 17 | 3.1.17 | Protect wireless access using authentication/encryption | `[SKIP]` | Network infrastructure — not server-internal |
| 18 | 3.1.18 | Control connection of mobile devices | `[SKIP]` | MDM/mobile policy — not server-internal |
| 19 | 3.1.19 | Encrypt CUI on mobile devices | `[SKIP]` | Mobile device management — not server-internal |
| 20 | 3.1.20 | Verify/control external system connections | `[~]` | AI API (Claude) egress not controlled/monitored |
| 21 | 3.1.21 | Limit use of portable storage devices | `[SKIP]` | Physical media policy — not server-internal |
| 22 | 3.1.22 | Control publicly posted information | `[x]` | ResponseGuardrail filters AI output |

## 3.2 — Awareness and Training (3 controls)

| # | Control | Description | Status | Notes |
|---|---------|-------------|--------|-------|
| 1 | 3.2.1 | Ensure personnel are aware of security risks | `[SKIP]` | Training program — organizational policy |
| 2 | 3.2.2 | Ensure personnel are trained in duties | `[SKIP]` | Training program — organizational policy |
| 3 | 3.2.3 | Provide security awareness training on threats | `[SKIP]` | Training program — organizational policy |

## 3.3 — Audit and Accountability (9 controls)

| # | Control | Description | Status | Notes |
|---|---------|-------------|--------|-------|
| 1 | 3.3.1 | Create/retain audit records | `[ ]` | Only syslog; no API/data audit (BT-02/03/04) |
| 2 | 3.3.2 | Ensure actions traceable to individual users | `[~]` | JWT identifies user; no audit trail |
| 3 | 3.3.3 | Review/update audit events | `[ ]` | No review process |
| 4 | 3.3.4 | Alert on audit process failure | `[ ]` | No failure detection (BT-03 adds this) |
| 5 | 3.3.5 | Correlate audit review/analysis/reporting | `[ ]` | No correlation engine (BT-07) |
| 6 | 3.3.6 | Provide audit reduction/report generation | `[ ]` | No reporting capability (BT-12) |
| 7 | 3.3.7 | Provide system clocks for audit record timestamps | `[x]` | NTP configured on Artemis |
| 8 | 3.3.8 | Protect audit information from unauthorized access/modification | `[ ]` | No audit log protection (BT-02 adds append-only role) |
| 9 | 3.3.9 | Limit management of audit functionality | `[ ]` | No audit management controls |

## 3.4 — Configuration Management (9 controls)

| # | Control | Description | Status | Notes |
|---|---------|-------------|--------|-------|
| 1 | 3.4.1 | Establish/maintain baseline configurations | `[~]` | nginx/PHP configs in git; no formal baseline |
| 2 | 3.4.2 | Establish/enforce security config settings | `[~]` | Nginx security headers; PHP settings not hardened |
| 3 | 3.4.3 | Track/control/review system changes | `[~]` | Git version control; no change review process |
| 4 | 3.4.4 | Analyze security impact of changes | `[ ]` | No security impact analysis process |
| 5 | 3.4.5 | Define/document/approve physical/logical access restrictions | `[~]` | RBAC defined; not formally documented |
| 6 | 3.4.6 | Employ least-functionality principle | `[~]` | Minimal services; some unnecessary PHP extensions |
| 7 | 3.4.7 | Restrict/disable/prevent nonessential programs/functions | `[~]` | No unnecessary services; PHP functions not restricted |
| 8 | 3.4.8 | Apply deny-by-exception (blocklist) policy | `[ ]` | No application allowlisting |
| 9 | 3.4.9 | Control/monitor user-installed software | `[SKIP]` | Endpoint management — not server-internal |

## 3.5 — Identification and Authentication (11 controls)

| # | Control | Description | Status | Notes |
|---|---------|-------------|--------|-------|
| 1 | 3.5.1 | Identify system users/processes/devices | `[~]` | Users identified via JWT; no device ID |
| 2 | 3.5.2 | Authenticate users/processes/devices | `[~]` | Email+password; no MFA |
| 3 | 3.5.3 | Use multifactor authentication for network access | `[ ]` | **CRITICAL GAP** — No MFA (BT-13 mfa_absence) |
| 4 | 3.5.4 | Employ replay-resistant authentication | `[~]` | JWT with expiration; no nonce/replay protection |
| 5 | 3.5.5 | Prevent reuse of identifiers | `[x]` | UUIDs for user IDs; email uniqueness enforced |
| 6 | 3.5.6 | Disable identifiers after inactivity | `[ ]` | No account deactivation for inactivity |
| 7 | 3.5.7 | Enforce minimum password complexity | `[ ]` | No password policy (BT-13 password_policy) |
| 8 | 3.5.8 | Prohibit password reuse for specified generations | `[ ]` | No password history |
| 9 | 3.5.9 | Allow temporary passwords for system logons | `[~]` | Password reset via email link; not temporary password |
| 10 | 3.5.10 | Store/transmit only cryptographically protected passwords | `[x]` | bcrypt hashing; TLS in transit |
| 11 | 3.5.11 | Obscure feedback of authentication information | `[x]` | Password fields masked; generic error messages |

## 3.6 — Incident Response (3 controls)

| # | Control | Description | Status | Notes |
|---|---------|-------------|--------|-------|
| 1 | 3.6.1 | Establish incident-handling capability | `[ ]` | No IR capability (BT-11) |
| 2 | 3.6.2 | Track/document/report incidents | `[ ]` | No incident tracking (BT-11) |
| 3 | 3.6.3 | Test incident response capability | `[ ]` | No IR testing |

## 3.7 — Maintenance (6 controls)

| # | Control | Description | Status | Notes |
|---|---------|-------------|--------|-------|
| 1 | 3.7.1 | Perform maintenance on systems | `[~]` | apt updates; no formal schedule |
| 2 | 3.7.2 | Provide controls on maintenance tools/media | `[SKIP]` | Physical maintenance tools — not server-internal |
| 3 | 3.7.3 | Ensure off-site maintenance equipment is sanitized | `[SKIP]` | Physical equipment — not server-internal |
| 4 | 3.7.4 | Check media containing diagnostic programs for malware | `[SKIP]` | Physical media — not server-internal |
| 5 | 3.7.5 | Require MFA for nonlocal maintenance sessions | `[ ]` | SSH key-based; no MFA for remote admin |
| 6 | 3.7.6 | Supervise maintenance activities of personnel without access | `[SKIP]` | Personnel supervision — organizational policy |

## 3.8 — Media Protection (9 controls)

| # | Control | Description | Status | Notes |
|---|---------|-------------|--------|-------|
| 1 | 3.8.1 | Protect (control access to) CUI on system media | `[~]` | DB access controlled; backups not encrypted |
| 2 | 3.8.2 | Limit access to CUI on system media to authorized users | `[~]` | DB roles; file permissions set |
| 3 | 3.8.3 | Sanitize/destroy system media before disposal | `[SKIP]` | Physical media disposal — not server-internal |
| 4 | 3.8.4 | Mark media with CUI markings/distribution limitations | `[SKIP]` | Physical media marking — not server-internal |
| 5 | 3.8.5 | Control access to media containing CUI, maintain accountability | `[SKIP]` | Physical media tracking — not server-internal |
| 6 | 3.8.6 | Implement cryptographic mechanisms for CUI during transport | `[x]` | TLS 1.2+ for all web traffic |
| 7 | 3.8.7 | Control use of removable media | `[SKIP]` | Removable media policy — not server-internal |
| 8 | 3.8.8 | Prohibit use of portable storage without an owner | `[SKIP]` | Portable storage policy — not server-internal |
| 9 | 3.8.9 | Protect confidentiality of backup CUI | `[ ]` | DB backups not encrypted (BT-13 encryption_at_rest) |

## 3.9 — Personnel Security (2 controls)

| # | Control | Description | Status | Notes |
|---|---------|-------------|--------|-------|
| 1 | 3.9.1 | Screen individuals before granting CUI access | `[SKIP]` | HR/personnel screening — organizational policy |
| 2 | 3.9.2 | Ensure CUI protection during/after personnel actions | `[SKIP]` | Personnel offboarding — organizational policy |

## 3.10 — Physical Protection (6 controls)

| # | Control | Description | Status | Notes |
|---|---------|-------------|--------|-------|
| 1 | 3.10.1 | Limit physical access to authorized individuals | `[SKIP]` | Physical security — Artemis server room |
| 2 | 3.10.2 | Protect/monitor the physical facility | `[SKIP]` | Physical security — facility |
| 3 | 3.10.3 | Escort visitors and monitor activity | `[SKIP]` | Physical security — organizational |
| 4 | 3.10.4 | Maintain audit logs of physical access | `[SKIP]` | Physical security — access logs |
| 5 | 3.10.5 | Control/manage physical access devices | `[SKIP]` | Physical security — locks/keys |
| 6 | 3.10.6 | Enforce safeguarding measures for CUI at alternate work sites | `[SKIP]` | Remote work policy — organizational |

## 3.11 — Risk Assessment (3 controls)

| # | Control | Description | Status | Notes |
|---|---------|-------------|--------|-------|
| 1 | 3.11.1 | Periodically assess risk to operations/assets | `[~]` | Red team assessments running; no formal RA |
| 2 | 3.11.2 | Scan for vulnerabilities periodically and when new threats identified | `[~]` | Red team covers app-layer; no infrastructure scanning |
| 3 | 3.11.3 | Remediate vulnerabilities per risk assessments | `[~]` | Red team findings tracked; remediation in progress |

## 3.12 — Security Assessment (4 controls)

| # | Control | Description | Status | Notes |
|---|---------|-------------|--------|-------|
| 1 | 3.12.1 | Periodically assess security controls | `[ ]` | No formal assessment cycle (BT-10/12 enables this) |
| 2 | 3.12.2 | Develop/implement plans of action to correct deficiencies | `[ ]` | No POA&M process (BT-10 adds this) |
| 3 | 3.12.3 | Monitor security controls on an ongoing basis | `[ ]` | No continuous monitoring (BT-09) |
| 4 | 3.12.4 | Develop/update/document system security plan | `[ ]` | No SSP (BT-10 generates this) |

## 3.13 — System and Communications Protection (16 controls)

| # | Control | Description | Status | Notes |
|---|---------|-------------|--------|-------|
| 1 | 3.13.1 | Monitor/control/protect communications at boundaries | `[~]` | Nginx TLS; no IDS/IPS |
| 2 | 3.13.2 | Employ architectural designs with security as primary consideration | `[~]` | Layered (nginx→PHP-FPM→PostgreSQL); not formally documented |
| 3 | 3.13.3 | Separate user functionality from system management | `[~]` | Admin panel separate; shared codebase |
| 4 | 3.13.4 | Prevent unauthorized/unintended information transfer | `[ ]` | No DLP controls |
| 5 | 3.13.5 | Implement subnetworks for public components | `[~]` | Nginx reverse proxy; no network segmentation |
| 6 | 3.13.6 | Deny network traffic by default; allow by exception | `[~]` | UFW configured; PHP-FPM on unix socket |
| 7 | 3.13.7 | Prevent remote activation of collaborative computing devices | `[N/A]` | No collaborative devices (webcams, mics) |
| 8 | 3.13.8 | Implement cryptographic mechanisms to prevent unauthorized disclosure | `[~]` | TLS in transit; no encryption at rest |
| 9 | 3.13.9 | Terminate network connections at end of sessions | `[ ]` | No session termination; keep-alive connections |
| 10 | 3.13.10 | Establish/manage cryptographic keys | `[ ]` | **CRITICAL** — JWT secret hardcoded (BT-01 fix) |
| 11 | 3.13.11 | Employ FIPS-validated cryptography | `[ ]` | OpenSSL not in FIPS mode |
| 12 | 3.13.12 | Prohibit remote activation of collaborative computing mechanisms | `[N/A]` | No collaborative mechanisms |
| 13 | 3.13.13 | Control/monitor use of mobile code | `[~]` | CSP headers set; no SRI for scripts |
| 14 | 3.13.14 | Control/monitor use of VoIP | `[N/A]` | No VoIP |
| 15 | 3.13.15 | Protect authenticity of communications sessions | `[x]` | TLS + JWT tokens |
| 16 | 3.13.16 | Protect confidentiality of CUI at rest | `[ ]` | **HIGH GAP** — No encryption at rest (BT-13) |

## 3.14 — System and Information Integrity (7 controls)

| # | Control | Description | Status | Notes |
|---|---------|-------------|--------|-------|
| 1 | 3.14.1 | Identify/report/correct system flaws in timely manner | `[~]` | Red team identifies flaws; no formal patch process |
| 2 | 3.14.2 | Provide protection from malicious code | `[~]` | InputValidator sanitizes input; no WAF |
| 3 | 3.14.3 | Monitor system security alerts/advisories | `[ ]` | No vulnerability feed monitoring |
| 4 | 3.14.4 | Update malicious code protection mechanisms | `[~]` | Apt security updates; no automated scanning |
| 5 | 3.14.5 | Perform scans when new vulnerabilities identified | `[~]` | Red team suite; manual trigger only |
| 6 | 3.14.6 | Monitor system including inbound/outbound traffic | `[ ]` | No real-time monitoring (BT-09) |
| 7 | 3.14.7 | Identify unauthorized use of system | `[ ]` | No anomaly detection (BT-07 correlator) |

### Level 2 Summary

| Status | Count |
|--------|-------|
| Implemented `[x]` | 11 |
| Partial `[~]` | 34 |
| Not started `[ ]` | 36 |
| Skipped `[SKIP]` | 26 |
| Not applicable `[N/A]` | 3 |
| **Actionable total** | **81** |
| **Compliance rate (x + ~*0.5) / actionable** | **~35%** |

---

# CMMC Level 3 — Expert (Enhanced CUI Protection)

**Source:** NIST SP 800-172, 24 selected enhanced requirements (on top of all Level 2)
**Requirement:** DIBCAC assessment

> Level 3 builds on Level 2. All Level 2 controls must be satisfied first.
> These are the 24 additional enhanced requirements.

| # | NIST 172 Ref | Practice | Status | Notes |
|---|-------------|----------|--------|-------|
| 1 | 3.1.1e | Employ dual authorization for critical/sensitive operations | `[ ]` | No dual-auth mechanism |
| 2 | 3.1.2e | Restrict access to systems/components under maintenance | `[~]` | SSH key-based access; no session recording |
| 3 | 3.1.3e | Employ secure information transfer solutions | `[~]` | TLS for web; AI API calls not through secure channel |
| 4 | 3.2.1e | Provide awareness training focused on APT recognition | `[SKIP]` | Training — organizational policy |
| 5 | 3.2.2e | Include practical exercises in awareness training | `[SKIP]` | Training — organizational policy |
| 6 | 3.3.1e | Employ automated mechanisms for audit review/analysis/reporting | `[ ]` | No automated audit (BT-07/09 will address) |
| 7 | 3.3.2e | Provide cross-organizational audit for CUI flow | `[ ]` | No cross-org audit capability |
| 8 | 3.4.1e | Establish/maintain authoritative source for system components | `[~]` | Git repos; no SBOM |
| 9 | 3.4.2e | Employ automated mechanisms to detect misconfigurations | `[ ]` | No config monitoring/drift detection |
| 10 | 3.4.3e | Employ automated discovery for network-connected components | `[SKIP]` | Network scanning — infrastructure, not server-internal |
| 11 | 3.5.1e | Employ automated mechanisms to prohibit compromised passwords | `[ ]` | No breached-password checking (BT-13 password_policy) |
| 12 | 3.5.3e | Employ phishing-resistant authentication | `[ ]` | No FIDO2/WebAuthn/PIV |
| 13 | 3.6.1e | Establish security operations center capability | `[ ]` | No SOC; blue team monitoring will partially address (BT-09) |
| 14 | 3.6.2e | Establish/maintain cyber incident response team | `[SKIP]` | Personnel/organizational — not server-internal |
| 15 | 3.11.1e | Employ threat intelligence to guide risk assessments | `[ ]` | No threat intel feeds |
| 16 | 3.11.2e | Conduct specialized assessments (red team, breach simulations) | `[~]` | Red team framework operational (31 modules + 10 planned) |
| 17 | 3.11.3e | Employ advanced automation for security testing | `[ ]` | Red team manual trigger; no CI/CD integration |
| 18 | 3.12.1e | Conduct penetration testing periodically | `[~]` | Red team suite available; no scheduled cadence |
| 19 | 3.13.1e | Employ isolation techniques for system components | `[~]` | PHP-FPM process isolation; no container isolation |
| 20 | 3.13.2e | Employ boundary protections to separate CUI components | `[ ]` | No micro-segmentation; CUI in shared DB |
| 21 | 3.13.3e | Employ cryptographic mechanisms to protect CUI during transmission | `[x]` | TLS 1.2+ enforced; HSTS |
| 22 | 3.13.4e | Employ physical/logical isolation for CUI processing | `[ ]` | No dedicated CUI processing enclave |
| 23 | 3.14.1e | Verify integrity of security-critical software using root of trust | `[ ]` | No code signing; no integrity verification |
| 24 | 3.14.2e | Monitor systems and detect advanced/targeted cyber attacks | `[ ]` | No advanced threat detection (BT-07/09 will partially address) |

### Level 3 Summary

| Status | Count |
|--------|-------|
| Implemented `[x]` | 1 |
| Partial `[~]` | 5 |
| Not started `[ ]` | 14 |
| Skipped `[SKIP]` | 4 |
| **Actionable total** | **20** |
| **Compliance rate** | **~15%** |

---

# Overall CMMC Posture Summary

| Level | Actionable Controls | Implemented | Partial | Not Started | Compliance Rate |
|-------|--------------------:|:-----------:|:-------:|:-----------:|:---------------:|
| **Level 1** | 12 | 1 | 7 | 4 | ~37% |
| **Level 2** | 81 | 11 | 34 | 36 | ~35% |
| **Level 3** | 20 | 1 | 5 | 14 | ~15% |

### CMMC Blockers (Must Fix for Level 2 Certification)

| Priority | Gap | NIST Ref | Remediation Task |
|----------|-----|----------|------------------|
| **CRITICAL** | No MFA | 3.5.3 | Future: TOTP/WebAuthn implementation |
| **CRITICAL** | JWT secret hardcoded | 3.13.10 | BT-01 |
| **CRITICAL** | Admin settings unauthenticated | 3.1.1 | BT-01 |
| **CRITICAL** | No audit logging | 3.3.1 | BT-02/03/04 |
| **HIGH** | No encryption at rest | 3.13.16 | Future: pgcrypto |
| **HIGH** | No incident response capability | 3.6.1-3 | BT-11 |
| **HIGH** | No continuous monitoring | 3.14.6-7 | BT-09 |
| **HIGH** | No SSP/POA&M | 3.12.2/4 | BT-10 |
| **MEDIUM** | No password policy | 3.5.7-8 | Future: PHP enforcement |
| **MEDIUM** | No session timeout | 3.1.10-11 | Future: JWT refresh tokens |

### Skipped Controls by Family

| Family | Controls | Reason |
|--------|:--------:|--------|
| 3.2 Awareness & Training | 5 | Organizational training policy |
| 3.9 Personnel Security | 2 | HR/personnel procedures |
| 3.10 Physical Protection | 6 | Physical facility security |
| 3.8 Media Protection (partial) | 5 | Physical media handling |
| 3.1 Access Control (partial) | 5 | Wireless/mobile device policies |
| 3.4 Config Management (partial) | 1 | Endpoint software management |
| 3.7 Maintenance (partial) | 4 | Physical equipment/personnel |
| 3.6 Incident Response (L3 partial) | 1 | CIRT staffing — organizational |
| 3.4 Config Management (L3) | 1 | Network discovery — infrastructure |
| **Total Skipped** | **30** | |

---

*Generated: 2026-03-05 | System: EQMON (Apollo) | Framework: CMMC 2.0*
*Red Team: /opt/security-red-team/ | Blue Team Plan: /opt/security-red-team/docs/plans/2026-03-05-security-blue-team-plan.md*
