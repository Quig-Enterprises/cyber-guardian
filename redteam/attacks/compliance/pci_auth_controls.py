"""PCI DSS 4.0 Requirement 8 — Authentication Controls.

Verifies user authentication controls for cardholder data environment
(CDE) access including password strength, account lockout, session
timeout, shared account detection, hardcoded credentials, and MFA
enforcement.
"""

import os
import re
import asyncio

from redteam.base import Attack, AttackResult, Severity, Status


# Generic / shared account names that violate PCI Req 8.5.
GENERIC_ACCOUNT_NAMES = {
    "admin", "administrator", "root", "operator", "guest", "service",
    "shared", "test", "demo", "default", "system", "sa", "dba",
    "backup", "monitor", "readonly", "support",
}

# Patterns indicating hardcoded credentials.
CREDENTIAL_PATTERNS = [
    re.compile(r'(?:password|passwd|pwd)\s*[=:]\s*["\']?.{3,}', re.IGNORECASE),
    re.compile(r'(?:secret|api_key|apikey|token|auth_token)\s*[=:]\s*["\']?.{3,}', re.IGNORECASE),
    re.compile(r'(?:db_pass|db_password|database_password)\s*[=:]\s*["\']?.{3,}', re.IGNORECASE),
]

# Known false positive patterns for credential detection
CREDENTIAL_FP_PATTERNS = [
    re.compile(r'passwd:\s+files', re.IGNORECASE),       # nsswitch.conf
    re.compile(r'%\(cf\w+\)s', re.IGNORECASE),           # fail2ban template vars
    re.compile(r'%\(\w+\)s', re.IGNORECASE),             # Python string template vars
    re.compile(r"&apos;", re.IGNORECASE),                 # XML entity (ImageMagick)
    re.compile(r'password\s*[=:]\s*["\']?\s*$'),          # Empty password values
    re.compile(r'password\s*[=:]\s*["\']?\$\{'),          # Shell variable substitution
    re.compile(r'password\s*[=:]\s*["\']?None', re.I),    # Python None
    re.compile(r'password\s*[=:]\s*["\']?null', re.I),    # null/placeholder
    re.compile(r'password\s*[=:]\s*["\']?%s', re.I),      # Format string placeholders
]

# Directories to scan for hardcoded credentials.
CONFIG_SCAN_DIRS = [
    "/etc",
    "/opt",
    "/var/www",
]

# Extensions to scan.
CONFIG_EXTENSIONS = {
    ".conf", ".cfg", ".ini", ".env", ".yaml", ".yml", ".toml",
    ".properties", ".json", ".xml", ".php", ".py", ".sh",
}

# Extensions / paths to skip.
SKIP_PATTERNS = {"node_modules", "__pycache__", ".git", "vendor", ".pyc",
                  "venv", ".venv", "env", "site-packages"}


class PCIAuthControlsAttack(Attack):
    name = "compliance.pci_auth_controls"
    category = "compliance"
    severity = Severity.CRITICAL
    description = "PCI DSS 4.0 Req 8 — Verify user authentication controls for CDE access"

    async def execute(self, client) -> list[AttackResult]:
        results: list[AttackResult] = []

        login_ep = self._get_login_endpoint()

        # ----------------------------------------------------------------
        # 1. Password minimum length — attempt short passwords
        # ----------------------------------------------------------------
        short_passwords = [
            ("8char", "Ab1!xyzw"),         # 8 chars
            ("10char", "Ab1!xyzw90"),      # 10 chars
            ("11char", "Ab1!xyzw901"),     # 11 chars
        ]
        any_accepted = False
        attempts_detail = []
        for label, pwd in short_passwords:
            try:
                status_code, body, headers = await client.post(
                    login_ep,
                    json_body={
                        "action": "change_password",
                        "email": "redteam-viewer@test.com",
                        "new_password": pwd,
                    },
                    cookies={},
                )
                accepted = status_code == 200 and "error" not in body.lower()
                if accepted:
                    any_accepted = True
                attempts_detail.append(f"{label}({len(pwd)} chars): status={status_code}, accepted={accepted}")
            except Exception as exc:
                attempts_detail.append(f"{label}: error={exc}")

        if any_accepted:
            pwd_status = Status.VULNERABLE
            detail = (
                "Short passwords were accepted. PCI DSS 4.0 Req 8.3.6 requires "
                "minimum 12-character passwords. Findings: " + "; ".join(attempts_detail)
            )
        else:
            pwd_status = Status.DEFENDED
            detail = (
                "All short password attempts were rejected. " + "; ".join(attempts_detail)
            )

        results.append(self._make_result(
            variant="password_min_length",
            status=pwd_status,
            severity=Severity.HIGH,
            evidence="; ".join(attempts_detail),
            details=detail,
        ))

        # ----------------------------------------------------------------
        # 2. Account lockout after 10 failed attempts
        # ----------------------------------------------------------------
        lockout_attempts = 11
        last_status = None
        locked = False
        attempt_results = []
        try:
            for i in range(1, lockout_attempts + 1):
                status_code, body, headers = await client.post(
                    login_ep,
                    json_body={
                        "email": "redteam-lockout@test.com",
                        "password": f"WrongPassword{i}!",
                    },
                    cookies={},
                )
                last_status = status_code
                is_locked = (
                    status_code == 429
                    or "locked" in body.lower()
                    or "too many" in body.lower()
                    or "temporarily" in body.lower()
                )
                attempt_results.append(f"attempt {i}: status={status_code}, locked={is_locked}")
                if is_locked:
                    locked = True
                    break
                # Small delay to avoid self-rate-limiting
                await asyncio.sleep(0.1)

            if locked:
                lockout_status = Status.DEFENDED
                detail = (
                    f"Account locked after {i} failed attempts. "
                    "PCI DSS Req 8.3.4 requires lockout after no more than 10 attempts."
                )
                if i > 10:
                    lockout_status = Status.PARTIAL
                    detail = (
                        f"Account locked after {i} attempts, but PCI DSS requires "
                        "lockout after at most 10 failed attempts."
                    )
            else:
                lockout_status = Status.VULNERABLE
                detail = (
                    f"No account lockout detected after {lockout_attempts} failed attempts. "
                    "PCI DSS Req 8.3.4 requires lockout after no more than 10 attempts."
                )
        except Exception as exc:
            lockout_status = Status.ERROR
            detail = f"Account lockout test failed: {exc}"
            attempt_results = [str(exc)]

        results.append(self._make_result(
            variant="account_lockout",
            status=lockout_status,
            severity=Severity.HIGH,
            evidence="; ".join(attempt_results[-5:]),  # last 5 for brevity
            details=detail,
        ))

        # ----------------------------------------------------------------
        # 3. Session timeout at 15 minutes idle
        # ----------------------------------------------------------------
        try:
            # Authenticate first
            status_code, body, headers = await client.post(
                login_ep,
                json_body={
                    "email": "redteam-viewer@test.com",
                    "password": "RedTeamV!ewer2026!",
                },
                cookies={},
            )

            # Extract session cookie
            session_cookie = None
            header_str = str(headers)
            cookie_match = re.search(r'(?:eqmon_session|PHPSESSID|session_id)=([^;\s]+)', header_str)
            if cookie_match:
                session_cookie = cookie_match.group(0)

            if session_cookie:
                # Check if session config enforces 15-min timeout
                # We cannot actually wait 15 minutes, so check server config
                test_endpoints = self._get_test_endpoints()
                ep = test_endpoints[0] if test_endpoints else "/api/ai_chat.php"
                cookie_name = session_cookie.split("=")[0]
                cookie_val = session_cookie.split("=")[1]

                # Make an authenticated request immediately — should work
                status_code2, body2, _ = await client.get(
                    ep,
                    cookies={cookie_name: cookie_val},
                )
                immediate_ok = status_code2 in (200, 201, 204)

                # Check PHP session config if accessible
                session_maxlife = None
                for php_ini in ["/etc/php/8.3/fpm/php.ini", "/etc/php/8.2/fpm/php.ini",
                                "/etc/php/8.1/fpm/php.ini", "/etc/php/8.0/fpm/php.ini",
                                "/etc/php/7.4/fpm/php.ini"]:
                    try:
                        with open(php_ini, "r") as f:
                            for line in f:
                                if "session.gc_maxlifetime" in line and not line.strip().startswith(";"):
                                    match = re.search(r'=\s*(\d+)', line)
                                    if match:
                                        session_maxlife = int(match.group(1))
                                        break
                    except (FileNotFoundError, PermissionError):
                        continue
                    if session_maxlife is not None:
                        break

                if session_maxlife is not None:
                    if session_maxlife <= 900:  # 15 min = 900 sec
                        timeout_status = Status.DEFENDED
                        detail = (
                            f"Session gc_maxlifetime = {session_maxlife}s "
                            f"({session_maxlife // 60} min), meets PCI 15-min requirement."
                        )
                    else:
                        timeout_status = Status.VULNERABLE
                        detail = (
                            f"Session gc_maxlifetime = {session_maxlife}s "
                            f"({session_maxlife // 60} min), exceeds PCI 15-min idle timeout. "
                            "PCI DSS Req 8.2.8 requires session timeout at 15 minutes."
                        )
                    evidence = f"gc_maxlifetime={session_maxlife}, immediate_auth={immediate_ok}"
                else:
                    timeout_status = Status.PARTIAL
                    detail = (
                        "Could not read PHP session configuration to verify idle timeout. "
                        "Manual verification of 15-minute session timeout required."
                    )
                    evidence = f"php.ini not found, immediate_auth={immediate_ok}"
            else:
                timeout_status = Status.PARTIAL
                detail = "Could not extract session cookie to test timeout behavior."
                evidence = f"Login status: {status_code}"
        except Exception as exc:
            timeout_status = Status.ERROR
            detail = f"Session timeout check failed: {exc}"
            evidence = str(exc)

        results.append(self._make_result(
            variant="session_timeout_15min",
            status=timeout_status,
            severity=Severity.MEDIUM,
            evidence=evidence,
            details=detail,
        ))

        # ----------------------------------------------------------------
        # 4. Shared / generic account detection
        # ----------------------------------------------------------------
        try:
            import psycopg2
            db_pass = os.environ.get("EQMON_AUTH_DB_PASS", "3eK4NNHxLQakuTQK5KcnB3Vz")
            conn = psycopg2.connect(
                host="localhost", dbname="eqmon", user="eqmon", password=db_pass,
            )
            cur = conn.cursor()

            # Look for accounts with generic names
            placeholders = ",".join(["%s"] * len(GENERIC_ACCOUNT_NAMES))
            cur.execute(f"""
                SELECT username, email, is_active, last_login
                FROM users
                WHERE LOWER(username) IN ({placeholders})
                   OR LOWER(email) LIKE ANY(ARRAY[{','.join(["'%%' || %s || '%%'"] * len(GENERIC_ACCOUNT_NAMES))}])
                ORDER BY username;
            """, list(GENERIC_ACCOUNT_NAMES) + list(GENERIC_ACCOUNT_NAMES))
            generic_accounts = cur.fetchall()
            conn.close()

            if generic_accounts:
                active = [a for a in generic_accounts if a[2]]  # is_active
                if active:
                    shared_status = Status.VULNERABLE
                    detail = (
                        f"Found {len(active)} active generic/shared account(s): "
                        f"{[a[0] for a in active]}. "
                        "PCI DSS Req 8.5.1 prohibits shared/generic accounts for CDE access."
                    )
                else:
                    shared_status = Status.PARTIAL
                    detail = (
                        f"Found {len(generic_accounts)} generic account(s) but all are inactive: "
                        f"{[a[0] for a in generic_accounts]}."
                    )
                evidence = f"Generic accounts: {generic_accounts}"
            else:
                shared_status = Status.DEFENDED
                detail = "No generic or shared accounts detected in user database."
                evidence = "Query returned 0 rows"
        except ImportError:
            shared_status = Status.ERROR
            detail = "psycopg2 not installed — cannot query database for shared accounts."
            evidence = "psycopg2 missing"
        except Exception as exc:
            # Table might not exist or different schema — try alternate query
            try:
                conn2 = psycopg2.connect(
                    host="localhost", dbname="eqmon", user="eqmon", password=db_pass,
                )
                cur2 = conn2.cursor()
                cur2.execute("""
                    SELECT column_name FROM information_schema.columns
                    WHERE table_schema = 'public' AND table_name = 'users';
                """)
                cols = [r[0] for r in cur2.fetchall()]
                conn2.close()
                shared_status = Status.ERROR
                detail = f"Users table schema differs from expected. Columns: {cols}. Error: {exc}"
                evidence = f"columns={cols}"
            except Exception:
                shared_status = Status.ERROR
                detail = f"Shared account detection failed: {exc}"
                evidence = str(exc)

        results.append(self._make_result(
            variant="shared_account_detection",
            status=shared_status,
            severity=Severity.HIGH,
            evidence=evidence,
            details=detail,
        ))

        # ----------------------------------------------------------------
        # 5. Hardcoded credentials in config files
        # ----------------------------------------------------------------
        hardcoded_findings: list[str] = []
        files_scanned = 0
        try:
            for scan_dir in CONFIG_SCAN_DIRS:
                if not os.path.isdir(scan_dir):
                    continue
                for dirpath, dirnames, filenames in os.walk(scan_dir):
                    # Skip unwanted directories
                    dirnames[:] = [d for d in dirnames
                                   if not any(s in d for s in SKIP_PATTERNS)]
                    for fname in filenames:
                        ext = os.path.splitext(fname)[1].lower()
                        if ext not in CONFIG_EXTENSIONS:
                            continue
                        fpath = os.path.join(dirpath, fname)
                        try:
                            with open(fpath, "r", errors="ignore") as f:
                                files_scanned += 1
                                for line_no, line in enumerate(f, 1):
                                    if line_no > 5000:  # safety limit
                                        break
                                    for pat in CREDENTIAL_PATTERNS:
                                        if pat.search(line):
                                            # Exclude comments and empty values
                                            stripped = line.strip()
                                            if stripped.startswith("#") or stripped.startswith("//"):
                                                continue
                                            # Exclude known false positive patterns
                                            if any(fp.search(stripped) for fp in CREDENTIAL_FP_PATTERNS):
                                                continue
                                            finding = f"{fpath}:{line_no}: {stripped[:120]}"
                                            hardcoded_findings.append(finding)
                                            if len(hardcoded_findings) >= 50:
                                                break
                                    if len(hardcoded_findings) >= 50:
                                        break
                        except (PermissionError, OSError):
                            continue
                    if len(hardcoded_findings) >= 50:
                        break
                if len(hardcoded_findings) >= 50:
                    break

            if hardcoded_findings:
                cred_status = Status.VULNERABLE
                detail = (
                    f"Found {len(hardcoded_findings)} potential hardcoded credential(s) "
                    f"in {files_scanned} files scanned. "
                    "PCI DSS Req 8.6.2 prohibits hardcoded passwords in scripts/config."
                )
            else:
                cred_status = Status.DEFENDED
                detail = (
                    f"No hardcoded credentials detected in {files_scanned} config files. "
                )
        except Exception as exc:
            cred_status = Status.ERROR
            detail = f"Hardcoded credential scan failed: {exc}"
            hardcoded_findings = [str(exc)]

        results.append(self._make_result(
            variant="hardcoded_credentials",
            status=cred_status,
            severity=Severity.HIGH,
            evidence="\n".join(hardcoded_findings[:10]),  # top 10
            details=detail,
        ))

        # ----------------------------------------------------------------
        # 6. MFA enforcement for all CDE access
        # ----------------------------------------------------------------
        cde_endpoints = self._get_test_endpoints()
        mfa_results: list[str] = []
        mfa_missing = False
        try:
            # Login and check for MFA challenge
            status_code, body, headers = await client.post(
                login_ep,
                json_body={
                    "email": "redteam-viewer@test.com",
                    "password": "RedTeamV!ewer2026!",
                },
                cookies={},
            )

            got_session = status_code == 200
            mfa_prompted = any(kw in body.lower()
                               for kw in ("mfa", "two_factor", "otp", "2fa", "totp"))

            if got_session and not mfa_prompted:
                mfa_missing = True
                mfa_results.append(
                    f"Login succeeded (status {status_code}) without MFA challenge"
                )
            elif mfa_prompted:
                mfa_results.append(f"MFA challenge detected on login (status {status_code})")
            else:
                mfa_results.append(f"Login returned status {status_code}")

            if mfa_missing:
                mfa_status = Status.VULNERABLE
                detail = (
                    "CDE login does not require MFA. PCI DSS 4.0 Req 8.4.2 requires "
                    "MFA for all access into the cardholder data environment."
                )
            else:
                mfa_status = Status.DEFENDED
                detail = "MFA challenge detected for CDE access."
        except Exception as exc:
            mfa_status = Status.ERROR
            detail = f"MFA check failed: {exc}"
            mfa_results = [str(exc)]

        results.append(self._make_result(
            variant="mfa_all_cde_access",
            status=mfa_status,
            severity=Severity.CRITICAL,
            evidence="; ".join(mfa_results),
            details=detail,
        ))

        return results
