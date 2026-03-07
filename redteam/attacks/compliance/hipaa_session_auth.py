"""HIPAA Session & Authentication verification — 45 CFR 164.312(a)(2)(iii) + (d).

Checks whether ePHI applications enforce auto-logoff (session timeout),
require multi-factor authentication, verify service-to-service entity
authentication, and provide emergency break-glass access procedures.
"""

import os
import re
import socket
import ssl
import subprocess
import json

from redteam.base import Attack, AttackResult, Severity, Status


class HIPAASessionAuthAttack(Attack):
    name = "compliance.hipaa_session_auth"
    category = "compliance"
    severity = Severity.HIGH
    description = (
        "HIPAA \u00a7164.312(a)(2)(iii)+(d) \u2014 Verify auto-logoff, MFA, "
        "and entity authentication"
    )

    DB_CONFIG = {
        "host": "localhost",
        "dbname": "eqmon",
        "user": "eqmon",
    }

    # Session timeout thresholds in seconds
    TIMEOUT_GOOD = 15 * 60       # 15 minutes
    TIMEOUT_ACCEPTABLE = 30 * 60  # 30 minutes

    def _get_db_password(self) -> str:
        return os.environ.get("EQMON_AUTH_DB_PASS", "3eK4NNHxLQakuTQK5KcnB3Vz")

    def _run(self, cmd: list[str], timeout: int = 10) -> subprocess.CompletedProcess:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)

    def _http_request(self, host: str, port: int, method: str, path: str,
                      headers: dict | None = None, use_tls: bool = True,
                      timeout: int = 5) -> tuple[str, dict]:
        """Make a raw HTTP request and return (status_line, headers_dict, body)."""
        header_lines = [f"{method} {path} HTTP/1.1", f"Host: {host}"]
        if headers:
            for k, v in headers.items():
                header_lines.append(f"{k}: {v}")
        header_lines.extend(["Connection: close", "", ""])
        raw_request = "\r\n".join(header_lines).encode()

        sock = socket.create_connection((host, port), timeout=timeout)
        try:
            if use_tls:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=host)

            sock.sendall(raw_request)
            response = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
                if len(response) > 32768:
                    break
        finally:
            sock.close()

        resp_text = response.decode(errors="replace")
        parts = resp_text.split("\r\n\r\n", 1)
        header_section = parts[0]
        body = parts[1] if len(parts) > 1 else ""

        lines = header_section.split("\r\n")
        status_line = lines[0] if lines else ""
        resp_headers: dict[str, str] = {}
        for line in lines[1:]:
            if ": " in line:
                k, v = line.split(": ", 1)
                resp_headers[k.lower()] = v

        return status_line, resp_headers, body

    # ------------------------------------------------------------------
    # Variant 1: Auto-logoff / session timeout
    # ------------------------------------------------------------------

    async def _check_auto_logoff(self) -> AttackResult:
        evidence_parts: list[str] = []
        timeout_seconds: int | None = None

        # 1a. Check PHP session.gc_maxlifetime
        php_ini_paths = [
            "/etc/php/8.3/apache2/php.ini",
            "/etc/php/8.2/apache2/php.ini",
            "/etc/php/8.1/apache2/php.ini",
            "/etc/php/8.0/apache2/php.ini",
            "/etc/php/7.4/apache2/php.ini",
            "/etc/php/8.3/fpm/php.ini",
            "/etc/php/8.2/fpm/php.ini",
            "/etc/php/8.1/fpm/php.ini",
        ]

        for ini_path in php_ini_paths:
            try:
                if not os.path.isfile(ini_path):
                    continue
                with open(ini_path, "r", errors="replace") as f:
                    content = f.read()

                gc_match = re.search(
                    r"^\s*session\.gc_maxlifetime\s*=\s*(\d+)",
                    content, re.MULTILINE,
                )
                if gc_match:
                    gc_lifetime = int(gc_match.group(1))
                    timeout_seconds = gc_lifetime
                    evidence_parts.append(
                        f"PHP session.gc_maxlifetime = {gc_lifetime}s "
                        f"({gc_lifetime // 60} min) in {ini_path}"
                    )

                cookie_lifetime_match = re.search(
                    r"^\s*session\.cookie_lifetime\s*=\s*(\d+)",
                    content, re.MULTILINE,
                )
                if cookie_lifetime_match:
                    cookie_lt = int(cookie_lifetime_match.group(1))
                    evidence_parts.append(
                        f"PHP session.cookie_lifetime = {cookie_lt}s in {ini_path}"
                    )
                break
            except PermissionError:
                evidence_parts.append(f"{ini_path}: permission denied")
            except Exception:
                pass

        # 1b. Check application-level session config files
        app_config_dirs = [
            "/var/www/html/eqmon",
            "/var/www/html",
            "/opt/eqmon",
        ]

        for config_dir in app_config_dirs:
            if not os.path.isdir(config_dir):
                continue
            for root, dirs, files in os.walk(config_dir):
                depth = root.replace(config_dir, "").count(os.sep)
                if depth > 3:
                    dirs.clear()
                    continue
                dirs[:] = [
                    d for d in dirs
                    if d not in ("node_modules", ".git", "vendor", "__pycache__")
                ]
                for f in files:
                    if f in ("config.php", "settings.php", "session.php",
                             ".env", "config.json", "config.yaml", "config.yml",
                             "app.config.js", "app.config.ts"):
                        fpath = os.path.join(root, f)
                        try:
                            with open(fpath, "r", errors="replace") as fh:
                                content = fh.read(4096)
                            # Look for session timeout settings
                            timeout_match = re.search(
                                r"(?:session[_.]?timeout|idle[_.]?timeout|max[_.]?lifetime|"
                                r"SESSION_TIMEOUT|IDLE_TIMEOUT)\s*[=:]\s*['\"]?(\d+)",
                                content, re.IGNORECASE,
                            )
                            if timeout_match:
                                val = int(timeout_match.group(1))
                                # Heuristic: values > 3600 are likely in seconds,
                                # values < 120 are likely in minutes
                                if val < 120:
                                    val_seconds = val * 60
                                else:
                                    val_seconds = val
                                timeout_seconds = val_seconds
                                evidence_parts.append(
                                    f"Session timeout = {val} "
                                    f"(~{val_seconds // 60} min) in {fpath}"
                                )
                        except (PermissionError, OSError):
                            pass

        # 1c. Try to check actual cookie behavior from a login endpoint
        base_url = self._config.get("target", {}).get("base_url", "https://localhost")
        host = base_url.replace("https://", "").replace("http://", "").split(":")[0].split("/")[0]
        port = 443
        try:
            port_str = base_url.split(":")[-1].split("/")[0]
            if port_str.isdigit():
                port = int(port_str)
        except Exception:
            pass

        try:
            login_endpoint = self._get_login_endpoint()
            status_line, resp_headers, body = self._http_request(
                host, port, "GET", login_endpoint,
            )
            set_cookie = resp_headers.get("set-cookie", "")
            if set_cookie:
                evidence_parts.append(f"Set-Cookie from {login_endpoint}: {set_cookie[:200]}")
                # Check for Max-Age or Expires
                max_age_match = re.search(r"Max-Age=(\d+)", set_cookie, re.IGNORECASE)
                expires_match = re.search(r"Expires=([^;]+)", set_cookie, re.IGNORECASE)
                if max_age_match:
                    cookie_max_age = int(max_age_match.group(1))
                    evidence_parts.append(f"Cookie Max-Age: {cookie_max_age}s ({cookie_max_age // 60} min)")
                    if timeout_seconds is None:
                        timeout_seconds = cookie_max_age
                if expires_match:
                    evidence_parts.append(f"Cookie Expires: {expires_match.group(1)}")
        except Exception as exc:
            evidence_parts.append(f"Cookie check failed: {exc}")

        # Determine status
        if timeout_seconds is None:
            status = Status.PARTIAL
            details = (
                "Could not determine session timeout configuration. "
                "No PHP session settings, application config, or cookie Max-Age found. "
                "HIPAA 164.312(a)(2)(iii) requires automatic logoff after inactivity."
            )
        elif timeout_seconds <= self.TIMEOUT_GOOD:
            status = Status.DEFENDED
            details = (
                f"Session timeout is {timeout_seconds // 60} minutes, which meets "
                f"HIPAA auto-logoff requirements (recommended <= 15 min for ePHI)."
            )
        elif timeout_seconds <= self.TIMEOUT_ACCEPTABLE:
            status = Status.PARTIAL
            details = (
                f"Session timeout is {timeout_seconds // 60} minutes. While functional, "
                f"HIPAA best practice recommends <= 15 minutes for ePHI systems. "
                f"Current setting is acceptable but not ideal."
            )
        else:
            status = Status.VULNERABLE
            details = (
                f"Session timeout is {timeout_seconds // 60} minutes (> 30 min). "
                f"HIPAA 164.312(a)(2)(iii) requires auto-logoff to prevent unauthorized "
                f"access to unattended sessions. Reduce to 15 minutes or less."
            )

        return self._make_result(
            variant="auto_logoff",
            status=status,
            severity=Severity.HIGH,
            evidence="; ".join(evidence_parts),
            details=details,
        )

    # ------------------------------------------------------------------
    # Variant 2: MFA for ePHI access
    # ------------------------------------------------------------------

    async def _check_mfa_ephi_access(self, conn) -> AttackResult:
        cur = conn.cursor()
        evidence_parts: list[str] = []
        mfa_indicators: list[str] = []

        # 2a. Check database for MFA-related tables or columns
        mfa_table_names = [
            "mfa", "totp", "two_factor", "2fa", "otp", "webauthn",
            "user_mfa", "auth_factors", "mfa_devices", "security_keys",
        ]

        for table in mfa_table_names:
            try:
                cur.execute(f"""
                    SELECT EXISTS(
                        SELECT 1 FROM information_schema.tables
                        WHERE table_schema = 'public' AND table_name = '{table}'
                    );
                """)
                if cur.fetchone()[0]:
                    mfa_indicators.append(f"MFA table found: {table}")
            except Exception:
                conn.rollback()

        # Check for MFA columns in user tables
        user_tables = ["users", "accounts", "app_users"]
        for table in user_tables:
            try:
                cur.execute(f"""
                    SELECT column_name FROM information_schema.columns
                    WHERE table_schema = 'public' AND table_name = '{table}'
                      AND (
                        column_name LIKE '%mfa%'
                        OR column_name LIKE '%totp%'
                        OR column_name LIKE '%two_factor%'
                        OR column_name LIKE '%otp%'
                        OR column_name LIKE '%2fa%'
                        OR column_name LIKE '%webauthn%'
                      );
                """)
                mfa_cols = cur.fetchall()
                if mfa_cols:
                    mfa_indicators.append(
                        f"MFA columns in {table}: {[c[0] for c in mfa_cols]}"
                    )
            except Exception:
                conn.rollback()

        evidence_parts.append(f"DB MFA indicators: {mfa_indicators if mfa_indicators else 'none'}")

        # 2b. Check for TOTP/WebAuthn libraries in application code
        app_dirs = ["/var/www/html", "/opt"]
        mfa_libs_found: list[str] = []

        for app_dir in app_dirs:
            if not os.path.isdir(app_dir):
                continue
            # Check PHP composer.json for MFA packages
            for root, dirs, files in os.walk(app_dir):
                depth = root.replace(app_dir, "").count(os.sep)
                if depth > 3:
                    dirs.clear()
                    continue
                dirs[:] = [
                    d for d in dirs
                    if d not in ("node_modules", ".git", "vendor", "__pycache__")
                ]
                for f in files:
                    if f in ("composer.json", "package.json", "requirements.txt",
                             "Gemfile", "go.mod", "Cargo.toml"):
                        fpath = os.path.join(root, f)
                        try:
                            with open(fpath, "r", errors="replace") as fh:
                                content = fh.read(8192)
                            mfa_keywords = [
                                "totp", "otp", "mfa", "two-factor", "2fa",
                                "webauthn", "fido", "google-authenticator",
                                "authy", "speakeasy", "pyotp",
                            ]
                            for kw in mfa_keywords:
                                if kw in content.lower():
                                    mfa_libs_found.append(f"{kw} in {fpath}")
                        except (PermissionError, OSError):
                            pass

        evidence_parts.append(f"MFA libraries: {mfa_libs_found if mfa_libs_found else 'none'}")

        # 2c. Attempt unauthenticated login to check for MFA challenge
        base_url = self._config.get("target", {}).get("base_url", "https://localhost")
        host = base_url.replace("https://", "").replace("http://", "").split(":")[0].split("/")[0]
        port = 443
        try:
            port_str = base_url.split(":")[-1].split("/")[0]
            if port_str.isdigit():
                port = int(port_str)
        except Exception:
            pass

        login_response_has_mfa = False
        try:
            login_endpoint = self._get_login_endpoint()
            _status, _headers, body = self._http_request(
                host, port, "GET", login_endpoint,
            )
            body_lower = body.lower()
            mfa_page_indicators = [
                "two-factor", "2fa", "mfa", "totp", "authenticator",
                "verification code", "security code", "one-time",
            ]
            for indicator in mfa_page_indicators:
                if indicator in body_lower:
                    login_response_has_mfa = True
                    mfa_indicators.append(f"MFA indicator in login page: '{indicator}'")
                    break
            evidence_parts.append(f"Login page MFA indicators: {login_response_has_mfa}")
        except Exception as exc:
            evidence_parts.append(f"Login page check failed: {exc}")

        # 2d. Check for MFA middleware / PAM modules
        pam_mfa = False
        try:
            pam_dir = "/etc/pam.d"
            if os.path.isdir(pam_dir):
                for f in os.listdir(pam_dir):
                    fpath = os.path.join(pam_dir, f)
                    try:
                        with open(fpath, "r", errors="replace") as fh:
                            content = fh.read()
                        if "pam_google_authenticator" in content or "pam_oath" in content:
                            pam_mfa = True
                            mfa_indicators.append(f"PAM MFA module in {fpath}")
                    except (PermissionError, OSError):
                        pass
        except Exception:
            pass

        # Determine status
        has_mfa_infra = bool(mfa_indicators)
        mandatory_mfa = len(mfa_indicators) >= 2  # Multiple indicators suggest enforced MFA

        if mandatory_mfa:
            status = Status.DEFENDED
            details = (
                f"MFA infrastructure detected with multiple indicators: "
                f"{mfa_indicators[:5]}. Multi-factor authentication appears to be "
                "enforced for ePHI access."
            )
        elif has_mfa_infra:
            status = Status.PARTIAL
            details = (
                f"MFA infrastructure partially detected: {mfa_indicators[:5]}. "
                "MFA may be optional or not fully enforced. HIPAA requires MFA "
                "for all ePHI access points."
            )
        else:
            status = Status.VULNERABLE
            details = (
                "No MFA infrastructure detected. No MFA tables, libraries, PAM modules, "
                "or login page MFA indicators found. HIPAA 164.312(d) requires entity "
                "authentication mechanisms including MFA for ePHI access."
            )

        return self._make_result(
            variant="mfa_ephi_access",
            status=status,
            severity=Severity.HIGH,
            evidence="; ".join(evidence_parts),
            details=details,
        )

    # ------------------------------------------------------------------
    # Variant 3: Entity (service-to-service) authentication
    # ------------------------------------------------------------------

    async def _check_entity_authentication(self) -> AttackResult:
        evidence_parts: list[str] = []
        unauthenticated_endpoints: list[str] = []
        authenticated_endpoints: list[str] = []

        base_url = self._config.get("target", {}).get("base_url", "https://localhost")
        host = base_url.replace("https://", "").replace("http://", "").split(":")[0].split("/")[0]
        port = 443
        try:
            port_str = base_url.split(":")[-1].split("/")[0]
            if port_str.isdigit():
                port = int(port_str)
        except Exception:
            pass

        # 3a. Try unauthenticated API calls to known endpoints
        test_endpoints = self._get_test_endpoints()
        api_paths = list(test_endpoints) + [
            "/api/", "/api/v1/", "/api/health", "/api/status",
            "/api/patients", "/api/records", "/api/data",
        ]

        for path in api_paths:
            try:
                status_line, headers, body = self._http_request(
                    host, port, "GET", path,
                )
                status_code = ""
                if status_line:
                    parts = status_line.split(" ", 2)
                    status_code = parts[1] if len(parts) > 1 else ""

                if status_code in ("200", "201"):
                    # Check if this returns actual data (not just a public page)
                    content_type = headers.get("content-type", "")
                    if "json" in content_type or "api" in path.lower():
                        unauthenticated_endpoints.append(
                            f"{path} (HTTP {status_code}, {content_type})"
                        )
                    else:
                        evidence_parts.append(
                            f"{path}: HTTP {status_code} but not API content type"
                        )
                elif status_code in ("401", "403"):
                    authenticated_endpoints.append(f"{path} (HTTP {status_code})")
                elif status_code in ("301", "302"):
                    location = headers.get("location", "")
                    if "login" in location.lower() or "auth" in location.lower():
                        authenticated_endpoints.append(
                            f"{path} (redirects to auth: {location})"
                        )
                    else:
                        evidence_parts.append(f"{path}: redirect to {location}")
                else:
                    evidence_parts.append(f"{path}: HTTP {status_code}")
            except Exception as exc:
                evidence_parts.append(f"{path}: connection failed ({exc})")

        evidence_parts.append(f"Unauthenticated API endpoints: {len(unauthenticated_endpoints)}")
        evidence_parts.append(f"Authenticated API endpoints: {len(authenticated_endpoints)}")

        # 3b. Check nginx/apache configs for auth requirements on API routes
        web_configs = [
            "/etc/nginx/sites-available/",
            "/etc/nginx/sites-enabled/",
            "/etc/nginx/conf.d/",
            "/etc/apache2/sites-available/",
            "/etc/apache2/sites-enabled/",
        ]

        for config_dir in web_configs:
            try:
                if not os.path.isdir(config_dir):
                    continue
                for f in os.listdir(config_dir):
                    fpath = os.path.join(config_dir, f)
                    if not os.path.isfile(fpath):
                        continue
                    with open(fpath, "r", errors="replace") as fh:
                        content = fh.read()

                    # Check for API locations without auth
                    api_location_blocks = re.findall(
                        r"location\s+[~*]*\s*/api[^{]*\{([^}]+)\}",
                        content, re.DOTALL,
                    )
                    for block in api_location_blocks:
                        if "auth_basic" not in block and "auth_request" not in block:
                            evidence_parts.append(
                                f"{fpath}: API location without nginx auth module"
                            )
                        else:
                            evidence_parts.append(
                                f"{fpath}: API location has auth configured"
                            )

                    # Check for mTLS configuration
                    if "ssl_client_certificate" in content or "ssl_verify_client" in content:
                        authenticated_endpoints.append(f"mTLS configured in {fpath}")
                        evidence_parts.append(f"mTLS configuration found in {fpath}")

                    # Check for API key proxy headers
                    if "proxy_set_header" in content and ("X-API-Key" in content or "Authorization" in content):
                        evidence_parts.append(f"Auth header forwarding in {fpath}")
            except PermissionError:
                evidence_parts.append(f"{config_dir}: permission denied")
            except Exception:
                pass

        # 3c. Check for JWT/OAuth configuration files
        auth_config_indicators: list[str] = []
        for config_dir in ["/var/www/html", "/opt"]:
            if not os.path.isdir(config_dir):
                continue
            for root, dirs, files in os.walk(config_dir):
                depth = root.replace(config_dir, "").count(os.sep)
                if depth > 3:
                    dirs.clear()
                    continue
                dirs[:] = [
                    d for d in dirs
                    if d not in ("node_modules", ".git", "vendor", "__pycache__")
                ]
                for f in files:
                    if f in (".env", "config.php", "auth.php", "jwt.php",
                             "oauth.php", "auth.config.js", "auth.config.ts"):
                        fpath = os.path.join(root, f)
                        try:
                            with open(fpath, "r", errors="replace") as fh:
                                content = fh.read(4096)
                            jwt_keywords = ["jwt", "oauth", "bearer", "api_key", "api-key"]
                            for kw in jwt_keywords:
                                if kw in content.lower():
                                    auth_config_indicators.append(f"{kw} in {fpath}")
                                    break
                        except (PermissionError, OSError):
                            pass

        if auth_config_indicators:
            evidence_parts.append(f"Auth config indicators: {auth_config_indicators[:5]}")

        # Determine status
        if unauthenticated_endpoints:
            status = Status.VULNERABLE
            details = (
                f"Found {len(unauthenticated_endpoints)} API endpoint(s) accessible "
                f"without authentication: {unauthenticated_endpoints[:5]}. "
                "HIPAA 164.312(d) requires entity authentication for all ePHI access."
            )
        elif authenticated_endpoints:
            status = Status.DEFENDED
            details = (
                f"All {len(authenticated_endpoints)} tested API endpoint(s) require "
                f"authentication. Service authentication appears properly configured."
            )
        else:
            status = Status.PARTIAL
            details = (
                "Could not definitively verify API authentication. No clear "
                "authenticated or unauthenticated responses received. "
                "Manual verification recommended."
            )

        return self._make_result(
            variant="entity_authentication",
            status=status,
            severity=Severity.HIGH,
            evidence="; ".join(evidence_parts),
            details=details,
        )

    # ------------------------------------------------------------------
    # Variant 4: Emergency access (break-glass) procedure
    # ------------------------------------------------------------------

    async def _check_emergency_access(self, conn) -> AttackResult:
        cur = conn.cursor()
        evidence_parts: list[str] = []
        has_mechanism = False
        has_audit_trail = False

        # 4a. Check for emergency/break-glass accounts in database
        emergency_keywords = [
            "break_glass", "breakglass", "emergency", "urgent_access",
            "override", "bypass", "escalation",
        ]

        # Check user tables for emergency accounts
        user_tables = ["users", "accounts", "app_users"]
        for table in user_tables:
            try:
                cur.execute(f"""
                    SELECT EXISTS(
                        SELECT 1 FROM information_schema.tables
                        WHERE table_schema = 'public' AND table_name = '{table}'
                    );
                """)
                if not cur.fetchone()[0]:
                    continue

                # Get username column
                cur.execute(f"""
                    SELECT column_name FROM information_schema.columns
                    WHERE table_schema = 'public' AND table_name = '{table}'
                      AND column_name IN ('username', 'login', 'email', 'name', 'role', 'account_type')
                    ORDER BY column_name;
                """)
                cols = [row[0] for row in cur.fetchall()]

                for col in cols:
                    conditions = " OR ".join(
                        f"LOWER({col}) LIKE '%{kw}%'" for kw in emergency_keywords
                    )
                    try:
                        cur.execute(f"SELECT {col} FROM {table} WHERE {conditions};")
                        matches = cur.fetchall()
                        if matches:
                            has_mechanism = True
                            evidence_parts.append(
                                f"Emergency accounts in {table}.{col}: "
                                f"{[m[0] for m in matches]}"
                            )
                    except Exception:
                        conn.rollback()
            except Exception:
                conn.rollback()

        # Check for emergency_access or break_glass table
        for kw in emergency_keywords:
            try:
                cur.execute(f"""
                    SELECT table_name FROM information_schema.tables
                    WHERE table_schema = 'public'
                      AND table_name LIKE '%{kw}%';
                """)
                tables = cur.fetchall()
                if tables:
                    has_mechanism = True
                    evidence_parts.append(f"Emergency tables: {[t[0] for t in tables]}")
            except Exception:
                conn.rollback()

        # 4b. Check for emergency access documentation
        doc_paths = [
            "/var/www/html/docs",
            "/opt/docs",
            "/opt/eqmon/docs",
            "/var/www/html/eqmon/docs",
        ]
        doc_keywords = ["emergency", "break-glass", "break_glass", "disaster", "contingency"]

        for doc_dir in doc_paths:
            try:
                if not os.path.isdir(doc_dir):
                    continue
                for root, dirs, files in os.walk(doc_dir):
                    depth = root.replace(doc_dir, "").count(os.sep)
                    if depth > 2:
                        dirs.clear()
                        continue
                    for f in files:
                        f_lower = f.lower()
                        if any(kw in f_lower for kw in doc_keywords):
                            has_mechanism = True
                            evidence_parts.append(f"Emergency doc: {os.path.join(root, f)}")
            except Exception:
                pass

        # 4c. Check for emergency access audit trail
        # Look for separate audit logging of emergency access
        audit_tables = [
            "emergency_access_log", "break_glass_log", "emergency_audit",
            "privileged_access_log",
        ]
        for table in audit_tables:
            try:
                cur.execute(f"""
                    SELECT EXISTS(
                        SELECT 1 FROM information_schema.tables
                        WHERE table_schema = 'public' AND table_name = '{table}'
                    );
                """)
                if cur.fetchone()[0]:
                    has_audit_trail = True
                    evidence_parts.append(f"Emergency audit table found: {table}")

                    # Check for entries
                    try:
                        cur.execute(f"SELECT COUNT(*) FROM {table};")
                        count = cur.fetchone()[0]
                        evidence_parts.append(f"  entries: {count}")
                    except Exception:
                        conn.rollback()
            except Exception:
                conn.rollback()

        # Also check general audit tables for emergency access events
        general_audit = [
            ("blueteam", "audit_events"),
            ("public", "audit_log"),
            ("public", "audit_events"),
        ]
        for schema, table in general_audit:
            try:
                cur.execute(f"""
                    SELECT EXISTS(
                        SELECT 1 FROM information_schema.tables
                        WHERE table_schema = '{schema}' AND table_name = '{table}'
                    );
                """)
                if not cur.fetchone()[0]:
                    continue

                # Check for emergency-related event types
                for event_col in ("event_type", "action", "type", "category"):
                    try:
                        cur.execute(f"""
                            SELECT column_name FROM information_schema.columns
                            WHERE table_schema = '{schema}' AND table_name = '{table}'
                              AND column_name = '{event_col}';
                        """)
                        if cur.fetchone():
                            conditions = " OR ".join(
                                f"LOWER({event_col}) LIKE '%{kw}%'"
                                for kw in emergency_keywords
                            )
                            cur.execute(f"""
                                SELECT COUNT(*) FROM {schema}.{table}
                                WHERE {conditions};
                            """)
                            count = cur.fetchone()[0]
                            if count > 0:
                                has_audit_trail = True
                                evidence_parts.append(
                                    f"Emergency events in {schema}.{table}: {count}"
                                )
                            break
                    except Exception:
                        conn.rollback()
                        continue
            except Exception:
                conn.rollback()

        # 4d. Check application code for break-glass patterns
        for app_dir in ["/var/www/html", "/opt"]:
            if not os.path.isdir(app_dir):
                continue
            for root, dirs, files in os.walk(app_dir):
                depth = root.replace(app_dir, "").count(os.sep)
                if depth > 3:
                    dirs.clear()
                    continue
                dirs[:] = [
                    d for d in dirs
                    if d not in ("node_modules", ".git", "vendor", "__pycache__", ".cache")
                ]
                for f in files:
                    if f.endswith((".php", ".py", ".js", ".ts", ".rb")):
                        fpath = os.path.join(root, f)
                        try:
                            with open(fpath, "r", errors="replace") as fh:
                                content = fh.read(8192)
                            content_lower = content.lower()
                            if any(kw in content_lower for kw in ("break_glass", "breakglass", "emergency_access")):
                                has_mechanism = True
                                evidence_parts.append(f"Emergency access code in {fpath}")
                        except (PermissionError, OSError):
                            pass

        # Determine status
        if has_mechanism and has_audit_trail:
            status = Status.DEFENDED
            details = (
                "Emergency access (break-glass) mechanism detected with audit trail. "
                "HIPAA 164.312(a)(2)(ii) emergency access procedure is in place."
            )
        elif has_mechanism:
            status = Status.PARTIAL
            details = (
                "Emergency access mechanism detected but no dedicated audit trail "
                "for emergency access events. HIPAA requires that all emergency "
                "access be logged and reviewed."
            )
        else:
            status = Status.VULNERABLE
            details = (
                "No emergency access (break-glass) mechanism detected. No emergency "
                "accounts, documentation, or code patterns found. HIPAA 164.312(a)(2)(ii) "
                "requires an emergency access procedure for obtaining ePHI during "
                "emergencies."
            )

        return self._make_result(
            variant="emergency_access_procedure",
            status=status,
            severity=Severity.MEDIUM,
            evidence="; ".join(evidence_parts),
            details=details,
        )

    # ------------------------------------------------------------------
    # Main execute
    # ------------------------------------------------------------------

    async def execute(self, client) -> list[AttackResult]:
        results: list[AttackResult] = []

        # Variant 1: Auto-logoff (no DB needed)
        try:
            results.append(await self._check_auto_logoff())
        except Exception as exc:
            results.append(self._make_result(
                variant="auto_logoff",
                status=Status.ERROR,
                evidence=f"Check failed: {exc}",
                details="Could not verify session timeout configuration.",
            ))

        # Variants 2, 4 need DB; Variant 3 does not
        conn = None
        try:
            import psycopg2
            conn = psycopg2.connect(
                host=self.DB_CONFIG["host"],
                dbname=self.DB_CONFIG["dbname"],
                user=self.DB_CONFIG["user"],
                password=self._get_db_password(),
            )

            # Variant 2: MFA for ePHI access
            try:
                results.append(await self._check_mfa_ephi_access(conn))
            except Exception as exc:
                results.append(self._make_result(
                    variant="mfa_ephi_access",
                    status=Status.ERROR,
                    evidence=f"Check failed: {exc}",
                    details="Could not verify MFA for ePHI access.",
                ))

            # Variant 4: Emergency access procedure
            try:
                results.append(await self._check_emergency_access(conn))
            except Exception as exc:
                results.append(self._make_result(
                    variant="emergency_access_procedure",
                    status=Status.ERROR,
                    evidence=f"Check failed: {exc}",
                    details="Could not verify emergency access procedure.",
                ))

        except ImportError:
            results.append(self._make_result(
                variant="mfa_ephi_access",
                status=Status.ERROR,
                evidence="psycopg2 not installed.",
                details="Install psycopg2-binary for MFA and emergency access checks.",
            ))
        except Exception as exc:
            results.append(self._make_result(
                variant="mfa_ephi_access",
                status=Status.ERROR,
                evidence=f"Database connection failed: {exc}",
                details="Could not connect to database for auth checks.",
            ))
        finally:
            if conn:
                conn.close()

        # Variant 3: Entity authentication (no DB needed)
        try:
            results.append(await self._check_entity_authentication())
        except Exception as exc:
            results.append(self._make_result(
                variant="entity_authentication",
                status=Status.ERROR,
                evidence=f"Check failed: {exc}",
                details="Could not verify service-to-service authentication.",
            ))

        return results
