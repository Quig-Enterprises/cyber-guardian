"""HIPAA ePHI Encryption verification — 45 CFR 164.312(a)(2)(iv) + (e)(2)(ii).

Checks whether electronic Protected Health Information (ePHI) is encrypted
at rest (database column-level and disk encryption), in transit (TLS 1.2+),
in backups, and whether encryption keys are properly managed.
"""

import os
import re
import ssl
import socket
import subprocess

from redteam.base import Attack, AttackResult, Severity, Status


class HIPAAEncryptionAttack(Attack):
    name = "compliance.hipaa_encryption"
    category = "compliance"
    severity = Severity.CRITICAL
    description = (
        "HIPAA \u00a7164.312(a)(2)(iv)+(e)(2)(ii) \u2014 Verify ePHI encryption "
        "at rest and in transit"
    )

    DB_CONFIG = {
        "host": "localhost",
        "dbname": "eqmon",
        "user": "eqmon",
    }

    # Tables likely to hold ePHI or health-related data
    HEALTH_TABLES = (
        "patients", "patient_records", "health_data", "medical_records",
        "diagnoses", "prescriptions", "lab_results", "encounters",
        "claims", "insurance", "phi_data", "clinical_notes",
        "bearing_data", "bearing_measurements", "devices", "vessels",
        "analysis_results", "ai_chat_messages",
    )

    BACKUP_DIRS = [
        "/var/backups", "/backup", "/opt/backup", "/opt/backups",
        "/opt/eqmon/backups", "/home/backup",
    ]

    KEY_EXTENSIONS = ("*.key", "*.pem", "*.p12", "*.pfx", "*.jks", "*.keystore")

    def _get_db_password(self) -> str:
        return os.environ.get("EQMON_AUTH_DB_PASS", "3eK4NNHxLQakuTQK5KcnB3Vz")

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _run(self, cmd: list[str], timeout: int = 10) -> subprocess.CompletedProcess:
        """Run a subprocess and return the result, swallowing errors."""
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)

    # ------------------------------------------------------------------
    # Variant 1: ePHI encryption at rest
    # ------------------------------------------------------------------

    async def _check_encryption_at_rest(self, conn) -> AttackResult:
        cur = conn.cursor()
        evidence_parts: list[str] = []
        has_column_encryption = False
        has_disk_encryption = False

        # 1a. Check pgcrypto extension
        cur.execute(
            "SELECT EXISTS(SELECT 1 FROM pg_extension WHERE extname = 'pgcrypto');"
        )
        pgcrypto_installed = cur.fetchone()[0]
        evidence_parts.append(f"pgcrypto installed: {pgcrypto_installed}")

        # 1b. Check for bytea columns in health/patient tables
        table_list = ", ".join(f"'{t}'" for t in self.HEALTH_TABLES)
        cur.execute(f"""
            SELECT table_name, column_name, data_type
            FROM information_schema.columns
            WHERE table_schema = 'public'
              AND table_name IN ({table_list})
              AND data_type = 'bytea'
            ORDER BY table_name, column_name;
        """)
        encrypted_cols = cur.fetchall()
        evidence_parts.append(
            f"bytea columns: {[f'{t}.{c}' for t, c, _ in encrypted_cols] if encrypted_cols else 'none'}"
        )

        if pgcrypto_installed and encrypted_cols:
            has_column_encryption = True

        # 1c. Check PostgreSQL data_directory for encryption indicators
        try:
            cur.execute("SHOW data_directory;")
            data_dir = cur.fetchone()[0]
            evidence_parts.append(f"data_directory: {data_dir}")
        except Exception:
            data_dir = "/var/lib/postgresql"

        # 1d. Check disk-level encryption (LUKS / dm-crypt)
        try:
            result = self._run(["lsblk", "-o", "NAME,FSTYPE,MOUNTPOINT,TYPE"])
            lsblk_output = result.stdout
            evidence_parts.append(f"lsblk output snippet: {lsblk_output[:300]}")

            if "crypt" in lsblk_output.lower() or "luks" in lsblk_output.lower():
                has_disk_encryption = True
                evidence_parts.append("disk encryption: LUKS/dm-crypt detected")
            else:
                evidence_parts.append("disk encryption: none detected")
        except Exception as exc:
            evidence_parts.append(f"lsblk check failed: {exc}")

        # Also check dmsetup
        try:
            dm_result = self._run(["dmsetup", "table", "--target", "crypt"])
            if dm_result.returncode == 0 and dm_result.stdout.strip():
                has_disk_encryption = True
                evidence_parts.append("dmsetup: crypt targets found")
        except Exception:
            pass

        # Determine status
        if has_column_encryption:
            status = Status.DEFENDED
            details = (
                f"Column-level encryption active. pgcrypto installed, "
                f"{len(encrypted_cols)} bytea column(s) found in ePHI tables. "
                f"Disk encryption: {'yes' if has_disk_encryption else 'no'}."
            )
        elif has_disk_encryption:
            status = Status.PARTIAL
            details = (
                "Disk-level encryption (LUKS/dm-crypt) detected but no column-level "
                "encryption in ePHI tables. HIPAA recommends defense-in-depth with "
                "both disk and application-layer encryption for ePHI."
            )
        else:
            status = Status.VULNERABLE
            details = (
                "No encryption at rest detected. pgcrypto not installed, no bytea "
                "columns in ePHI tables, and no disk encryption (LUKS/dm-crypt). "
                "ePHI is stored in plaintext, violating HIPAA 164.312(a)(2)(iv)."
            )

        return self._make_result(
            variant="ephi_encryption_at_rest",
            status=status,
            severity=Severity.CRITICAL,
            evidence="; ".join(evidence_parts),
            details=details,
        )

    # ------------------------------------------------------------------
    # Variant 2: ePHI encryption in transit
    # ------------------------------------------------------------------

    async def _check_encryption_in_transit(self) -> AttackResult:
        evidence_parts: list[str] = []
        endpoints = self._get_test_endpoints()
        base_url = self._config.get("target", {}).get("base_url", "https://localhost")

        # Parse host from base_url
        host = base_url.replace("https://", "").replace("http://", "").split(":")[0].split("/")[0]
        port = 443
        try:
            port_str = base_url.split(":")[-1].split("/")[0]
            if port_str.isdigit():
                port = int(port_str)
        except Exception:
            pass

        any_http = False
        any_weak_tls = False
        all_good = True
        tested = 0

        for endpoint in endpoints:
            tested += 1
            # Try TLS connection
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE  # We just care about protocol version

                with socket.create_connection((host, port), timeout=5) as sock:
                    with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                        protocol_version = ssock.version()
                        cipher = ssock.cipher()
                        cert = ssock.getpeercert(binary_form=True)

                        evidence_parts.append(
                            f"{endpoint}: TLS={protocol_version}, cipher={cipher[0] if cipher else 'unknown'}"
                        )

                        # Check TLS version
                        if protocol_version and protocol_version in ("TLSv1", "SSLv3", "SSLv2", "TLSv1.1"):
                            any_weak_tls = True
                            all_good = False
                            evidence_parts.append(f"  WEAK TLS: {protocol_version}")
                        elif protocol_version and protocol_version in ("TLSv1.2", "TLSv1.3"):
                            pass  # Good
                        else:
                            any_weak_tls = True
                            all_good = False

                        # Check cert validity (basic)
                        if not cert:
                            evidence_parts.append(f"  WARNING: No certificate presented")
                            all_good = False

            except ssl.SSLError as e:
                evidence_parts.append(f"{endpoint}: SSL error — {e}")
                all_good = False
            except (socket.timeout, ConnectionRefusedError, OSError) as e:
                evidence_parts.append(f"{endpoint}: Connection failed — {e}")
                # Try plain HTTP to see if that works
                try:
                    with socket.create_connection((host, 80), timeout=3) as plain_sock:
                        plain_sock.sendall(
                            f"HEAD {endpoint} HTTP/1.1\r\nHost: {host}\r\n\r\n".encode()
                        )
                        resp = plain_sock.recv(256).decode(errors="replace")
                        if "HTTP/" in resp:
                            any_http = True
                            all_good = False
                            evidence_parts.append(f"  PLAIN HTTP accessible on port 80")
                except Exception:
                    pass

        # Also check if port 80 redirects or serves content
        try:
            with socket.create_connection((host, 80), timeout=3) as sock:
                sock.sendall(f"HEAD / HTTP/1.1\r\nHost: {host}\r\n\r\n".encode())
                resp = sock.recv(512).decode(errors="replace")
                if "HTTP/" in resp:
                    if "301" in resp or "302" in resp:
                        evidence_parts.append("Port 80: redirects (likely to HTTPS)")
                    else:
                        any_http = True
                        evidence_parts.append("Port 80: serves content without redirect to HTTPS")
        except Exception:
            evidence_parts.append("Port 80: not accessible (good)")

        if any_http:
            status = Status.VULNERABLE
            details = (
                "Plain HTTP endpoints detected serving ePHI content without TLS. "
                "HIPAA 164.312(e)(2)(ii) requires encryption of ePHI in transit."
            )
        elif any_weak_tls:
            status = Status.PARTIAL
            details = (
                "TLS is enabled but weak protocol versions (< TLS 1.2) detected. "
                "HIPAA requires strong encryption; TLS 1.2+ is the current standard."
            )
        elif all_good and tested > 0:
            status = Status.DEFENDED
            details = (
                f"All {tested} tested endpoint(s) use TLS 1.2+. "
                "ePHI in-transit encryption meets HIPAA requirements."
            )
        else:
            status = Status.PARTIAL
            details = "Could not fully verify TLS on all endpoints."

        return self._make_result(
            variant="ephi_encryption_in_transit",
            status=status,
            severity=Severity.CRITICAL,
            evidence="; ".join(evidence_parts),
            details=details,
        )

    # ------------------------------------------------------------------
    # Variant 3: Backup encryption
    # ------------------------------------------------------------------

    async def _check_backup_encryption(self) -> AttackResult:
        evidence_parts: list[str] = []
        unencrypted_backups: list[str] = []
        encrypted_backups: list[str] = []
        backup_extensions = (".sql", ".dump", ".tar", ".gz", ".bz2", ".xz", ".bak", ".pg_dump")
        encrypted_extensions = (".gpg", ".enc", ".aes", ".age")

        # Scan backup directories for backup files
        for backup_dir in self.BACKUP_DIRS:
            try:
                if not os.path.isdir(backup_dir):
                    continue
                for root, _dirs, files in os.walk(backup_dir):
                    for f in files:
                        full_path = os.path.join(root, f)
                        is_backup = any(f.endswith(ext) for ext in backup_extensions)
                        is_encrypted = any(f.endswith(ext) for ext in encrypted_extensions)

                        if is_backup and not is_encrypted:
                            unencrypted_backups.append(full_path)
                        elif is_encrypted:
                            encrypted_backups.append(full_path)
                        elif is_backup:
                            # Has backup extension but also check compound extensions
                            # e.g., backup.sql.gpg
                            base_is_encrypted = any(
                                ext in f for ext in encrypted_extensions
                            )
                            if base_is_encrypted:
                                encrypted_backups.append(full_path)
                            else:
                                unencrypted_backups.append(full_path)
            except PermissionError:
                evidence_parts.append(f"{backup_dir}: permission denied")
            except Exception as exc:
                evidence_parts.append(f"{backup_dir}: error scanning — {exc}")

        evidence_parts.append(f"unencrypted backups: {len(unencrypted_backups)}")
        evidence_parts.append(f"encrypted backups: {len(encrypted_backups)}")
        if unencrypted_backups:
            evidence_parts.append(f"unencrypted files: {unencrypted_backups[:10]}")

        # Check cron and backup scripts for encryption piping
        cron_has_backup = False
        cron_encrypts = False
        try:
            cron_result = self._run(["crontab", "-l"])
            cron_text = cron_result.stdout + cron_result.stderr
            backup_lines = [
                l for l in cron_text.splitlines()
                if any(kw in l for kw in ("pg_dump", "mysqldump", "backup", "rsync"))
                and not l.strip().startswith("#")
            ]
            if backup_lines:
                cron_has_backup = True
                evidence_parts.append(f"cron backup commands: {backup_lines[:5]}")
                for line in backup_lines:
                    if any(enc in line for enc in ("gpg", "openssl", "age ", "encrypt")):
                        cron_encrypts = True
                if not cron_encrypts:
                    evidence_parts.append("cron backup commands do NOT pipe through encryption")
        except Exception:
            pass

        # Also check /etc/cron.d/ and /etc/cron.daily/
        for cron_dir in ["/etc/cron.d", "/etc/cron.daily", "/etc/cron.weekly"]:
            try:
                if not os.path.isdir(cron_dir):
                    continue
                for f in os.listdir(cron_dir):
                    fpath = os.path.join(cron_dir, f)
                    if os.path.isfile(fpath):
                        try:
                            with open(fpath, "r", errors="replace") as fh:
                                content = fh.read()
                            if any(kw in content for kw in ("pg_dump", "backup", "mysqldump")):
                                cron_has_backup = True
                                if any(enc in content for enc in ("gpg", "openssl", "age ", "encrypt")):
                                    cron_encrypts = True
                                else:
                                    evidence_parts.append(
                                        f"{fpath}: backup script without encryption"
                                    )
                        except PermissionError:
                            pass
            except Exception:
                pass

        # Determine status
        if unencrypted_backups:
            status = Status.VULNERABLE
            details = (
                f"Found {len(unencrypted_backups)} unencrypted backup file(s) in "
                f"standard backup directories. ePHI backups must be encrypted per "
                f"HIPAA 164.312(a)(2)(iv). Files: {unencrypted_backups[:5]}"
            )
        elif cron_has_backup and not cron_encrypts:
            status = Status.VULNERABLE
            details = (
                "Backup cron jobs detected but none pipe through encryption "
                "(gpg/openssl/age). Backups are likely stored unencrypted."
            )
        elif encrypted_backups or cron_encrypts:
            status = Status.DEFENDED
            details = (
                f"Backup encryption verified. {len(encrypted_backups)} encrypted "
                f"backup file(s) found. Cron encryption: {cron_encrypts}."
            )
        else:
            status = Status.VULNERABLE
            details = (
                "No backup infrastructure detected. Either no backups exist "
                "(separate compliance issue) or they are stored without encryption."
            )

        return self._make_result(
            variant="backup_encryption",
            status=status,
            severity=Severity.HIGH,
            evidence="; ".join(evidence_parts),
            details=details,
        )

    # ------------------------------------------------------------------
    # Variant 4: Key management
    # ------------------------------------------------------------------

    async def _check_key_management(self) -> AttackResult:
        evidence_parts: list[str] = []
        issues: list[str] = []

        # Directories where application code / data typically lives
        app_dirs = [
            "/var/www", "/opt", "/srv", "/home",
        ]
        data_dirs: list[str] = []
        key_files_found: list[dict] = []

        # Find key files in application directories
        for app_dir in app_dirs:
            try:
                if not os.path.isdir(app_dir):
                    continue
                for root, dirs, files in os.walk(app_dir):
                    # Skip deep traversal
                    depth = root.replace(app_dir, "").count(os.sep)
                    if depth > 4:
                        dirs.clear()
                        continue
                    # Skip common non-relevant dirs
                    dirs[:] = [
                        d for d in dirs
                        if d not in ("node_modules", ".git", "__pycache__", "vendor", ".cache")
                    ]

                    for f in files:
                        fpath = os.path.join(root, f)
                        is_key = False
                        if any(f.endswith(ext) for ext in (".key", ".pem", ".p12", ".pfx", ".jks")):
                            is_key = True
                        elif f in ("privkey.pem", "server.key", "ssl.key", "tls.key", "secret.key"):
                            is_key = True

                        if is_key:
                            try:
                                stat = os.stat(fpath)
                                mode = oct(stat.st_mode)[-3:]
                                key_files_found.append({
                                    "path": fpath,
                                    "mode": mode,
                                    "dir": root,
                                })
                            except Exception:
                                key_files_found.append({
                                    "path": fpath,
                                    "mode": "unknown",
                                    "dir": root,
                                })
            except PermissionError:
                evidence_parts.append(f"{app_dir}: permission denied during scan")
            except Exception as exc:
                evidence_parts.append(f"{app_dir}: scan error — {exc}")

        evidence_parts.append(f"key files found: {len(key_files_found)}")

        # Check key file permissions
        weak_perm_keys: list[str] = []
        for kf in key_files_found:
            mode = kf["mode"]
            if mode not in ("600", "400", "640", "000"):
                weak_perm_keys.append(f"{kf['path']} (mode={mode})")
                issues.append(f"Weak permissions on {kf['path']}: {mode}")

        if weak_perm_keys:
            evidence_parts.append(f"weak permission keys: {weak_perm_keys[:10]}")

        # Check if keys are in environment variables vs config files
        env_key_vars = []
        for var in os.environ:
            var_lower = var.lower()
            if any(kw in var_lower for kw in ("key", "secret", "private", "encrypt")):
                if any(kw in var_lower for kw in ("api_key", "secret_key", "private_key", "encryption_key")):
                    env_key_vars.append(var)

        evidence_parts.append(f"env key variables: {env_key_vars if env_key_vars else 'none'}")

        # Check if key files are colocated with data directories
        keys_with_data = []
        try:
            # Get PostgreSQL data directory
            import psycopg2
            conn = psycopg2.connect(
                host=self.DB_CONFIG["host"],
                dbname=self.DB_CONFIG["dbname"],
                user=self.DB_CONFIG["user"],
                password=self._get_db_password(),
            )
            cur = conn.cursor()
            cur.execute("SHOW data_directory;")
            pg_data_dir = cur.fetchone()[0]
            data_dirs.append(pg_data_dir)
            conn.close()
        except Exception:
            data_dirs.append("/var/lib/postgresql")

        for kf in key_files_found:
            for dd in data_dirs:
                if kf["dir"].startswith(dd) or dd.startswith(kf["dir"]):
                    keys_with_data.append(kf["path"])
                    issues.append(f"Key file {kf['path']} colocated with data dir {dd}")

        # Check for keys in config files (hardcoded secrets)
        config_patterns = ["*.conf", "*.ini", "*.yaml", "*.yml", "*.json", "*.env", ".env"]
        hardcoded_secrets: list[str] = []
        secret_pattern = re.compile(
            r"(encryption_key|secret_key|private_key|api_key)\s*[=:]\s*['\"]?[A-Za-z0-9+/=]{16,}",
            re.IGNORECASE,
        )
        for app_dir in ["/var/www/html", "/opt"]:
            try:
                if not os.path.isdir(app_dir):
                    continue
                for root, dirs, files in os.walk(app_dir):
                    depth = root.replace(app_dir, "").count(os.sep)
                    if depth > 3:
                        dirs.clear()
                        continue
                    dirs[:] = [
                        d for d in dirs
                        if d not in ("node_modules", ".git", "__pycache__", "vendor")
                    ]
                    for f in files:
                        if any(f.endswith(ext) for ext in (".conf", ".ini", ".yaml", ".yml", ".env")):
                            fpath = os.path.join(root, f)
                            try:
                                with open(fpath, "r", errors="replace") as fh:
                                    content = fh.read(8192)
                                matches = secret_pattern.findall(content)
                                if matches:
                                    hardcoded_secrets.append(fpath)
                            except (PermissionError, OSError):
                                pass
            except Exception:
                pass

        if hardcoded_secrets:
            evidence_parts.append(f"hardcoded secrets in config: {hardcoded_secrets[:5]}")
            issues.append(f"Hardcoded encryption keys in config files: {hardcoded_secrets[:5]}")

        # Determine status
        if keys_with_data or (hardcoded_secrets and weak_perm_keys):
            status = Status.VULNERABLE
            details = (
                "Encryption key management fails HIPAA requirements. "
                f"Issues: {'; '.join(issues[:5])}. "
                "Keys must be stored separately from encrypted data with "
                "restrictive file permissions (600 or 400)."
            )
        elif weak_perm_keys or hardcoded_secrets:
            status = Status.PARTIAL
            details = (
                "Key management has weaknesses. "
                f"Issues: {'; '.join(issues[:5])}. "
                "Keys should have restrictive permissions and not be hardcoded in configs."
            )
        elif key_files_found and not weak_perm_keys:
            status = Status.DEFENDED
            details = (
                f"Found {len(key_files_found)} key file(s) with proper permissions. "
                "Keys are separated from data directories. "
                f"Env-based key management: {'yes' if env_key_vars else 'no'}."
            )
        elif env_key_vars and not key_files_found:
            status = Status.DEFENDED
            details = (
                "Encryption keys managed via environment variables (not on disk). "
                "This is a recommended practice for key separation."
            )
        else:
            status = Status.PARTIAL
            details = (
                "No key files or environment-based keys detected. "
                "Cannot determine key management posture. Manual review recommended."
            )

        return self._make_result(
            variant="key_management",
            status=status,
            severity=Severity.HIGH,
            evidence="; ".join(evidence_parts),
            details=details,
        )

    # ------------------------------------------------------------------
    # Main execute
    # ------------------------------------------------------------------

    async def execute(self, client) -> list[AttackResult]:
        results: list[AttackResult] = []

        # Variant 1: Encryption at rest (requires DB)
        conn = None
        try:
            import psycopg2
            conn = psycopg2.connect(
                host=self.DB_CONFIG["host"],
                dbname=self.DB_CONFIG["dbname"],
                user=self.DB_CONFIG["user"],
                password=self._get_db_password(),
            )
            results.append(await self._check_encryption_at_rest(conn))
        except ImportError:
            results.append(self._make_result(
                variant="ephi_encryption_at_rest",
                status=Status.ERROR,
                evidence="psycopg2 not installed.",
                details="Install psycopg2-binary to enable database encryption checks.",
            ))
        except Exception as exc:
            results.append(self._make_result(
                variant="ephi_encryption_at_rest",
                status=Status.ERROR,
                evidence=f"Database connection failed: {exc}",
                details="Could not connect to database to verify encryption at rest.",
            ))
        finally:
            if conn:
                conn.close()

        # Variant 2: Encryption in transit (network-based)
        try:
            results.append(await self._check_encryption_in_transit())
        except Exception as exc:
            results.append(self._make_result(
                variant="ephi_encryption_in_transit",
                status=Status.ERROR,
                evidence=f"TLS check failed: {exc}",
                details="Could not verify encryption in transit.",
            ))

        # Variant 3: Backup encryption (filesystem-based)
        try:
            results.append(await self._check_backup_encryption())
        except Exception as exc:
            results.append(self._make_result(
                variant="backup_encryption",
                status=Status.ERROR,
                evidence=f"Backup check failed: {exc}",
                details="Could not verify backup encryption.",
            ))

        # Variant 4: Key management (filesystem + DB)
        try:
            results.append(await self._check_key_management())
        except Exception as exc:
            results.append(self._make_result(
                variant="key_management",
                status=Status.ERROR,
                evidence=f"Key management check failed: {exc}",
                details="Could not verify encryption key management.",
            ))

        return results
