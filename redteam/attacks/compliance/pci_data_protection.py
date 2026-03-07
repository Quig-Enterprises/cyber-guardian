"""PCI DSS 4.0 Requirement 3 — Stored Account Data Protection.

Verifies that stored account data is protected, including PAN discovery
in logs and databases, encryption algorithm strength, and prohibited
CVV storage.
"""

import os
import re
import glob as globmod

from redteam.base import Attack, AttackResult, Severity, Status


# Card number prefixes by brand.
PAN_PATTERNS = [
    # Visa: starts with 4, 13 or 16 digits
    re.compile(r'\b4\d{12}(?:\d{3})?\b'),
    # Mastercard: starts with 5[1-5] or 2[2-7], 16 digits
    re.compile(r'\b5[1-5]\d{14}\b'),
    re.compile(r'\b2[2-7]\d{14}\b'),
    # Amex: starts with 3[47], 15 digits
    re.compile(r'\b3[47]\d{13}\b'),
    # Discover: starts with 6011, 6[45], 16 digits
    re.compile(r'\b6(?:011|[45]\d)\d{12,15}\b'),
]

# Weak encryption algorithms.
WEAK_ALGORITHMS = {
    "des", "3des", "tripledes", "triple-des", "des3",
    "rc4", "arcfour", "rc2", "blowfish", "bf",
    "idea", "cast5", "seed",
}

# Column names that indicate CVV storage (PCI violation).
CVV_COLUMN_NAMES = {
    "cvv", "cvc", "cvv2", "cvc2", "cid", "security_code",
    "card_security", "card_verification", "verification_value",
    "sec_code", "card_code",
}


def luhn_check(number_str: str) -> bool:
    """Validate a number string using the Luhn algorithm."""
    try:
        digits = [int(d) for d in number_str if d.isdigit()]
        if len(digits) < 13 or len(digits) > 19:
            return False
        checksum = 0
        reverse_digits = digits[::-1]
        for i, d in enumerate(reverse_digits):
            if i % 2 == 1:
                d *= 2
                if d > 9:
                    d -= 9
            checksum += d
        return checksum % 10 == 0
    except (ValueError, IndexError):
        return False


class PCIDataProtectionAttack(Attack):
    name = "compliance.pci_data_protection"
    category = "compliance"
    severity = Severity.CRITICAL
    description = "PCI DSS 4.0 Req 3 — Verify protection of stored account data"

    async def execute(self, client) -> list[AttackResult]:
        results: list[AttackResult] = []

        # ----------------------------------------------------------------
        # 1. PAN discovery in log files
        # ----------------------------------------------------------------
        pan_in_logs: list[str] = []
        log_files_checked = 0
        log_dirs = ["/var/log"]

        # Also check application log directories
        for app_dir in ["/var/www/html", "/opt"]:
            try:
                for match in globmod.glob(os.path.join(app_dir, "**", "*.log"), recursive=True):
                    if match not in log_dirs:
                        log_dirs.append(os.path.dirname(match))
            except Exception:
                pass

        try:
            skip_dirs = {"vendor", "node_modules", ".git", "__pycache__",
                         ".cache", "venv", ".venv", "env", "site-packages"}
            for log_dir in log_dirs:
                if not os.path.isdir(log_dir):
                    continue
                for dirpath, dirnames, filenames in os.walk(log_dir):
                    dirnames[:] = [d for d in dirnames if d not in skip_dirs]
                    for fname in filenames:
                        # Only check text-based log files
                        if not any(fname.endswith(ext)
                                   for ext in (".log", ".txt", ".out", ".err")):
                            # Check extensionless files too if in /var/log
                            if dirpath.startswith("/var/log"):
                                if "." in fname:
                                    continue
                            else:
                                continue

                        fpath = os.path.join(dirpath, fname)
                        try:
                            fsize = os.path.getsize(fpath)
                            if fsize > 50 * 1024 * 1024:  # Skip files > 50MB
                                continue
                        except OSError:
                            continue

                        try:
                            with open(fpath, "r", errors="ignore") as f:
                                log_files_checked += 1
                                # Read last 10000 lines for efficiency
                                lines = f.readlines()[-10000:]
                                for line_no, line in enumerate(lines, 1):
                                    for pattern in PAN_PATTERNS:
                                        matches = pattern.findall(line)
                                        for m in matches:
                                            # Filter out common false positives
                                            digits_only = re.sub(r'\D', '', m)
                                            if luhn_check(digits_only):
                                                # Mask the PAN for evidence
                                                masked = digits_only[:6] + "****" + digits_only[-4:]
                                                pan_in_logs.append(
                                                    f"{fpath}:{line_no}: {masked}"
                                                )
                                                if len(pan_in_logs) >= 20:
                                                    break
                                    if len(pan_in_logs) >= 20:
                                        break
                        except (PermissionError, OSError):
                            continue
                    if len(pan_in_logs) >= 20:
                        break
                if len(pan_in_logs) >= 20:
                    break

            if pan_in_logs:
                pan_log_status = Status.VULNERABLE
                detail = (
                    f"Found {len(pan_in_logs)} Luhn-valid PAN(s) in log files! "
                    "PCI DSS Req 3.1 prohibits storing PAN in logs. "
                    f"Files checked: {log_files_checked}."
                )
            else:
                pan_log_status = Status.DEFENDED
                detail = (
                    f"No Luhn-valid PANs found in {log_files_checked} log files. "
                    "Log data appears free of unprotected cardholder data."
                )
        except Exception as exc:
            pan_log_status = Status.ERROR
            detail = f"PAN discovery in logs failed: {exc}"
            pan_in_logs = [str(exc)]

        results.append(self._make_result(
            variant="pan_discovery_logs",
            status=pan_log_status,
            severity=Severity.CRITICAL,
            evidence="\n".join(pan_in_logs[:10]) if pan_in_logs else f"Scanned {log_files_checked} files",
            details=detail,
        ))

        # ----------------------------------------------------------------
        # 2. PAN discovery in database columns
        # ----------------------------------------------------------------
        try:
            import psycopg2
            db_pass = os.environ.get("EQMON_AUTH_DB_PASS", "3eK4NNHxLQakuTQK5KcnB3Vz")
            conn = psycopg2.connect(
                host="localhost", dbname="eqmon", user="eqmon", password=db_pass,
            )
            cur = conn.cursor()

            # Find text/varchar columns in payment-related tables
            cur.execute("""
                SELECT table_name, column_name, data_type
                FROM information_schema.columns
                WHERE table_schema = 'public'
                  AND data_type IN ('text', 'character varying', 'varchar', 'char')
                  AND (table_name LIKE '%%payment%%'
                       OR table_name LIKE '%%transaction%%'
                       OR table_name LIKE '%%order%%'
                       OR table_name LIKE '%%card%%'
                       OR table_name LIKE '%%billing%%'
                       OR table_name LIKE '%%charge%%'
                       OR column_name LIKE '%%card%%'
                       OR column_name LIKE '%%pan%%'
                       OR column_name LIKE '%%account_number%%'
                       OR column_name LIKE '%%credit%%')
                ORDER BY table_name, column_name;
            """)
            suspect_columns = cur.fetchall()

            pan_in_db: list[str] = []
            columns_checked = 0

            for table, column, dtype in suspect_columns:
                columns_checked += 1
                try:
                    cur.execute(
                        f"SELECT {column} FROM {table} "
                        f"WHERE {column} IS NOT NULL LIMIT 100;"
                    )
                    rows = cur.fetchall()
                    for row in rows:
                        val = str(row[0])
                        digits = re.sub(r'\D', '', val)
                        if 13 <= len(digits) <= 19 and luhn_check(digits):
                            masked = digits[:6] + "****" + digits[-4:]
                            pan_in_db.append(
                                f"{table}.{column}: {masked} (plaintext {dtype})"
                            )
                            if len(pan_in_db) >= 20:
                                break
                except Exception:
                    continue
                if len(pan_in_db) >= 20:
                    break

            conn.close()

            if pan_in_db:
                pan_db_status = Status.VULNERABLE
                detail = (
                    f"Found {len(pan_in_db)} unencrypted PAN(s) in database! "
                    "PCI DSS Req 3.5.1 requires PAN to be rendered unreadable "
                    "anywhere it is stored."
                )
            elif suspect_columns:
                pan_db_status = Status.DEFENDED
                detail = (
                    f"Checked {columns_checked} suspect column(s) in "
                    f"{len(set(t for t, _, _ in suspect_columns))} table(s). "
                    "No unencrypted PANs found."
                )
            else:
                pan_db_status = Status.DEFENDED
                detail = "No payment/card-related columns found in database schema."

        except ImportError:
            pan_db_status = Status.ERROR
            detail = "psycopg2 not installed — cannot scan database for PANs."
            pan_in_db = ["psycopg2 missing"]
        except Exception as exc:
            pan_db_status = Status.ERROR
            detail = f"PAN discovery in database failed: {exc}"
            pan_in_db = [str(exc)]

        results.append(self._make_result(
            variant="pan_discovery_db",
            status=pan_db_status,
            severity=Severity.CRITICAL,
            evidence="\n".join(pan_in_db[:10]) if pan_in_db else "No PANs found",
            details=detail,
        ))

        # ----------------------------------------------------------------
        # 3. Encryption algorithm strength
        # ----------------------------------------------------------------
        weak_algo_findings: list[str] = []

        # Check PostgreSQL pgcrypto settings
        try:
            import psycopg2
            conn = psycopg2.connect(
                host="localhost", dbname="eqmon", user="eqmon", password=db_pass,
            )
            cur = conn.cursor()

            # Check if pgcrypto is installed and what algorithms are in use
            cur.execute("""
                SELECT EXISTS(SELECT 1 FROM pg_extension WHERE extname = 'pgcrypto');
            """)
            has_pgcrypto = cur.fetchone()[0]

            if has_pgcrypto:
                # Look for pgp_sym_encrypt calls in function definitions
                cur.execute("""
                    SELECT routine_name, routine_definition
                    FROM information_schema.routines
                    WHERE routine_schema = 'public'
                      AND routine_definition IS NOT NULL
                      AND (routine_definition LIKE '%%encrypt%%'
                           OR routine_definition LIKE '%%pgp_sym%%'
                           OR routine_definition LIKE '%%cipher%%');
                """)
                crypto_funcs = cur.fetchall()
                for func_name, func_def in crypto_funcs:
                    func_lower = func_def.lower()
                    for weak in WEAK_ALGORITHMS:
                        if weak in func_lower:
                            weak_algo_findings.append(
                                f"Function '{func_name}' uses weak algorithm '{weak}'"
                            )

            conn.close()
        except Exception:
            pass

        # Check application config files for encryption settings
        config_scan_dirs = ["/var/www/html", "/opt", "/etc"]
        crypto_config_patterns = [
            re.compile(r'(?:cipher|algorithm|encryption)\s*[=:]\s*["\']?(\w+)', re.IGNORECASE),
            re.compile(r'(?:MCRYPT_|CIPHER_)(\w+)', re.IGNORECASE),
        ]

        for scan_dir in config_scan_dirs:
            if not os.path.isdir(scan_dir):
                continue
            try:
                for dirpath, dirnames, filenames in os.walk(scan_dir):
                    dirnames[:] = [d for d in dirnames
                                   if d not in {"node_modules", "__pycache__",
                                                ".git", "vendor"}]
                    for fname in filenames:
                        ext = os.path.splitext(fname)[1].lower()
                        if ext not in {".php", ".py", ".conf", ".cfg", ".ini",
                                       ".yaml", ".yml", ".env", ".json"}:
                            continue
                        fpath = os.path.join(dirpath, fname)
                        try:
                            with open(fpath, "r", errors="ignore") as f:
                                content = f.read(50000)  # limit read
                            for pat in crypto_config_patterns:
                                for m in pat.finditer(content):
                                    algo = m.group(1).lower()
                                    if algo in WEAK_ALGORITHMS:
                                        weak_algo_findings.append(
                                            f"{fpath}: weak algorithm '{algo}' configured"
                                        )
                        except (PermissionError, OSError):
                            continue
                    if len(weak_algo_findings) >= 20:
                        break
            except Exception:
                continue

        if weak_algo_findings:
            algo_status = Status.VULNERABLE
            detail = (
                f"Found {len(weak_algo_findings)} weak encryption algorithm(s). "
                "PCI DSS Req 3.6.1 requires strong cryptography (AES-128+). "
                + "; ".join(weak_algo_findings[:5])
            )
        else:
            algo_status = Status.DEFENDED
            detail = (
                "No weak encryption algorithms detected in database functions "
                "or application configuration."
            )

        results.append(self._make_result(
            variant="encryption_algorithm",
            status=algo_status,
            severity=Severity.HIGH,
            evidence="\n".join(weak_algo_findings[:10]) if weak_algo_findings else "No weak algorithms found",
            details=detail,
        ))

        # ----------------------------------------------------------------
        # 4. CVV storage check — CVV must NEVER be stored post-authorization
        # ----------------------------------------------------------------
        try:
            import psycopg2
            conn = psycopg2.connect(
                host="localhost", dbname="eqmon", user="eqmon", password=db_pass,
            )
            cur = conn.cursor()

            # Search for CVV-related column names across all tables
            placeholders = ",".join(["%s"] * len(CVV_COLUMN_NAMES))
            cur.execute(f"""
                SELECT table_name, column_name, data_type
                FROM information_schema.columns
                WHERE table_schema = 'public'
                  AND LOWER(column_name) IN ({placeholders})
                ORDER BY table_name, column_name;
            """, list(CVV_COLUMN_NAMES))
            cvv_columns = cur.fetchall()

            # Also search with LIKE for partial matches
            like_conditions = " OR ".join(
                [f"LOWER(column_name) LIKE '%{name}%'" for name in CVV_COLUMN_NAMES]
            )
            cur.execute(f"""
                SELECT table_name, column_name, data_type
                FROM information_schema.columns
                WHERE table_schema = 'public'
                  AND ({like_conditions})
                ORDER BY table_name, column_name;
            """)
            cvv_like_columns = cur.fetchall()

            # Merge and deduplicate
            all_cvv = list({(t, c, d) for t, c, d in cvv_columns + cvv_like_columns})

            conn.close()

            if all_cvv:
                # Check if any contain actual data
                has_data = False
                try:
                    conn2 = psycopg2.connect(
                        host="localhost", dbname="eqmon", user="eqmon", password=db_pass,
                    )
                    cur2 = conn2.cursor()
                    for table, column, dtype in all_cvv[:5]:
                        try:
                            cur2.execute(
                                f"SELECT COUNT(*) FROM {table} "
                                f"WHERE {column} IS NOT NULL AND {column}::text != '';"
                            )
                            count = cur2.fetchone()[0]
                            if count > 0:
                                has_data = True
                                break
                        except Exception:
                            continue
                    conn2.close()
                except Exception:
                    pass

                if has_data:
                    cvv_status = Status.VULNERABLE
                    detail = (
                        f"CVV/CVC data columns found WITH data: "
                        f"{[(t, c) for t, c, _ in all_cvv]}. "
                        "PCI DSS Req 3.3.1.1 PROHIBITS storing CVV/CVC "
                        "after authorization. This is a critical violation."
                    )
                else:
                    cvv_status = Status.PARTIAL
                    detail = (
                        f"CVV/CVC columns exist but appear empty: "
                        f"{[(t, c) for t, c, _ in all_cvv]}. "
                        "Columns should be removed to prevent future misuse."
                    )
                evidence = f"CVV columns: {all_cvv}"
            else:
                cvv_status = Status.DEFENDED
                detail = (
                    "No CVV/CVC/security code columns found in database schema. "
                    "Compliant with PCI DSS Req 3.3.1.1."
                )
                evidence = "No CVV columns found"

        except ImportError:
            cvv_status = Status.ERROR
            detail = "psycopg2 not installed — cannot check for CVV storage."
            evidence = "psycopg2 missing"
        except Exception as exc:
            cvv_status = Status.ERROR
            detail = f"CVV storage check failed: {exc}"
            evidence = str(exc)

        results.append(self._make_result(
            variant="cvv_storage_check",
            status=cvv_status,
            severity=Severity.CRITICAL,
            evidence=evidence,
            details=detail,
        ))

        return results
