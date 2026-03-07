"""HIPAA Access Control & Audit Logging verification — 45 CFR 164.312(a)(1) + (b).

Checks whether ePHI systems enforce unique user identification, comprehensive
audit logging of all ePHI access, 6-year log retention, and tamper-proof
log storage.
"""

import os
import re
import subprocess
from datetime import datetime, timedelta

from redteam.base import Attack, AttackResult, Severity, Status


class HIPAAAccessAuditAttack(Attack):
    name = "compliance.hipaa_access_audit"
    category = "compliance"
    severity = Severity.HIGH
    description = (
        "HIPAA \u00a7164.312(a)(1)+(b) \u2014 Verify ePHI access control "
        "and audit logging"
    )

    DB_CONFIG = {
        "host": "localhost",
        "dbname": "eqmon",
        "user": "eqmon",
    }

    GENERIC_ACCOUNT_NAMES = (
        "admin", "root", "operator", "guest", "service", "shared",
        "system", "test", "demo", "user", "default", "anonymous",
        "support", "helpdesk", "generic", "temp",
    )

    HIPAA_RETENTION_DAYS = 2190  # 6 years

    def _get_db_password(self) -> str:
        return os.environ.get("EQMON_AUTH_DB_PASS", "3eK4NNHxLQakuTQK5KcnB3Vz")

    def _run(self, cmd: list[str], timeout: int = 10) -> subprocess.CompletedProcess:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)

    # ------------------------------------------------------------------
    # Variant 1: Unique user IDs — detect shared/generic accounts
    # ------------------------------------------------------------------

    async def _check_unique_user_ids(self, conn) -> AttackResult:
        cur = conn.cursor()
        evidence_parts: list[str] = []
        shared_accounts: list[str] = []

        # 1a. Check database user accounts for generic names
        pattern_list = ", ".join(f"'%{name}%'" for name in self.GENERIC_ACCOUNT_NAMES)

        # Check application users table (try common table names)
        user_tables = ["users", "accounts", "app_users", "user_accounts", "staff"]
        found_table = None
        for table in user_tables:
            try:
                cur.execute(f"""
                    SELECT EXISTS(
                        SELECT 1 FROM information_schema.tables
                        WHERE table_schema = 'public' AND table_name = '{table}'
                    );
                """)
                if cur.fetchone()[0]:
                    found_table = table
                    break
            except Exception:
                continue

        if found_table:
            # Look for username/login columns
            cur.execute(f"""
                SELECT column_name FROM information_schema.columns
                WHERE table_schema = 'public' AND table_name = '{found_table}'
                  AND column_name IN ('username', 'login', 'email', 'name', 'user_name', 'account_name')
                LIMIT 1;
            """)
            username_col_row = cur.fetchone()

            if username_col_row:
                username_col = username_col_row[0]
                # Build ILIKE conditions for generic names
                conditions = " OR ".join(
                    f"LOWER({username_col}) = '{name}'" for name in self.GENERIC_ACCOUNT_NAMES
                )
                like_conditions = " OR ".join(
                    f"LOWER({username_col}) LIKE '%{name}%'" for name in ("shared", "generic", "temp", "test")
                )

                cur.execute(f"""
                    SELECT {username_col} FROM {found_table}
                    WHERE ({conditions}) OR ({like_conditions});
                """)
                generic_rows = cur.fetchall()
                for row in generic_rows:
                    shared_accounts.append(f"db:{found_table}.{row[0]}")

                evidence_parts.append(
                    f"Checked table '{found_table}' column '{username_col}': "
                    f"found {len(generic_rows)} generic account(s)"
                )
            else:
                evidence_parts.append(f"Table '{found_table}' found but no username column identified")
        else:
            evidence_parts.append("No standard user table found in database")

        # 1b. Check PostgreSQL roles for generic/shared names
        cur.execute("""
            SELECT rolname, rolcanlogin, rolsuper
            FROM pg_roles
            WHERE rolcanlogin = true
            ORDER BY rolname;
        """)
        pg_roles = cur.fetchall()
        for rolname, can_login, is_super in pg_roles:
            if any(generic in rolname.lower() for generic in self.GENERIC_ACCOUNT_NAMES):
                shared_accounts.append(f"pg_role:{rolname} (super={is_super})")

        evidence_parts.append(f"PostgreSQL login roles: {[r[0] for r in pg_roles]}")

        # 1c. Check /etc/passwd for shared service accounts accessing ePHI paths
        try:
            with open("/etc/passwd", "r") as f:
                for line in f:
                    parts = line.strip().split(":")
                    if len(parts) >= 7:
                        username = parts[0]
                        shell = parts[6]
                        # Flag accounts with login shells and generic names
                        if shell not in ("/usr/sbin/nologin", "/bin/false", "/sbin/nologin"):
                            if any(generic == username.lower() for generic in self.GENERIC_ACCOUNT_NAMES):
                                shared_accounts.append(f"system:{username} (shell={shell})")
            evidence_parts.append("Checked /etc/passwd for shared accounts")
        except Exception as exc:
            evidence_parts.append(f"/etc/passwd check failed: {exc}")

        # 1d. Check for multiple concurrent sessions from same user (via who/w)
        try:
            result = self._run(["who"])
            who_lines = [l for l in result.stdout.strip().splitlines() if l.strip()]
            user_sessions: dict[str, int] = {}
            for line in who_lines:
                user = line.split()[0]
                user_sessions[user] = user_sessions.get(user, 0) + 1
            multi_session_users = {u: c for u, c in user_sessions.items() if c > 1}
            if multi_session_users:
                evidence_parts.append(f"Multiple sessions from same user: {multi_session_users}")
                # This could indicate shared credentials
                for u, c in multi_session_users.items():
                    shared_accounts.append(f"multi-session:{u} ({c} sessions)")
        except Exception:
            pass

        # Determine status
        if shared_accounts:
            status = Status.VULNERABLE
            details = (
                f"Found {len(shared_accounts)} shared/generic account(s) that may access ePHI: "
                f"{shared_accounts[:10]}. HIPAA 164.312(a)(2)(i) requires unique user "
                "identification for all users accessing ePHI."
            )
        else:
            status = Status.DEFENDED
            details = (
                "No shared or generic accounts detected in application database, "
                "PostgreSQL roles, or system accounts. Unique user identification "
                "appears to be enforced."
            )

        return self._make_result(
            variant="unique_user_ids",
            status=status,
            severity=Severity.HIGH,
            evidence="; ".join(evidence_parts),
            details=details,
        )

    # ------------------------------------------------------------------
    # Variant 2: Audit log coverage
    # ------------------------------------------------------------------

    async def _check_audit_log_coverage(self, conn) -> AttackResult:
        cur = conn.cursor()
        evidence_parts: list[str] = []
        has_pgaudit = False
        has_log_all = False
        has_app_audit = False
        recent_entries = 0

        # 2a. Check for pgaudit extension
        cur.execute(
            "SELECT EXISTS(SELECT 1 FROM pg_extension WHERE extname = 'pgaudit');"
        )
        has_pgaudit = cur.fetchone()[0]
        evidence_parts.append(f"pgaudit extension: {has_pgaudit}")

        # 2b. Check log_statement setting
        cur.execute("SHOW log_statement;")
        log_statement = cur.fetchone()[0]
        evidence_parts.append(f"log_statement: {log_statement}")
        if log_statement in ("all", "mod"):
            has_log_all = True

        # Also check log_min_duration_statement
        try:
            cur.execute("SHOW log_min_duration_statement;")
            log_min_dur = cur.fetchone()[0]
            evidence_parts.append(f"log_min_duration_statement: {log_min_dur}")
        except Exception:
            pass

        # 2c. Check for application-level audit table
        audit_table_candidates = [
            ("blueteam", "audit_events"),
            ("public", "audit_log"),
            ("public", "audit_events"),
            ("public", "audit_trail"),
            ("public", "activity_log"),
            ("public", "access_log"),
            ("audit", "events"),
        ]

        for schema, table in audit_table_candidates:
            try:
                cur.execute(f"""
                    SELECT EXISTS(
                        SELECT 1 FROM information_schema.tables
                        WHERE table_schema = '{schema}' AND table_name = '{table}'
                    );
                """)
                if cur.fetchone()[0]:
                    has_app_audit = True
                    evidence_parts.append(f"Audit table found: {schema}.{table}")

                    # Check for recent entries
                    try:
                        # Try common timestamp columns
                        for ts_col in ("created_at", "timestamp", "event_time", "logged_at", "ts"):
                            try:
                                cur.execute(f"""
                                    SELECT COUNT(*) FROM {schema}.{table}
                                    WHERE {ts_col} > NOW() - INTERVAL '24 hours';
                                """)
                                recent_entries = cur.fetchone()[0]
                                evidence_parts.append(
                                    f"Recent entries (24h) in {schema}.{table}: {recent_entries}"
                                )
                                break
                            except Exception:
                                conn.rollback()
                                continue

                        # Check total row count
                        cur.execute(f"SELECT COUNT(*) FROM {schema}.{table};")
                        total = cur.fetchone()[0]
                        evidence_parts.append(f"Total entries in {schema}.{table}: {total}")
                    except Exception:
                        conn.rollback()
                    break
            except Exception:
                conn.rollback()
                continue

        # 2d. Check if SELECT queries on sensitive tables are logged
        # by checking postgresql.conf for logging configuration
        pg_conf_paths = [
            "/etc/postgresql/16/main/postgresql.conf",
            "/etc/postgresql/15/main/postgresql.conf",
            "/etc/postgresql/14/main/postgresql.conf",
            "/var/lib/postgresql/data/postgresql.conf",
        ]

        pg_conf_found = False
        for conf_path in pg_conf_paths:
            try:
                if os.path.isfile(conf_path):
                    with open(conf_path, "r", errors="replace") as f:
                        content = f.read()
                    pg_conf_found = True
                    evidence_parts.append(f"postgresql.conf found at {conf_path}")

                    # Check for logging configuration
                    if "pgaudit" in content.lower():
                        evidence_parts.append("pgaudit configuration found in postgresql.conf")
                    if re.search(r"^\s*log_statement\s*=\s*'all'", content, re.MULTILINE):
                        has_log_all = True
                        evidence_parts.append("log_statement = 'all' in postgresql.conf")
                    break
            except PermissionError:
                evidence_parts.append(f"{conf_path}: permission denied")
            except Exception:
                pass

        # Determine status
        if has_pgaudit and has_app_audit and recent_entries > 0:
            status = Status.DEFENDED
            details = (
                "Comprehensive audit logging is in place. pgaudit extension active, "
                f"application audit table found with {recent_entries} entries in last 24h. "
                "Meets HIPAA 164.312(b) requirements."
            )
        elif has_app_audit or has_pgaudit or has_log_all:
            status = Status.PARTIAL
            details = (
                "Audit logging partially configured. "
                f"pgaudit: {has_pgaudit}, log_statement: {log_statement}, "
                f"app audit table: {has_app_audit}, recent entries: {recent_entries}. "
                "HIPAA requires logging of ALL ePHI access including reads."
            )
        else:
            status = Status.VULNERABLE
            details = (
                "No audit logging detected. pgaudit not installed, log_statement not "
                f"set to 'all' (current: '{log_statement}'), and no application "
                "audit table found. HIPAA 164.312(b) requires audit controls for "
                "all ePHI access."
            )

        return self._make_result(
            variant="audit_log_coverage",
            status=status,
            severity=Severity.HIGH,
            evidence="; ".join(evidence_parts),
            details=details,
        )

    # ------------------------------------------------------------------
    # Variant 3: Audit log retention (6-year requirement)
    # ------------------------------------------------------------------

    async def _check_audit_log_retention(self, conn) -> AttackResult:
        cur = conn.cursor()
        evidence_parts: list[str] = []
        retention_days: int | None = None

        # 3a. Check logrotate configuration for retention period
        logrotate_configs = [
            "/etc/logrotate.d/postgresql-common",
            "/etc/logrotate.d/postgresql",
            "/etc/logrotate.d/rsyslog",
            "/etc/logrotate.d/syslog",
            "/etc/logrotate.conf",
        ]

        max_logrotate_retention = 0
        for conf_path in logrotate_configs:
            try:
                if not os.path.isfile(conf_path):
                    continue
                with open(conf_path, "r", errors="replace") as f:
                    content = f.read()

                # Parse rotate count and frequency
                rotate_match = re.search(r"rotate\s+(\d+)", content)
                rotate_count = int(rotate_match.group(1)) if rotate_match else 4

                if "daily" in content:
                    days = rotate_count
                elif "weekly" in content:
                    days = rotate_count * 7
                elif "monthly" in content:
                    days = rotate_count * 30
                elif "yearly" in content:
                    days = rotate_count * 365
                else:
                    days = rotate_count * 7  # default weekly

                if days > max_logrotate_retention:
                    max_logrotate_retention = days

                evidence_parts.append(
                    f"{conf_path}: rotate {rotate_count}, ~{days} days retention"
                )
            except PermissionError:
                evidence_parts.append(f"{conf_path}: permission denied")
            except Exception:
                pass

        if max_logrotate_retention > 0:
            evidence_parts.append(f"Max logrotate retention: {max_logrotate_retention} days")

        # 3b. Check oldest entries in audit tables
        oldest_entry_age_days: int | None = None
        audit_table_candidates = [
            ("blueteam", "audit_events"),
            ("public", "audit_log"),
            ("public", "audit_events"),
            ("public", "audit_trail"),
        ]

        for schema, table in audit_table_candidates:
            try:
                cur.execute(f"""
                    SELECT EXISTS(
                        SELECT 1 FROM information_schema.tables
                        WHERE table_schema = '{schema}' AND table_name = '{table}'
                    );
                """)
                if not cur.fetchone()[0]:
                    continue

                for ts_col in ("created_at", "timestamp", "event_time", "logged_at", "ts"):
                    try:
                        cur.execute(f"""
                            SELECT MIN({ts_col}), MAX({ts_col}),
                                   EXTRACT(EPOCH FROM (NOW() - MIN({ts_col}))) / 86400
                            FROM {schema}.{table};
                        """)
                        row = cur.fetchone()
                        if row and row[0]:
                            oldest_entry_age_days = int(row[2]) if row[2] else 0
                            evidence_parts.append(
                                f"Oldest entry in {schema}.{table}: {row[0]} "
                                f"({oldest_entry_age_days} days ago), newest: {row[1]}"
                            )
                            break
                    except Exception:
                        conn.rollback()
                        continue

                if oldest_entry_age_days is not None:
                    break
            except Exception:
                conn.rollback()
                continue

        # 3c. Check syslog retention settings
        syslog_retention_days = 0
        try:
            # Check journald retention
            journald_conf = "/etc/systemd/journald.conf"
            if os.path.isfile(journald_conf):
                with open(journald_conf, "r", errors="replace") as f:
                    content = f.read()
                max_retention = re.search(r"MaxRetentionSec\s*=\s*(\S+)", content)
                if max_retention:
                    val = max_retention.group(1)
                    evidence_parts.append(f"journald MaxRetentionSec: {val}")
                    # Parse value (could be "1year", "365d", etc.)
                    if "year" in val:
                        num = re.search(r"(\d+)", val)
                        syslog_retention_days = int(num.group(1)) * 365 if num else 365
                    elif "month" in val:
                        num = re.search(r"(\d+)", val)
                        syslog_retention_days = int(num.group(1)) * 30 if num else 30
                    elif "week" in val:
                        num = re.search(r"(\d+)", val)
                        syslog_retention_days = int(num.group(1)) * 7 if num else 7
                    elif "d" in val:
                        num = re.search(r"(\d+)", val)
                        syslog_retention_days = int(num.group(1)) if num else 0
                else:
                    evidence_parts.append("journald MaxRetentionSec: not set (no limit)")
                    syslog_retention_days = -1  # -1 means unlimited
        except Exception as exc:
            evidence_parts.append(f"journald config check: {exc}")

        # Determine effective retention
        if oldest_entry_age_days is not None:
            retention_days = oldest_entry_age_days
        elif max_logrotate_retention > 0:
            retention_days = max_logrotate_retention
        elif syslog_retention_days != 0:
            retention_days = syslog_retention_days if syslog_retention_days > 0 else self.HIPAA_RETENTION_DAYS

        evidence_parts.append(f"Effective retention estimate: {retention_days} days")

        # Determine status
        if retention_days is None:
            status = Status.VULNERABLE
            details = (
                "Could not determine audit log retention period. No audit tables, "
                "logrotate configs, or syslog retention settings found. HIPAA requires "
                "6-year (2190 days) retention of audit logs."
            )
        elif retention_days >= self.HIPAA_RETENTION_DAYS:
            status = Status.DEFENDED
            details = (
                f"Audit log retention of ~{retention_days} days meets HIPAA 6-year "
                f"({self.HIPAA_RETENTION_DAYS} days) requirement."
            )
        elif retention_days >= 365:
            status = Status.PARTIAL
            details = (
                f"Audit log retention of ~{retention_days} days ({retention_days // 365} years). "
                f"HIPAA requires 6 years ({self.HIPAA_RETENTION_DAYS} days). "
                f"Current retention is {self.HIPAA_RETENTION_DAYS - retention_days} days short."
            )
        else:
            status = Status.VULNERABLE
            details = (
                f"Audit log retention of only ~{retention_days} days (< 1 year). "
                f"HIPAA requires 6 years ({self.HIPAA_RETENTION_DAYS} days). "
                "Significantly below compliance threshold."
            )

        return self._make_result(
            variant="audit_log_retention_6yr",
            status=status,
            severity=Severity.HIGH,
            evidence="; ".join(evidence_parts),
            details=details,
        )

    # ------------------------------------------------------------------
    # Variant 4: Audit log tamper protection
    # ------------------------------------------------------------------

    async def _check_audit_log_tamper_protection(self, conn) -> AttackResult:
        cur = conn.cursor()
        evidence_parts: list[str] = []
        has_remote_logging = False
        has_immutable_attr = False
        has_db_protection = False
        has_integrity_checks = False

        # 4a. Check if logs are forwarded to remote syslog
        remote_syslog_configs = [
            "/etc/rsyslog.conf",
            "/etc/rsyslog.d/",
            "/etc/syslog-ng/syslog-ng.conf",
        ]

        for conf in remote_syslog_configs:
            try:
                if os.path.isdir(conf):
                    for f in os.listdir(conf):
                        fpath = os.path.join(conf, f)
                        if os.path.isfile(fpath):
                            with open(fpath, "r", errors="replace") as fh:
                                content = fh.read()
                            # Look for remote forwarding (@@host for TCP, @host for UDP)
                            if re.search(r"@@?\S+:\d+", content) or "action(" in content:
                                has_remote_logging = True
                                evidence_parts.append(f"Remote syslog configured in {fpath}")
                elif os.path.isfile(conf):
                    with open(conf, "r", errors="replace") as f:
                        content = f.read()
                    if re.search(r"@@?\S+:\d+", content):
                        has_remote_logging = True
                        evidence_parts.append(f"Remote syslog configured in {conf}")
                    elif "destination" in content and "tcp" in content.lower():
                        has_remote_logging = True
                        evidence_parts.append(f"syslog-ng remote destination in {conf}")
            except PermissionError:
                evidence_parts.append(f"{conf}: permission denied")
            except Exception:
                pass

        if not has_remote_logging:
            evidence_parts.append("No remote syslog forwarding detected")

        # 4b. Check if audit table has DELETE/UPDATE restrictions
        audit_tables = [
            ("blueteam", "audit_events"),
            ("public", "audit_log"),
            ("public", "audit_events"),
            ("public", "audit_trail"),
        ]

        for schema, table in audit_tables:
            try:
                cur.execute(f"""
                    SELECT EXISTS(
                        SELECT 1 FROM information_schema.tables
                        WHERE table_schema = '{schema}' AND table_name = '{table}'
                    );
                """)
                if not cur.fetchone()[0]:
                    continue

                # Check for triggers that prevent DELETE/UPDATE
                cur.execute(f"""
                    SELECT trigger_name, event_manipulation, action_statement
                    FROM information_schema.triggers
                    WHERE event_object_schema = '{schema}'
                      AND event_object_table = '{table}'
                      AND event_manipulation IN ('DELETE', 'UPDATE');
                """)
                triggers = cur.fetchall()
                if triggers:
                    has_db_protection = True
                    evidence_parts.append(
                        f"Protective triggers on {schema}.{table}: "
                        f"{[(t[0], t[1]) for t in triggers]}"
                    )

                # Check for RLS policies
                cur.execute(f"""
                    SELECT polname, polcmd
                    FROM pg_policy
                    WHERE polrelid = '{schema}.{table}'::regclass;
                """)
                policies = cur.fetchall()
                if policies:
                    has_db_protection = True
                    evidence_parts.append(
                        f"RLS policies on {schema}.{table}: "
                        f"{[(p[0], p[1]) for p in policies]}"
                    )

                # Check table permissions - see if DELETE is revoked
                cur.execute(f"""
                    SELECT grantee, privilege_type
                    FROM information_schema.table_privileges
                    WHERE table_schema = '{schema}' AND table_name = '{table}'
                      AND privilege_type IN ('DELETE', 'UPDATE');
                """)
                perms = cur.fetchall()
                evidence_parts.append(
                    f"DELETE/UPDATE grants on {schema}.{table}: "
                    f"{[(p[0], p[1]) for p in perms] if perms else 'none'}"
                )
                if not perms:
                    has_db_protection = True

                break
            except Exception:
                conn.rollback()
                continue

        # 4c. Check if log files have append-only attribute (chattr +a)
        log_paths = [
            "/var/log/postgresql",
            "/var/log/syslog",
            "/var/log/auth.log",
            "/var/log/audit",
        ]

        for log_path in log_paths:
            try:
                if os.path.isdir(log_path):
                    target = log_path
                elif os.path.isfile(log_path):
                    target = log_path
                else:
                    continue

                result = subprocess.run(
                    ["lsattr", "-d" if os.path.isdir(target) else "", target],
                    capture_output=True, text=True, timeout=5,
                )
                if result.returncode == 0 and result.stdout.strip():
                    attrs = result.stdout.strip()
                    evidence_parts.append(f"lsattr {target}: {attrs}")
                    # 'a' attribute means append-only
                    if "a" in attrs.split()[0] if attrs.split() else "":
                        has_immutable_attr = True
                        evidence_parts.append(f"Append-only attribute set on {target}")
            except Exception:
                pass

        # 4d. Check for log integrity / checksums (aide, tripwire, etc.)
        integrity_tools = ["aide", "tripwire", "ossec", "samhain"]
        for tool in integrity_tools:
            try:
                result = subprocess.run(
                    ["which", tool], capture_output=True, text=True, timeout=5
                )
                if result.returncode == 0:
                    has_integrity_checks = True
                    evidence_parts.append(f"Integrity tool installed: {tool}")
            except Exception:
                pass

        # Also check for systemd file integrity monitoring
        try:
            result = subprocess.run(
                ["systemctl", "list-units", "--type=service", "--state=active"],
                capture_output=True, text=True, timeout=10,
            )
            for tool in integrity_tools:
                if tool in result.stdout.lower():
                    has_integrity_checks = True
                    evidence_parts.append(f"Integrity service running: {tool}")
        except Exception:
            pass

        # Determine status
        protections = sum([
            has_remote_logging,
            has_immutable_attr,
            has_db_protection,
            has_integrity_checks,
        ])

        if protections >= 2:
            status = Status.DEFENDED
            details = (
                f"Audit log tamper protection in place ({protections}/4 controls). "
                f"Remote logging: {has_remote_logging}, immutable attrs: {has_immutable_attr}, "
                f"DB protection: {has_db_protection}, integrity checks: {has_integrity_checks}."
            )
        elif protections == 1:
            status = Status.PARTIAL
            details = (
                f"Only {protections}/4 tamper protection control(s) detected. "
                f"Remote logging: {has_remote_logging}, immutable attrs: {has_immutable_attr}, "
                f"DB protection: {has_db_protection}, integrity checks: {has_integrity_checks}. "
                "HIPAA requires robust protection against audit log modification."
            )
        else:
            status = Status.VULNERABLE
            details = (
                "No audit log tamper protection detected. Logs can be modified or "
                "deleted locally without detection. HIPAA requires that audit logs "
                "be protected from unauthorized alteration. Implement remote syslog, "
                "append-only attributes, database restrictions, or integrity monitoring."
            )

        return self._make_result(
            variant="audit_log_tamper_protection",
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

        conn = None
        try:
            import psycopg2
        except ImportError:
            return [self._make_result(
                variant="unique_user_ids",
                status=Status.ERROR,
                evidence="psycopg2 not installed.",
                details="Install psycopg2-binary to enable HIPAA access audit checks.",
            )]

        try:
            conn = psycopg2.connect(
                host=self.DB_CONFIG["host"],
                dbname=self.DB_CONFIG["dbname"],
                user=self.DB_CONFIG["user"],
                password=self._get_db_password(),
            )

            # Variant 1: Unique user IDs
            try:
                results.append(await self._check_unique_user_ids(conn))
            except Exception as exc:
                results.append(self._make_result(
                    variant="unique_user_ids",
                    status=Status.ERROR,
                    evidence=f"Check failed: {exc}",
                    details="Could not verify unique user identification.",
                ))

            # Variant 2: Audit log coverage
            try:
                results.append(await self._check_audit_log_coverage(conn))
            except Exception as exc:
                results.append(self._make_result(
                    variant="audit_log_coverage",
                    status=Status.ERROR,
                    evidence=f"Check failed: {exc}",
                    details="Could not verify audit log coverage.",
                ))

            # Variant 3: Audit log retention
            try:
                results.append(await self._check_audit_log_retention(conn))
            except Exception as exc:
                results.append(self._make_result(
                    variant="audit_log_retention_6yr",
                    status=Status.ERROR,
                    evidence=f"Check failed: {exc}",
                    details="Could not verify audit log retention period.",
                ))

            # Variant 4: Audit log tamper protection
            try:
                results.append(await self._check_audit_log_tamper_protection(conn))
            except Exception as exc:
                results.append(self._make_result(
                    variant="audit_log_tamper_protection",
                    status=Status.ERROR,
                    evidence=f"Check failed: {exc}",
                    details="Could not verify audit log tamper protection.",
                ))

        except Exception as exc:
            results.append(self._make_result(
                variant="unique_user_ids",
                status=Status.ERROR,
                evidence=f"Database connection failed: {exc}",
                details="Could not connect to database for HIPAA access audit checks.",
            ))
        finally:
            if conn:
                conn.close()

        return results
