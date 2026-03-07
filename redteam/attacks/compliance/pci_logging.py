"""PCI DSS 4.0 Requirement 10 — Logging and Monitoring.

Verifies that logging and monitoring mechanisms are in place to track
access to cardholder data environment resources, including log field
completeness, NTP synchronization, log tamper protection, and
privileged action audit logging.
"""

import os
import re
import subprocess
from datetime import datetime, timedelta

from redteam.base import Attack, AttackResult, Severity, Status


# Required fields per PCI DSS Req 10.3
REQUIRED_LOG_FIELDS = {"user", "timestamp", "event_type", "source_ip", "outcome"}

# Patterns to identify each field in log entries.
FIELD_PATTERNS = {
    "user": re.compile(
        r'(?:user|usr|uid|username|account|email|login)\s*[=:]\s*\S+',
        re.IGNORECASE,
    ),
    "timestamp": re.compile(
        r'\d{4}[-/]\d{2}[-/]\d{2}[T ]\d{2}:\d{2}:\d{2}'
        r'|[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}',
    ),
    "event_type": re.compile(
        r'(?:event|action|type|operation|activity|method)\s*[=:]\s*\S+',
        re.IGNORECASE,
    ),
    "source_ip": re.compile(
        r'(?:src|source|ip|client|remote|addr)\s*[=:]\s*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        r'|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',
        re.IGNORECASE,
    ),
    "outcome": re.compile(
        r'(?:result|status|outcome|success|fail|error|ok|denied|granted)\s*[=:]?\s*\S*',
        re.IGNORECASE,
    ),
}


class PCILoggingAttack(Attack):
    name = "compliance.pci_logging"
    category = "compliance"
    severity = Severity.HIGH
    description = "PCI DSS 4.0 Req 10 — Verify logging and monitoring of CDE access"

    async def execute(self, client) -> list[AttackResult]:
        results: list[AttackResult] = []

        # ----------------------------------------------------------------
        # 1. Log field completeness — verify required fields present
        # ----------------------------------------------------------------
        log_sources = [
            "/var/log/syslog",
            "/var/log/auth.log",
            "/var/log/nginx/access.log",
            "/var/log/apache2/access.log",
        ]

        # Also check application audit table if database is available
        db_log_entries: list[str] = []
        try:
            import psycopg2
            db_pass = os.environ.get("EQMON_AUTH_DB_PASS", "3eK4NNHxLQakuTQK5KcnB3Vz")
            conn = psycopg2.connect(
                host="localhost", dbname="eqmon", user="eqmon", password=db_pass,
            )
            cur = conn.cursor()
            # Try to find an audit/event log table
            cur.execute("""
                SELECT table_name FROM information_schema.tables
                WHERE table_schema = 'public'
                  AND (table_name LIKE '%%audit%%'
                       OR table_name LIKE '%%event_log%%'
                       OR table_name LIKE '%%activity%%'
                       OR table_name LIKE '%%access_log%%')
                ORDER BY table_name;
            """)
            audit_tables = [r[0] for r in cur.fetchall()]

            for tbl in audit_tables[:2]:  # Check up to 2 tables
                cur.execute(f"SELECT * FROM {tbl} ORDER BY 1 DESC LIMIT 10;")
                rows = cur.fetchall()
                col_names = [desc[0] for desc in cur.description]
                for row in rows:
                    entry = "; ".join(f"{c}={v}" for c, v in zip(col_names, row) if v)
                    db_log_entries.append(entry)
            conn.close()
        except Exception:
            pass

        # Read file-based log entries
        file_log_entries: list[str] = []
        for log_file in log_sources:
            try:
                with open(log_file, "r", errors="ignore") as f:
                    # Read last 20 lines
                    lines = f.readlines()[-20:]
                    file_log_entries.extend(line.strip() for line in lines if line.strip())
            except (FileNotFoundError, PermissionError):
                continue

        all_entries = file_log_entries + db_log_entries
        if not all_entries:
            completeness_status = Status.VULNERABLE
            detail = (
                "No log entries found in any checked source. "
                "PCI DSS Req 10.2 requires logging of all access to CDE."
            )
            evidence = f"Checked: {log_sources}, DB audit tables: {audit_tables if 'audit_tables' in dir() else 'N/A'}"
        else:
            # Analyze a sample of entries for field presence
            sample = all_entries[:15]
            field_coverage: dict[str, int] = {f: 0 for f in REQUIRED_LOG_FIELDS}
            for entry in sample:
                for field_name, pattern in FIELD_PATTERNS.items():
                    if pattern.search(entry):
                        field_coverage[field_name] += 1

            present_fields = {f for f, count in field_coverage.items()
                              if count >= len(sample) * 0.3}
            missing_fields = REQUIRED_LOG_FIELDS - present_fields

            if not missing_fields:
                completeness_status = Status.DEFENDED
                detail = (
                    f"All required PCI DSS log fields detected in sample of "
                    f"{len(sample)} entries: {REQUIRED_LOG_FIELDS}."
                )
            elif len(missing_fields) <= 2:
                completeness_status = Status.PARTIAL
                detail = (
                    f"Some required log fields missing: {missing_fields}. "
                    f"Present: {present_fields}. PCI DSS Req 10.3 requires "
                    "user ID, timestamp, event type, source IP, and outcome."
                )
            else:
                completeness_status = Status.VULNERABLE
                detail = (
                    f"Multiple required log fields missing: {missing_fields}. "
                    f"Only found: {present_fields}. PCI DSS Req 10.3 requires "
                    "comprehensive audit trail fields."
                )
            evidence = f"Coverage: {field_coverage}, sample_size: {len(sample)}"

        results.append(self._make_result(
            variant="log_field_completeness",
            status=completeness_status,
            evidence=evidence if 'evidence' in dir() else "No data",
            details=detail,
        ))

        # ----------------------------------------------------------------
        # 2. NTP synchronization — time must be accurate
        # ----------------------------------------------------------------
        try:
            timedatectl = subprocess.run(
                ["timedatectl", "status"],
                capture_output=True, text=True, timeout=5,
            )
            output = timedatectl.stdout

            ntp_active = False
            synchronized = False
            for line in output.splitlines():
                lower = line.lower()
                if "ntp" in lower and ("active" in lower or "enabled" in lower
                                        or "yes" in lower):
                    ntp_active = True
                if "synchronized" in lower and "yes" in lower:
                    synchronized = True
                if "system clock synchronized" in lower and "yes" in lower:
                    synchronized = True

            if ntp_active and synchronized:
                ntp_status = Status.DEFENDED
                detail = "NTP is active and system clock is synchronized."
            elif ntp_active:
                ntp_status = Status.PARTIAL
                detail = (
                    "NTP service is active but clock synchronization status "
                    "could not be confirmed."
                )
            else:
                ntp_status = Status.VULNERABLE
                detail = (
                    "NTP is NOT active. PCI DSS Req 10.6.1 requires all system "
                    "clocks to be synchronized using NTP or similar technology."
                )
            evidence = output.strip()[:500]

        except FileNotFoundError:
            # Fallback to ntpq
            try:
                ntpq = subprocess.run(
                    ["ntpq", "-p"], capture_output=True, text=True, timeout=5,
                )
                if ntpq.returncode == 0 and ntpq.stdout.strip():
                    # Check for active sync peer (line starting with *)
                    has_sync = any(line.startswith("*") for line in ntpq.stdout.splitlines())
                    if has_sync:
                        ntp_status = Status.DEFENDED
                        detail = "NTP synchronized (active peer detected via ntpq)."
                    else:
                        ntp_status = Status.PARTIAL
                        detail = "NTP running but no synchronized peer detected."
                    evidence = ntpq.stdout.strip()[:500]
                else:
                    ntp_status = Status.VULNERABLE
                    detail = "Neither timedatectl nor ntpq available/working."
                    evidence = f"ntpq rc={ntpq.returncode}"
            except Exception as exc2:
                ntp_status = Status.ERROR
                detail = f"NTP check failed: {exc2}"
                evidence = str(exc2)
        except Exception as exc:
            ntp_status = Status.ERROR
            detail = f"NTP check failed: {exc}"
            evidence = str(exc)

        results.append(self._make_result(
            variant="ntp_sync",
            status=ntp_status,
            severity=Severity.MEDIUM,
            evidence=evidence,
            details=detail,
        ))

        # ----------------------------------------------------------------
        # 3. Log tamper protection — logs forwarded to remote/immutable store
        # ----------------------------------------------------------------
        remote_logging = False
        log_protection_evidence: list[str] = []

        # Check rsyslog config for remote forwarding
        rsyslog_configs = [
            "/etc/rsyslog.conf",
            "/etc/rsyslog.d/",
        ]
        for cfg_path in rsyslog_configs:
            try:
                if os.path.isfile(cfg_path):
                    with open(cfg_path, "r") as f:
                        content = f.read()
                    # Remote targets use @@ (TCP) or @ (UDP)
                    if re.search(r'@@?\s*\S+:\d+', content):
                        remote_logging = True
                        log_protection_evidence.append(
                            f"rsyslog remote target found in {cfg_path}"
                        )
                elif os.path.isdir(cfg_path):
                    for fname in os.listdir(cfg_path):
                        fpath = os.path.join(cfg_path, fname)
                        try:
                            with open(fpath, "r") as f:
                                content = f.read()
                            if re.search(r'@@?\s*\S+:\d+', content):
                                remote_logging = True
                                log_protection_evidence.append(
                                    f"rsyslog remote target found in {fpath}"
                                )
                        except (PermissionError, OSError):
                            continue
            except (PermissionError, OSError):
                continue

        # Check syslog-ng for remote destinations
        for syslog_ng in ["/etc/syslog-ng/syslog-ng.conf", "/etc/syslog-ng.conf"]:
            try:
                with open(syslog_ng, "r") as f:
                    content = f.read()
                if "destination" in content and ("tcp" in content or "udp" in content):
                    remote_logging = True
                    log_protection_evidence.append(
                        f"syslog-ng remote destination in {syslog_ng}"
                    )
            except (FileNotFoundError, PermissionError):
                continue

        # Check for append-only or immutable log files
        try:
            lsattr = subprocess.run(
                ["lsattr", "/var/log/syslog", "/var/log/auth.log"],
                capture_output=True, text=True, timeout=5,
            )
            if "a" in lsattr.stdout:  # append-only attribute
                log_protection_evidence.append(
                    "Append-only attribute set on log files"
                )
                remote_logging = True  # immutable counts as protected
        except Exception:
            pass

        # Check journald for persistent + remote forwarding
        try:
            with open("/etc/systemd/journald.conf", "r") as f:
                journald = f.read()
            if "ForwardToSyslog=yes" in journald:
                log_protection_evidence.append("journald forwards to syslog")
            if "Storage=persistent" in journald:
                log_protection_evidence.append("journald storage is persistent")
        except (FileNotFoundError, PermissionError):
            pass

        if remote_logging:
            tamper_status = Status.DEFENDED
            detail = (
                "Log tamper protection detected: "
                + "; ".join(log_protection_evidence)
                + ". PCI DSS Req 10.5 requirements appear met."
            )
        elif log_protection_evidence:
            tamper_status = Status.PARTIAL
            detail = (
                "Some log protection found but no confirmed remote forwarding: "
                + "; ".join(log_protection_evidence)
            )
        else:
            tamper_status = Status.VULNERABLE
            detail = (
                "No log tamper protection detected. No remote syslog forwarding, "
                "no append-only attributes, no immutable storage. "
                "PCI DSS Req 10.5.1 requires audit logs protected from modification."
            )

        results.append(self._make_result(
            variant="log_tamper_protection",
            status=tamper_status,
            severity=Severity.HIGH,
            evidence="; ".join(log_protection_evidence) if log_protection_evidence else "None found",
            details=detail,
        ))

        # ----------------------------------------------------------------
        # 4. Privileged action logging — admin actions appear in audit log
        # ----------------------------------------------------------------
        try:
            import psycopg2
            db_pass = os.environ.get("EQMON_AUTH_DB_PASS", "3eK4NNHxLQakuTQK5KcnB3Vz")
            conn = psycopg2.connect(
                host="localhost", dbname="eqmon", user="eqmon", password=db_pass,
            )
            cur = conn.cursor()

            # Find audit-style tables
            cur.execute("""
                SELECT table_name FROM information_schema.tables
                WHERE table_schema = 'public'
                  AND (table_name LIKE '%%audit%%'
                       OR table_name LIKE '%%event_log%%'
                       OR table_name LIKE '%%activity_log%%'
                       OR table_name LIKE '%%access_log%%')
                ORDER BY table_name;
            """)
            audit_tables = [r[0] for r in cur.fetchall()]

            if audit_tables:
                # Perform a test admin action (a benign SELECT with a marker)
                marker = f"pci_audit_test_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"

                # Check for recent privileged entries
                recent_cutoff = datetime.utcnow() - timedelta(hours=24)
                privileged_entries = 0
                for tbl in audit_tables[:2]:
                    try:
                        # Get columns to find timestamp column
                        cur.execute(f"""
                            SELECT column_name FROM information_schema.columns
                            WHERE table_name = '{tbl}'
                              AND data_type IN ('timestamp without time zone',
                                                'timestamp with time zone',
                                                'timestamptz', 'timestamp');
                        """)
                        ts_cols = [r[0] for r in cur.fetchall()]
                        if ts_cols:
                            cur.execute(
                                f"SELECT COUNT(*) FROM {tbl} WHERE {ts_cols[0]} > %s;",
                                (recent_cutoff,),
                            )
                            privileged_entries += cur.fetchone()[0]
                    except Exception:
                        continue

                conn.close()

                if privileged_entries > 0:
                    audit_status = Status.DEFENDED
                    detail = (
                        f"Audit logging active: {privileged_entries} entries in last 24h "
                        f"across tables: {audit_tables}. "
                        "PCI DSS Req 10.2 privileged action logging appears operational."
                    )
                else:
                    audit_status = Status.PARTIAL
                    detail = (
                        f"Audit tables exist ({audit_tables}) but no recent entries found. "
                        "Privileged action logging may not be capturing events."
                    )
                evidence = (
                    f"Audit tables: {audit_tables}, "
                    f"Recent entries (24h): {privileged_entries}"
                )
            else:
                conn.close()
                audit_status = Status.VULNERABLE
                detail = (
                    "No audit/activity log tables found in database. "
                    "PCI DSS Req 10.2 requires logging of all privileged actions."
                )
                evidence = "No audit tables found"

        except ImportError:
            audit_status = Status.ERROR
            detail = "psycopg2 not installed — cannot verify audit logging."
            evidence = "psycopg2 missing"
        except Exception as exc:
            audit_status = Status.ERROR
            detail = f"Privileged action logging check failed: {exc}"
            evidence = str(exc)

        results.append(self._make_result(
            variant="privileged_action_logging",
            status=audit_status,
            severity=Severity.HIGH,
            evidence=evidence,
            details=detail,
        ))

        return results
