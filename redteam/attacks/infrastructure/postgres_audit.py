"""PostgreSQL security audit — authentication, privilege, and configuration checks.

Variants:
- default_credentials:     Tests well-known default username/password pairs against
                           the target PostgreSQL instance (postgres/postgres, etc.).
- trust_auth_exposure:     Attempts a passwordless connection as 'postgres' to detect
                           pg_hba.conf trust entries that bypass authentication entirely.
- port_exposure:           Verifies whether port 5432 is reachable from the scanner's
                           network context. DB ports should not be accessible from
                           untrusted segments.
- superuser_enumeration:   After connecting with a valid credential, queries
                           pg_catalog.pg_roles for superuser accounts. Multiple or
                           unexpected superusers indicate privilege sprawl.
- dangerous_extensions:    Checks for installed extensions that allow OS-level access:
                           pg_read_file, pg_execute_server_program, dblink, postgres_fdw,
                           file_fdw, pg_replication_slot, plpythonu/plperlu.
- public_schema_writeable: Tests whether the 'public' schema is writable by the
                           connecting user (CVE-2018-1058 attack vector).
- pg_version_disclosure:   Checks if the server banner version is exposed on the port,
                           and whether the version is within supported lifetime.
"""

import logging
import socket

from redteam.base import Attack, AttackResult, Severity, Status

logger = logging.getLogger(__name__)

# Default / factory credentials to try (user, password)
DEFAULT_CREDS = [
    ("postgres", "postgres"),
    ("postgres", ""),
    ("postgres", "password"),
    ("postgres", "admin"),
    ("postgres", "secret"),
    ("admin", "admin"),
    ("admin", "postgres"),
    ("pgsql", "pgsql"),
    ("root", "root"),
]

# Extensions that grant dangerous OS/filesystem capabilities
DANGEROUS_EXTENSIONS = {
    "plpythonu":             "Untrusted PL/Python — arbitrary OS code execution as the DB server user",
    "plperlu":               "Untrusted PL/Perl — arbitrary OS code execution as the DB server user",
    "plsh":                  "PL/sh — executes shell commands directly from SQL",
    "pg_execute_server_program": "Allows SQL to invoke OS programs (CVE class: OS command execution)",
    "dblink":                "Cross-database queries; can be abused for SSRF or lateral movement",
    "postgres_fdw":          "Foreign data wrapper; enables connections to other PG servers",
    "file_fdw":              "Foreign data wrapper for local filesystem files — arbitrary file read",
    "pg_read_file":          "Direct filesystem read function (if installed as extension)",
    "lo":                    "Large object manipulation; historically used for filesystem write",
    "adminpack":             "Server-side file management functions (pg_read_file, pg_write_file)",
}

# PostgreSQL major versions and approximate EOL
# Versions <= 13 are EOL as of 2025
EOL_VERSIONS = {9, 10, 11, 12, 13}


def _tcp_port_open(host: str, port: int, timeout: float = 3.0) -> tuple[bool, str]:
    """Check if a TCP port is open. Returns (open, banner_or_error)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((host, port))
        if result == 0:
            s.settimeout(2.0)
            try:
                banner = s.recv(256)
                banner_str = banner.decode("latin-1", errors="replace").strip()
            except Exception:
                banner_str = ""
            s.close()
            return (True, banner_str)
        s.close()
        return (False, "port closed or filtered")
    except OSError as exc:
        return (False, str(exc))


def _try_connect(host: str, port: int, dbname: str, user: str, password: str, timeout: int = 5):
    """
    Try to connect to PostgreSQL. Returns (conn_or_None, error_str).
    Imports psycopg2 lazily so the module loads even without it installed.
    """
    try:
        import psycopg2
        import psycopg2.extras
    except ImportError:
        return (None, "psycopg2 not installed")

    try:
        conn = psycopg2.connect(
            host=host,
            port=port,
            dbname=dbname,
            user=user,
            password=password,
            connect_timeout=timeout,
            options="-c statement_timeout=5000",
        )
        conn.autocommit = True
        return (conn, "")
    except psycopg2.OperationalError as exc:
        return (None, str(exc).strip())
    except Exception as exc:
        return (None, str(exc).strip())


class PostgresAuditAttack(Attack):
    """Probe a PostgreSQL instance for authentication weaknesses and dangerous configuration."""

    name = "infrastructure.postgres_audit"
    category = "infrastructure"
    severity = Severity.HIGH
    description = (
        "Audit PostgreSQL security: default credentials, trust auth, port exposure, "
        "superuser enumeration, dangerous extensions, and schema privilege"
    )
    target_types = {"app", "generic"}

    PG_PORT   = 5432
    PG_DBNAME = "postgres"

    def _get_pg_host(self, client) -> str:
        """Derive PG host from scan target or config."""
        try:
            from urllib.parse import urlparse
            if client is not None:
                parsed = urlparse(client.base_url)
                return parsed.hostname or "localhost"
        except Exception:
            pass
        return self._config.get("target", {}).get("origin_ip") or "localhost"

    def _get_pg_port(self) -> int:
        return int(
            self._config.get("database", {}).get("port", self.PG_PORT)
        )

    async def execute(self, client) -> list[AttackResult]:
        results = []
        host = self._get_pg_host(client)
        port = self._get_pg_port()

        # ----------------------------------------------------------------
        # 1. port_exposure — check reachability before anything else
        # ----------------------------------------------------------------
        port_open, banner = _tcp_port_open(host, port)

        if port_open:
            results.append(self._make_result(
                variant="port_exposure",
                status=Status.VULNERABLE,
                severity=Severity.HIGH,
                evidence=(
                    f"TCP port {port} (PostgreSQL) on {host} is reachable from this "
                    f"network context. Banner: '{banner[:80]}'" if banner else
                    f"TCP port {port} (PostgreSQL) on {host} accepted a connection."
                ),
                details=(
                    f"The PostgreSQL port {port} is accessible from the scanner's network "
                    "context. Database ports should be firewalled to the application tier "
                    "only. Direct exposure to untrusted segments allows credential attacks "
                    "and version fingerprinting."
                ),
                request={"host": host, "port": port},
                response={"open": True, "banner": banner[:80] if banner else ""},
            ))
        else:
            results.append(self._make_result(
                variant="port_exposure",
                status=Status.DEFENDED,
                evidence=f"TCP port {port} on {host} is not reachable: {banner}",
                details=(
                    "PostgreSQL port is not accessible from this network context. "
                    "DB port is properly firewalled from untrusted segments."
                ),
                request={"host": host, "port": port},
                response={"open": False, "error": banner},
            ))
            # Port closed — remaining checks are pointless, skip them
            for variant in ("trust_auth_exposure", "default_credentials",
                            "superuser_enumeration", "dangerous_extensions",
                            "public_schema_writeable", "pg_version_disclosure"):
                results.append(self._make_result(
                    variant=variant,
                    status=Status.SKIPPED,
                    evidence=f"Port {port} unreachable on {host} — skipped",
                    details="PostgreSQL port not reachable; remaining audit checks skipped.",
                ))
            return results

        # ----------------------------------------------------------------
        # 2. trust_auth_exposure — passwordless 'postgres' login
        # ----------------------------------------------------------------
        trust_conn, trust_err = _try_connect(host, port, self.PG_DBNAME, "postgres", "")

        if trust_conn is not None:
            trust_conn.close()
            results.append(self._make_result(
                variant="trust_auth_exposure",
                status=Status.VULNERABLE,
                severity=Severity.CRITICAL,
                evidence=f"Connected to {host}:{port} as 'postgres' with an empty password",
                details=(
                    "PostgreSQL accepted a connection as the 'postgres' superuser "
                    "with no password. This indicates a 'trust' or 'password' entry "
                    "in pg_hba.conf without a credential requirement. An attacker on "
                    "any allowed network can gain full superuser access. "
                    "Set a strong password for the postgres superuser and configure "
                    "pg_hba.conf to require md5 or scram-sha-256 authentication."
                ),
                request={"host": host, "port": port, "user": "postgres", "password": "(empty)"},
                response={"connected": True},
            ))
        elif "psycopg2 not installed" in trust_err:
            results.append(self._make_result(
                variant="trust_auth_exposure",
                status=Status.ERROR,
                evidence="psycopg2 not installed — cannot test PostgreSQL authentication",
                details="Install psycopg2-binary to enable PostgreSQL audit checks.",
            ))
            # No point running further DB checks either
            for variant in ("default_credentials", "superuser_enumeration",
                            "dangerous_extensions", "public_schema_writeable",
                            "pg_version_disclosure"):
                results.append(self._make_result(
                    variant=variant,
                    status=Status.SKIPPED,
                    evidence="psycopg2 not installed",
                    details="Install psycopg2-binary to enable this check.",
                ))
            return results
        else:
            results.append(self._make_result(
                variant="trust_auth_exposure",
                status=Status.DEFENDED,
                evidence=f"Empty-password 'postgres' login refused: {trust_err[:120]}",
                details="postgres superuser requires a password — trust auth is not configured for this host.",
                request={"host": host, "port": port, "user": "postgres", "password": "(empty)"},
                response={"error": trust_err[:120]},
            ))

        # ----------------------------------------------------------------
        # 3. default_credentials
        # ----------------------------------------------------------------
        default_hits = []
        working_conn = trust_conn  # reuse if trust worked

        for user, password in DEFAULT_CREDS:
            if user == "postgres" and password == "":
                continue  # already tested in trust check
            conn, err = _try_connect(host, port, self.PG_DBNAME, user, password)
            if conn is not None:
                default_hits.append(f"user='{user}' password='{password}'")
                if working_conn is None:
                    working_conn = conn
                else:
                    conn.close()

        if default_hits:
            results.append(self._make_result(
                variant="default_credentials",
                status=Status.VULNERABLE,
                severity=Severity.CRITICAL,
                evidence="PostgreSQL accepted default credentials:\n" + "\n".join(default_hits),
                details=(
                    "Default or well-known credentials grant access to the database. "
                    "An attacker can log in and read, modify, or destroy data. "
                    "Change all database passwords immediately and audit pg_hba.conf."
                ),
                request={"host": host, "port": port, "pairs_tested": len(DEFAULT_CREDS)},
                response={"accepted": default_hits},
            ))
        else:
            results.append(self._make_result(
                variant="default_credentials",
                status=Status.DEFENDED,
                evidence=f"None of {len(DEFAULT_CREDS)} default credential pairs were accepted",
                details="No default credentials work against this PostgreSQL instance.",
                request={"host": host, "port": port, "pairs_tested": len(DEFAULT_CREDS)},
                response={"accepted": []},
            ))

        # ----------------------------------------------------------------
        # Remaining checks need a live connection
        # ----------------------------------------------------------------
        if working_conn is None:
            for variant in ("superuser_enumeration", "dangerous_extensions",
                            "public_schema_writeable", "pg_version_disclosure"):
                results.append(self._make_result(
                    variant=variant,
                    status=Status.SKIPPED,
                    evidence="No valid credential available — cannot run authenticated checks",
                    details=(
                        "Authenticated PostgreSQL checks require a working credential. "
                        "Provide credentials via the database config block or confirm "
                        "the instance is reachable with a known user."
                    ),
                ))
            return results

        conn = working_conn
        try:
            results += self._check_superusers(conn, host, port)
            results += self._check_dangerous_extensions(conn, host, port)
            results += self._check_public_schema(conn, host, port)
            results += self._check_version(conn, host, port)
        finally:
            try:
                conn.close()
            except Exception:
                pass

        return results

    def _check_superusers(self, conn, host: str, port: int) -> list[AttackResult]:
        try:
            import psycopg2
            cur = conn.cursor()
            cur.execute(
                "SELECT rolname FROM pg_catalog.pg_roles WHERE rolsuper = TRUE ORDER BY rolname;"
            )
            superusers = [row[0] for row in cur.fetchall()]
            cur.close()
        except Exception as exc:
            return [self._make_result(
                variant="superuser_enumeration",
                status=Status.ERROR,
                evidence=f"Query failed: {exc}",
                details="Could not enumerate superuser accounts.",
            )]

        expected = {"postgres"}
        unexpected = set(superusers) - expected

        if unexpected:
            return [self._make_result(
                variant="superuser_enumeration",
                status=Status.VULNERABLE,
                severity=Severity.HIGH,
                evidence=(
                    f"Superuser accounts found: {', '.join(sorted(superusers))}. "
                    f"Unexpected superusers: {', '.join(sorted(unexpected))}"
                ),
                details=(
                    f"{len(unexpected)} unexpected superuser role(s) detected. "
                    "Superuser accounts bypass all row-level security and object "
                    "permissions. Revoke superuser from any account that does not "
                    "require it (ALTER ROLE <name> NOSUPERUSER)."
                ),
                request={"host": host, "port": port, "query": "pg_roles WHERE rolsuper"},
                response={"superusers": superusers, "unexpected": list(unexpected)},
            )]

        if len(superusers) == 1:
            return [self._make_result(
                variant="superuser_enumeration",
                status=Status.DEFENDED,
                evidence=f"Only the default 'postgres' superuser exists: {superusers}",
                details="No unexpected superuser accounts found.",
                request={"host": host, "port": port},
                response={"superusers": superusers},
            )]

        # Multiple but only expected ones (edge case)
        return [self._make_result(
            variant="superuser_enumeration",
            status=Status.PARTIAL,
            severity=Severity.MEDIUM,
            evidence=f"Multiple superuser accounts: {', '.join(sorted(superusers))}",
            details=(
                "More than one superuser account exists. Verify each is necessary and "
                "restrict to the minimum required accounts."
            ),
            request={"host": host, "port": port},
            response={"superusers": superusers},
        )]

    def _check_dangerous_extensions(self, conn, host: str, port: int) -> list[AttackResult]:
        try:
            cur = conn.cursor()
            cur.execute(
                "SELECT extname FROM pg_catalog.pg_extension ORDER BY extname;"
            )
            installed = {row[0].lower() for row in cur.fetchall()}
            cur.close()
        except Exception as exc:
            return [self._make_result(
                variant="dangerous_extensions",
                status=Status.ERROR,
                evidence=f"Query failed: {exc}",
                details="Could not query installed extensions.",
            )]

        found_dangerous = {
            ext: desc for ext, desc in DANGEROUS_EXTENSIONS.items()
            if ext.lower() in installed
        }

        if found_dangerous:
            lines = [f"  - {ext}: {desc}" for ext, desc in found_dangerous.items()]
            return [self._make_result(
                variant="dangerous_extensions",
                status=Status.VULNERABLE,
                severity=Severity.HIGH,
                evidence=f"{len(found_dangerous)} dangerous extension(s) installed:\n" + "\n".join(
                    ext for ext in found_dangerous
                ),
                details=(
                    "The following dangerous PostgreSQL extensions are installed:\n"
                    + "\n".join(lines)
                    + "\nThese extensions can allow OS command execution, arbitrary file "
                    "read/write, or lateral movement to other databases. Remove extensions "
                    "that are not actively required (DROP EXTENSION <name>;)."
                ),
                request={"host": host, "port": port, "query": "pg_extension"},
                response={"dangerous": list(found_dangerous.keys()), "all_installed": list(installed)},
            )]

        return [self._make_result(
            variant="dangerous_extensions",
            status=Status.DEFENDED,
            evidence=f"No dangerous extensions found among {len(installed)} installed: {', '.join(sorted(installed)) or 'none'}",
            details="No high-risk PostgreSQL extensions (plpythonu, dblink, file_fdw, etc.) are installed.",
            request={"host": host, "port": port},
            response={"all_installed": list(installed)},
        )]

    def _check_public_schema(self, conn, host: str, port: int) -> list[AttackResult]:
        """Test CVE-2018-1058: PUBLIC can CREATE objects in the public schema."""
        try:
            cur = conn.cursor()
            cur.execute(
                "SELECT has_schema_privilege('public', 'public', 'CREATE');"
            )
            row = cur.fetchone()
            cur.close()
            public_create = row[0] if row else False
        except Exception as exc:
            return [self._make_result(
                variant="public_schema_writeable",
                status=Status.ERROR,
                evidence=f"Query failed: {exc}",
                details="Could not check public schema CREATE privilege.",
            )]

        if public_create:
            return [self._make_result(
                variant="public_schema_writeable",
                status=Status.VULNERABLE,
                severity=Severity.HIGH,
                evidence="PUBLIC role has CREATE privilege on the 'public' schema",
                details=(
                    "Any authenticated database user can create objects (tables, functions, "
                    "views) in the public schema. This is the CVE-2018-1058 attack vector: "
                    "a low-privilege user can create a trojan function in 'public' that "
                    "overrides a trusted function and escalates privileges. "
                    "Fix: REVOKE CREATE ON SCHEMA public FROM PUBLIC;"
                ),
                request={"host": host, "port": port, "check": "has_schema_privilege(public, public, CREATE)"},
                response={"public_can_create": True},
            )]

        return [self._make_result(
            variant="public_schema_writeable",
            status=Status.DEFENDED,
            evidence="PUBLIC does not have CREATE privilege on the 'public' schema",
            details=(
                "CVE-2018-1058 mitigated — unprivileged users cannot create objects in the "
                "public schema and cannot plant trojan functions."
            ),
            request={"host": host, "port": port},
            response={"public_can_create": False},
        )]

    def _check_version(self, conn, host: str, port: int) -> list[AttackResult]:
        try:
            cur = conn.cursor()
            cur.execute("SELECT version();")
            row = cur.fetchone()
            cur.close()
            version_str = row[0] if row else ""
        except Exception as exc:
            return [self._make_result(
                variant="pg_version_disclosure",
                status=Status.ERROR,
                evidence=f"Query failed: {exc}",
                details="Could not retrieve server version.",
            )]

        # Extract major version number
        major = None
        try:
            # version() returns e.g. "PostgreSQL 14.12 on x86_64-..."
            parts = version_str.split()
            for i, p in enumerate(parts):
                if p == "PostgreSQL" and i + 1 < len(parts):
                    major = int(parts[i + 1].split(".")[0])
                    break
        except (ValueError, IndexError):
            pass

        if major is None:
            return [self._make_result(
                variant="pg_version_disclosure",
                status=Status.PARTIAL,
                evidence=f"Version string: '{version_str[:120]}'",
                details="Could not parse major version number from server version string.",
                response={"version_string": version_str[:120]},
            )]

        if major in EOL_VERSIONS:
            return [self._make_result(
                variant="pg_version_disclosure",
                status=Status.VULNERABLE,
                severity=Severity.HIGH,
                evidence=f"PostgreSQL major version {major} is end-of-life. Full version: '{version_str[:120]}'",
                details=(
                    f"PostgreSQL {major} is past its end-of-life date and no longer receives "
                    "security patches. Known CVEs for this version will never be fixed. "
                    f"Upgrade to a supported release (currently: 14, 15, 16, 17)."
                ),
                request={"host": host, "port": port},
                response={"major_version": major, "full_version": version_str[:120]},
            )]

        return [self._make_result(
            variant="pg_version_disclosure",
            status=Status.DEFENDED,
            severity=Severity.INFO,
            evidence=f"PostgreSQL {major} is within supported lifecycle. Full: '{version_str[:100]}'",
            details=f"PostgreSQL major version {major} is currently supported and receives security patches.",
            request={"host": host, "port": port},
            response={"major_version": major},
        )]
