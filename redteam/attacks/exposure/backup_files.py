"""Backup file and database dump exposure detection.

Probes for commonly left-behind backup files, database dumps, archive
files, and editor temporary files that may expose sensitive data or
source code.

Evaluation:
- 200 response with non-HTML content and Content-Length > 1000 -> VULNERABLE
- 200 response with SQL keywords in plain text -> VULNERABLE
- 403/401 -> PARTIAL (file exists but access restricted)
- 404/other -> DEFENDED
"""

import asyncio
import time
import logging

from redteam.base import Attack, AttackResult, Severity, Status

logger = logging.getLogger(__name__)

# Delay between probes in AWS mode (seconds)
AWS_PROBE_DELAY = 0.1

# SQL content indicators in response body
SQL_KEYWORDS = [
    "CREATE TABLE",
    "INSERT INTO",
    "DROP TABLE",
    "ALTER TABLE",
    "-- MySQL dump",
    "-- PostgreSQL database dump",
    "LOCK TABLES",
    "UNLOCK TABLES",
    "mysqldump",
]


def _looks_like_real_file(status_code: int, body: str, headers: dict) -> bool:
    """Return True if the response appears to be a real file (not an error page)."""
    if status_code != 200:
        return False

    content_type = headers.get("Content-Type", "").lower()
    content_length = int(headers.get("Content-Length", 0) or 0)

    # If content length header says > 1000 and it's not HTML, likely real
    if content_length > 1000 and "text/html" not in content_type:
        return True

    # Binary / archive content types
    binary_types = [
        "application/octet-stream",
        "application/zip",
        "application/gzip",
        "application/x-gzip",
        "application/x-tar",
        "application/x-bzip2",
        "application/sql",
    ]
    for bt in binary_types:
        if bt in content_type:
            return True

    # Plain text with SQL keywords = database dump
    if "text/plain" in content_type or content_type == "":
        body_upper = body[:4096].upper()
        if any(kw.upper() in body_upper for kw in SQL_KEYWORDS):
            return True

    # Large body that isn't an HTML error page
    if len(body) > 1000 and "<html" not in body[:200].lower():
        # Check for SQL keywords directly in body regardless of content type
        body_upper = body[:4096].upper()
        if any(kw.upper() in body_upper for kw in SQL_KEYWORDS):
            return True

    return False


def _looks_like_restricted(status_code: int) -> bool:
    """Return True if the server indicates the file exists but is restricted."""
    return status_code in (401, 403)


class BackupFileAttack(Attack):
    """Detect exposed backup files, database dumps, archives, and editor temps."""

    name = "exposure.backup_files"
    category = "exposure"
    severity = Severity.CRITICAL
    description = "Probe for exposed backup files, database dumps, and archive files"
    target_types = {"app", "wordpress", "generic"}

    async def execute(self, client) -> list[AttackResult]:
        """Run all backup file exposure variants."""
        results = []

        results.append(await self._test_database_dumps(client))
        results.append(await self._test_config_backups(client))
        results.append(await self._test_archive_files(client))
        results.append(await self._test_editor_backups(client))

        return results

    def _get_hostname_paths(self) -> list[str]:
        """Return hostname-based SQL dump paths from config if available."""
        hostname = self._config.get("target", {}).get("hostname", "")
        if hostname:
            # Strip port if present
            host = hostname.split(":")[0]
            return [f"/{host}.sql"]
        return []

    async def _test_database_dumps(self, client) -> AttackResult:
        """Probe for common database dump paths."""
        start = time.monotonic()
        aws_mode = self._is_aws_mode()

        paths = [
            "/backup.sql",
            "/dump.sql",
            "/db.sql",
            "/database.sql",
            "/backup.sql.gz",
            "/site.sql",
            "/data.sql",
        ] + self._get_hostname_paths()

        vulnerable_paths = []
        restricted_paths = []

        try:
            for path in paths:
                try:
                    status_code, body, headers = await client.get(path, cookies={})

                    if _looks_like_real_file(status_code, body, headers):
                        content_type = headers.get("Content-Type", "unknown")
                        content_length = headers.get("Content-Length", str(len(body)))
                        vulnerable_paths.append({
                            "path": path,
                            "status": status_code,
                            "content_type": content_type,
                            "content_length": content_length,
                            "preview": body[:200],
                        })
                    elif _looks_like_restricted(status_code):
                        restricted_paths.append(path)

                except Exception as e:
                    logger.debug("Error probing %s: %s", path, e)

                if aws_mode:
                    await asyncio.sleep(AWS_PROBE_DELAY)

            duration = (time.monotonic() - start) * 1000

            if vulnerable_paths:
                found = [p["path"] for p in vulnerable_paths]
                return self._make_result(
                    variant="database_dumps",
                    status=Status.VULNERABLE,
                    evidence=f"Database dump(s) accessible: {', '.join(found)}",
                    details=(
                        f"Found {len(vulnerable_paths)} exposed database dump(s). "
                        f"These files may contain credentials, user data, and full schema. "
                        f"Paths: {', '.join(found)}"
                    ),
                    request={"paths_probed": paths},
                    response={"vulnerable_paths": vulnerable_paths},
                    duration_ms=duration,
                )

            if restricted_paths:
                return self._make_result(
                    variant="database_dumps",
                    status=Status.PARTIAL,
                    severity=Severity.HIGH,
                    evidence=f"Database dump paths exist but access is restricted: {', '.join(restricted_paths)}",
                    details=(
                        f"Server returned 401/403 for {len(restricted_paths)} dump path(s), "
                        f"indicating the files may exist: {', '.join(restricted_paths)}"
                    ),
                    request={"paths_probed": paths},
                    response={"restricted_paths": restricted_paths},
                    duration_ms=duration,
                )

            return self._make_result(
                variant="database_dumps",
                status=Status.DEFENDED,
                evidence=f"No database dump files found at {len(paths)} probed paths",
                details=f"Probed {len(paths)} common dump paths; none returned accessible content",
                request={"paths_probed": paths},
                duration_ms=duration,
            )

        except Exception as e:
            return self._make_result(
                variant="database_dumps",
                status=Status.ERROR,
                details=str(e),
                duration_ms=(time.monotonic() - start) * 1000,
            )

    async def _test_config_backups(self, client) -> AttackResult:
        """Probe for configuration file backups."""
        start = time.monotonic()
        aws_mode = self._is_aws_mode()

        paths = [
            "/wp-config.php.bak",
            "/wp-config.php~",
            "/wp-config.php.old",
            "/wp-config.php.orig",
            "/config.php.bak",
            "/config.php~",
            "/config.php.old",
            "/.htaccess.bak",
            "/.htaccess~",
            "/web.config.bak",
            "/web.config~",
            "/settings.php.bak",
            "/.env.bak",
            "/.env~",
            "/.env.old",
        ]

        vulnerable_paths = []
        restricted_paths = []

        try:
            for path in paths:
                try:
                    status_code, body, headers = await client.get(path, cookies={})

                    if status_code == 200 and len(body) > 0:
                        # Config backups: any non-empty 200 is suspicious
                        # Check it's not a custom 404 HTML page
                        body_lower = body[:500].lower()
                        is_html_error = (
                            "<html" in body_lower
                            and any(kw in body_lower for kw in ["not found", "404", "error", "page"])
                            and len(body) < 2000
                        )
                        if not is_html_error:
                            content_type = headers.get("Content-Type", "unknown")
                            vulnerable_paths.append({
                                "path": path,
                                "status": status_code,
                                "content_type": content_type,
                                "size": len(body),
                                "preview": body[:200],
                            })
                    elif _looks_like_restricted(status_code):
                        restricted_paths.append(path)

                except Exception as e:
                    logger.debug("Error probing %s: %s", path, e)

                if aws_mode:
                    await asyncio.sleep(AWS_PROBE_DELAY)

            duration = (time.monotonic() - start) * 1000

            if vulnerable_paths:
                found = [p["path"] for p in vulnerable_paths]
                return self._make_result(
                    variant="config_backups",
                    status=Status.VULNERABLE,
                    evidence=f"Configuration backup(s) accessible: {', '.join(found)}",
                    details=(
                        f"Found {len(vulnerable_paths)} exposed configuration backup(s). "
                        f"These may contain database credentials, API keys, and secrets. "
                        f"Paths: {', '.join(found)}"
                    ),
                    request={"paths_probed": paths},
                    response={"vulnerable_paths": vulnerable_paths},
                    duration_ms=duration,
                )

            if restricted_paths:
                return self._make_result(
                    variant="config_backups",
                    status=Status.PARTIAL,
                    severity=Severity.HIGH,
                    evidence=f"Config backup paths restricted (may exist): {', '.join(restricted_paths)}",
                    details=(
                        f"Server returned 401/403 for {len(restricted_paths)} config backup path(s). "
                        f"Files may exist but access is blocked."
                    ),
                    request={"paths_probed": paths},
                    response={"restricted_paths": restricted_paths},
                    duration_ms=duration,
                )

            return self._make_result(
                variant="config_backups",
                status=Status.DEFENDED,
                evidence=f"No configuration backup files found at {len(paths)} probed paths",
                details=f"Probed {len(paths)} common config backup paths; none returned accessible content",
                request={"paths_probed": paths},
                duration_ms=duration,
            )

        except Exception as e:
            return self._make_result(
                variant="config_backups",
                status=Status.ERROR,
                details=str(e),
                duration_ms=(time.monotonic() - start) * 1000,
            )

    async def _test_archive_files(self, client) -> AttackResult:
        """Probe for exposed archive files containing site source or backups."""
        start = time.monotonic()
        aws_mode = self._is_aws_mode()

        paths = [
            "/backup.zip",
            "/backup.tar.gz",
            "/backup.tar",
            "/backup.tgz",
            "/site.zip",
            "/site.tar.gz",
            "/www.zip",
            "/www.tar.gz",
            "/public_html.zip",
            "/public_html.tar.gz",
            "/html.zip",
            "/html.tar.gz",
            "/web.zip",
            "/web.tar.gz",
            "/httpdocs.zip",
            "/htdocs.zip",
        ]

        vulnerable_paths = []
        restricted_paths = []

        try:
            for path in paths:
                try:
                    status_code, body, headers = await client.get(path, cookies={})
                    content_type = headers.get("Content-Type", "").lower()

                    if status_code == 200:
                        # Archives should have binary content type or non-HTML
                        is_archive = (
                            "zip" in content_type
                            or "gzip" in content_type
                            or "tar" in content_type
                            or "octet-stream" in content_type
                            or (len(body) > 1000 and "text/html" not in content_type)
                        )
                        # Also check magic bytes for zip (PK\x03\x04) and gzip (\x1f\x8b)
                        body_bytes = body[:4] if body else ""
                        has_archive_magic = (
                            body_bytes.startswith("PK")
                            or body_bytes[:2] == "\x1f\x8b"
                        )

                        if is_archive or has_archive_magic:
                            content_length = headers.get("Content-Length", str(len(body)))
                            vulnerable_paths.append({
                                "path": path,
                                "status": status_code,
                                "content_type": content_type,
                                "content_length": content_length,
                            })
                    elif _looks_like_restricted(status_code):
                        restricted_paths.append(path)

                except Exception as e:
                    logger.debug("Error probing %s: %s", path, e)

                if aws_mode:
                    await asyncio.sleep(AWS_PROBE_DELAY)

            duration = (time.monotonic() - start) * 1000

            if vulnerable_paths:
                found = [p["path"] for p in vulnerable_paths]
                return self._make_result(
                    variant="archive_files",
                    status=Status.VULNERABLE,
                    evidence=f"Archive file(s) accessible: {', '.join(found)}",
                    details=(
                        f"Found {len(vulnerable_paths)} exposed archive(s) that may contain "
                        f"full site source code, configuration files, and sensitive data. "
                        f"Paths: {', '.join(found)}"
                    ),
                    request={"paths_probed": paths},
                    response={"vulnerable_paths": vulnerable_paths},
                    duration_ms=duration,
                )

            if restricted_paths:
                return self._make_result(
                    variant="archive_files",
                    status=Status.PARTIAL,
                    severity=Severity.HIGH,
                    evidence=f"Archive paths exist but are restricted: {', '.join(restricted_paths)}",
                    details=(
                        f"Server returned 401/403 for {len(restricted_paths)} archive path(s). "
                        f"Files may exist but access is blocked."
                    ),
                    request={"paths_probed": paths},
                    response={"restricted_paths": restricted_paths},
                    duration_ms=duration,
                )

            return self._make_result(
                variant="archive_files",
                status=Status.DEFENDED,
                evidence=f"No archive files found at {len(paths)} probed paths",
                details=f"Probed {len(paths)} common archive paths; none returned accessible content",
                request={"paths_probed": paths},
                duration_ms=duration,
            )

        except Exception as e:
            return self._make_result(
                variant="archive_files",
                status=Status.ERROR,
                details=str(e),
                duration_ms=(time.monotonic() - start) * 1000,
            )

    async def _test_editor_backups(self, client) -> AttackResult:
        """Probe for editor temporary and swap files."""
        start = time.monotonic()
        aws_mode = self._is_aws_mode()

        # Common files that editors leave backup/swap copies of
        base_files = [
            "/index.php",
            "/index.html",
            "/wp-config.php",
            "/config.php",
            "/settings.php",
            "/.htaccess",
            "/login.php",
            "/admin.php",
        ]

        # Editor backup suffixes
        paths = []
        for base in base_files:
            paths.append(base + "~")          # Emacs/Nano tilde backup
            paths.append(base + ".swp")       # Vim swap
            paths.append(base + ".swo")       # Vim swap overflow
            paths.append(base + ".bak")       # Generic backup

        # Also check common standalone swap/backup filenames
        paths.extend([
            "/.wp-config.php.swp",
            "/.index.php.swp",
            "/wp-login.php~",
            "/wp-login.php.swp",
        ])

        vulnerable_paths = []
        restricted_paths = []

        try:
            for path in paths:
                try:
                    status_code, body, headers = await client.get(path, cookies={})
                    content_type = headers.get("Content-Type", "").lower()

                    if status_code == 200 and len(body) > 0:
                        # Swap/temp files usually aren't served as text/html
                        # Vim swap files start with "b0VIM"
                        is_swap_magic = body[:5] == "b0VIM"
                        is_not_html = "text/html" not in content_type
                        is_large_enough = len(body) > 100

                        if is_swap_magic or (is_not_html and is_large_enough):
                            vulnerable_paths.append({
                                "path": path,
                                "status": status_code,
                                "content_type": content_type,
                                "size": len(body),
                                "is_vim_swap": is_swap_magic,
                            })
                    elif _looks_like_restricted(status_code):
                        restricted_paths.append(path)

                except Exception as e:
                    logger.debug("Error probing %s: %s", path, e)

                if aws_mode:
                    await asyncio.sleep(AWS_PROBE_DELAY)

            duration = (time.monotonic() - start) * 1000

            if vulnerable_paths:
                found = [p["path"] for p in vulnerable_paths]
                return self._make_result(
                    variant="editor_backups",
                    status=Status.VULNERABLE,
                    evidence=f"Editor backup/swap file(s) accessible: {', '.join(found)}",
                    details=(
                        f"Found {len(vulnerable_paths)} exposed editor backup file(s). "
                        f"Vim swap files and tilde backups can expose full source code "
                        f"including credentials. Paths: {', '.join(found)}"
                    ),
                    request={"paths_probed": paths},
                    response={"vulnerable_paths": vulnerable_paths},
                    duration_ms=duration,
                )

            if restricted_paths:
                return self._make_result(
                    variant="editor_backups",
                    status=Status.PARTIAL,
                    severity=Severity.HIGH,
                    evidence=f"Editor backup paths exist but are restricted: {', '.join(restricted_paths)}",
                    details=(
                        f"Server returned 401/403 for {len(restricted_paths)} editor backup path(s). "
                        f"Files may exist but are access controlled."
                    ),
                    request={"paths_probed": paths},
                    response={"restricted_paths": restricted_paths},
                    duration_ms=duration,
                )

            return self._make_result(
                variant="editor_backups",
                status=Status.DEFENDED,
                evidence=f"No editor backup files found at {len(paths)} probed paths",
                details=f"Probed {len(paths)} common editor backup paths; none returned accessible content",
                request={"paths_probed": paths},
                duration_ms=duration,
            )

        except Exception as e:
            return self._make_result(
                variant="editor_backups",
                status=Status.ERROR,
                details=str(e),
                duration_ms=(time.monotonic() - start) * 1000,
            )

    async def cleanup(self, client) -> None:
        """No persistent state created by backup file probes."""
        pass
