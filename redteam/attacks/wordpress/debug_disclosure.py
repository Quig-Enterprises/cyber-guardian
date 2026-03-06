"""WordPress debug mode and log exposure attacks — MEDIUM severity.

Tests for debug mode artifacts: exposed debug.log files, visible PHP
errors in page output, phpinfo() pages, and debug plugin output leaking
to unauthenticated users.
"""

import re
import time
import logging

from redteam.base import Attack, AttackResult, Severity, Status

logger = logging.getLogger(__name__)

DEBUG_LOG_PATTERNS = [
    "PHP Fatal error",
    "PHP Warning",
    "PHP Notice",
    "PHP Deprecated",
    "PHP Parse error",
    "Stack trace",
    "thrown in",
    "on line",
]

PHP_ERROR_PATTERNS = [
    "Fatal error:",
    "Warning:",
    "Notice:",
    "Deprecated:",
    "Parse error:",
]

PHPINFO_PATHS = [
    "/phpinfo.php",
    "/info.php",
    "/php_info.php",
    "/test.php",
]


class DebugDisclosureAttack(Attack):
    """Test for WordPress debug mode and log exposure."""

    name = "wordpress.debug_disclosure"
    category = "wordpress"
    severity = Severity.MEDIUM
    description = "Debug mode artifacts exposing PHP errors, stack traces, and server configuration"
    target_types = {"wordpress"}

    async def execute(self, client) -> list[AttackResult]:
        results = []

        results.append(await self._test_debug_log(client))
        results.append(await self._test_wp_debug_display(client))
        results.extend(await self._test_phpinfo_exposure(client))
        results.append(await self._test_display_errors(client))
        results.append(await self._test_query_monitor_output(client))

        return results

    # ------------------------------------------------------------------
    # debug.log
    # ------------------------------------------------------------------
    async def _test_debug_log(self, client) -> AttackResult:
        """GET /wp-content/debug.log — CRITICAL if contains PHP errors."""
        path = f"{client.content_path}/debug.log"
        start = time.monotonic()
        try:
            status, body, headers = await client.get(path, cookies={})
            duration = (time.monotonic() - start) * 1000

            if status == 200 and len(body) > 10:
                found = [p for p in DEBUG_LOG_PATTERNS if p in body]
                if found:
                    return self._make_result(
                        variant="debug_log",
                        status=Status.VULNERABLE,
                        severity=Severity.CRITICAL,
                        evidence=f"debug.log accessible with {len(found)} error patterns: {found[:4]}",
                        details=(
                            f"GET {path} returned HTTP {status} with {len(body)} bytes. "
                            f"Contains PHP error/stack trace patterns: {', '.join(found[:4])}. "
                            f"Debug logs expose file paths, function names, database queries, "
                            f"and potentially sensitive data from error context."
                        ),
                        request={"method": "GET", "path": path},
                        response={"status": status, "body": body[:500]},
                        duration_ms=duration,
                    )

                # File exists but no recognizable patterns — still a concern
                return self._make_result(
                    variant="debug_log",
                    status=Status.VULNERABLE,
                    severity=Severity.HIGH,
                    evidence=f"debug.log accessible ({len(body)} bytes), patterns not matched",
                    details=(
                        f"GET {path} returned HTTP {status} with {len(body)} bytes of content. "
                        f"File is publicly accessible even though standard error patterns "
                        f"were not matched. May contain application-specific debug output."
                    ),
                    request={"method": "GET", "path": path},
                    response={"status": status, "body": body[:500]},
                    duration_ms=duration,
                )

            return self._make_result(
                variant="debug_log",
                status=Status.DEFENDED,
                evidence=f"HTTP {status}, debug.log not accessible",
                details=f"GET {path} returned HTTP {status}. Debug log is not publicly exposed.",
                request={"method": "GET", "path": path},
                response={"status": status},
                duration_ms=duration,
            )
        except Exception as e:
            return self._make_result(
                variant="debug_log",
                status=Status.ERROR,
                details=f"Error testing debug.log: {e}",
                duration_ms=(time.monotonic() - start) * 1000,
            )

    # ------------------------------------------------------------------
    # WP_DEBUG_DISPLAY — visible PHP errors on pages
    # ------------------------------------------------------------------
    async def _test_wp_debug_display(self, client) -> AttackResult:
        """GET homepage — check for visible PHP errors/warnings/notices."""
        start = time.monotonic()
        try:
            status, body, headers = await client.get("/", cookies={})
            duration = (time.monotonic() - start) * 1000

            found = [p for p in PHP_ERROR_PATTERNS if p in body]

            if found:
                return self._make_result(
                    variant="wp_debug_display",
                    status=Status.VULNERABLE,
                    severity=Severity.HIGH,
                    evidence=f"PHP errors visible on homepage: {found}",
                    details=(
                        f"Homepage (HTTP {status}) contains visible PHP error output: "
                        f"{', '.join(found)}. WP_DEBUG_DISPLAY is likely enabled. "
                        f"Error messages expose file paths, line numbers, and internal logic."
                    ),
                    request={"method": "GET", "path": "/"},
                    response={"status": status, "body": body[:500]},
                    duration_ms=duration,
                )

            return self._make_result(
                variant="wp_debug_display",
                status=Status.DEFENDED,
                evidence="No PHP errors visible on homepage",
                details="Homepage does not contain visible PHP error output.",
                request={"method": "GET", "path": "/"},
                response={"status": status},
                duration_ms=duration,
            )
        except Exception as e:
            return self._make_result(
                variant="wp_debug_display",
                status=Status.ERROR,
                details=f"Error testing WP_DEBUG_DISPLAY: {e}",
                duration_ms=(time.monotonic() - start) * 1000,
            )

    # ------------------------------------------------------------------
    # phpinfo() exposure
    # ------------------------------------------------------------------
    async def _test_phpinfo_exposure(self, client) -> list[AttackResult]:
        """Try common phpinfo() file paths — CRITICAL if found."""
        results = []

        for path in PHPINFO_PATHS:
            start = time.monotonic()
            try:
                status, body, headers = await client.get(path, cookies={})
                duration = (time.monotonic() - start) * 1000

                is_phpinfo = (
                    status == 200
                    and "PHP Version" in body
                    and "phpinfo()" in body
                )

                if is_phpinfo:
                    results.append(self._make_result(
                        variant="phpinfo_exposure",
                        status=Status.VULNERABLE,
                        severity=Severity.CRITICAL,
                        evidence=f"phpinfo() exposed at {path}",
                        details=(
                            f"GET {path} returned phpinfo() output (HTTP {status}). "
                            f"Exposes complete PHP configuration, loaded modules, "
                            f"environment variables, and server paths. "
                            f"Remove this file immediately."
                        ),
                        request={"method": "GET", "path": path},
                        response={"status": status, "body": body[:400]},
                        duration_ms=duration,
                    ))
                else:
                    results.append(self._make_result(
                        variant="phpinfo_exposure",
                        status=Status.DEFENDED,
                        evidence=f"{path} not a phpinfo page (HTTP {status})",
                        details=f"GET {path} returned HTTP {status}, not phpinfo output.",
                        request={"method": "GET", "path": path},
                        response={"status": status},
                        duration_ms=duration,
                    ))
            except Exception as e:
                results.append(self._make_result(
                    variant="phpinfo_exposure",
                    status=Status.ERROR,
                    details=f"Error testing {path}: {e}",
                    duration_ms=(time.monotonic() - start) * 1000,
                ))

        return results

    # ------------------------------------------------------------------
    # display_errors — trigger error via malformed request
    # ------------------------------------------------------------------
    async def _test_display_errors(self, client) -> AttackResult:
        """Send malformed parameters to trigger potential error display."""
        path = "/?p=999999%00%ff"
        start = time.monotonic()
        try:
            status, body, headers = await client.get(path, cookies={})
            duration = (time.monotonic() - start) * 1000

            found = [p for p in PHP_ERROR_PATTERNS if p in body]

            if found:
                return self._make_result(
                    variant="display_errors",
                    status=Status.VULNERABLE,
                    severity=Severity.HIGH,
                    evidence=f"Malformed request triggered visible errors: {found}",
                    details=(
                        f"GET {path} with malformed parameters triggered visible "
                        f"PHP error output: {', '.join(found)}. display_errors is On "
                        f"and errors are not handled gracefully."
                    ),
                    request={"method": "GET", "path": path},
                    response={"status": status, "body": body[:500]},
                    duration_ms=duration,
                )

            return self._make_result(
                variant="display_errors",
                status=Status.DEFENDED,
                evidence=f"Malformed request handled cleanly (HTTP {status})",
                details=(
                    "Malformed request parameters did not trigger visible PHP errors. "
                    "Error display appears to be suppressed."
                ),
                request={"method": "GET", "path": path},
                response={"status": status},
                duration_ms=duration,
            )
        except Exception as e:
            return self._make_result(
                variant="display_errors",
                status=Status.ERROR,
                details=f"Error testing display_errors: {e}",
                duration_ms=(time.monotonic() - start) * 1000,
            )

    # ------------------------------------------------------------------
    # Query Monitor / Debug Bar output
    # ------------------------------------------------------------------
    async def _test_query_monitor_output(self, client) -> AttackResult:
        """GET homepage — check for Query Monitor or Debug Bar output."""
        start = time.monotonic()
        try:
            status, body, headers = await client.get("/", cookies={})
            duration = (time.monotonic() - start) * 1000

            qm_present = 'class="qm-' in body or "id=\"query-monitor" in body.lower()
            db_present = 'id="debug-bar' in body.lower() or 'class="debug-bar' in body.lower()

            if qm_present or db_present:
                plugin_name = "Query Monitor" if qm_present else "Debug Bar"
                return self._make_result(
                    variant="query_monitor_output",
                    status=Status.VULNERABLE,
                    severity=Severity.HIGH,
                    evidence=f"{plugin_name} output visible to unauthenticated users",
                    details=(
                        f"Homepage contains {plugin_name} debug output visible to "
                        f"unauthenticated visitors. This exposes database queries, "
                        f"PHP errors, hooks, and performance data. "
                        f"Restrict debug plugin output to authenticated administrators only."
                    ),
                    request={"method": "GET", "path": "/"},
                    response={"status": status, "body": body[:500]},
                    duration_ms=duration,
                )

            return self._make_result(
                variant="query_monitor_output",
                status=Status.DEFENDED,
                evidence="No debug plugin output visible on homepage",
                details="Homepage does not contain Query Monitor or Debug Bar output.",
                request={"method": "GET", "path": "/"},
                response={"status": status},
                duration_ms=duration,
            )
        except Exception as e:
            return self._make_result(
                variant="query_monitor_output",
                status=Status.ERROR,
                details=f"Error testing debug plugin output: {e}",
                duration_ms=(time.monotonic() - start) * 1000,
            )
