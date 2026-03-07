"""Sensitive path and endpoint exposure detection.

Probes for commonly exposed sensitive paths including PHP info pages,
admin panels, debug endpoints, version disclosure files, and API
documentation that should not be publicly accessible.

Evaluation:
- phpinfo() output detected -> VULNERABLE (CRITICAL)
- Admin panel accessible without auth (200) -> VULNERABLE
- Admin panel returns 401/403 -> DEFENDED (auth required)
- Debug/status endpoints with sensitive info -> VULNERABLE
- Version/changelog files accessible -> VULNERABLE (LOW, info disclosure)
- API docs publicly accessible -> VULNERABLE (MEDIUM)
"""

import asyncio
import time
import logging

from redteam.base import Attack, AttackResult, Severity, Status

logger = logging.getLogger(__name__)

# Delay between probes in AWS mode (seconds)
AWS_PROBE_DELAY = 0.1

# Indicators that a phpinfo() page is being served
PHPINFO_INDICATORS = [
    "phpinfo()",
    "<title>phpinfo()</title>",
    "PHP Version",
    "php_info",
    "PHP Extension",
    "Loaded Configuration File",
    "_SERVER[",
]

# Indicators of sensitive data in debug/status endpoints
DEBUG_SENSITIVE_INDICATORS = [
    "SERVER_NAME",
    "SERVER_ADDR",
    "DB_PASSWORD",
    "DATABASE_URL",
    "SECRET_KEY",
    "REMOTE_ADDR",
    "document_root",
    "DOCUMENT_ROOT",
    "_SERVER",
    "_ENV",
    "phpinfo",
    "stack trace",
    "Stack Trace",
    "Traceback",
    "Exception",
    "Fatal error",
    "Warning:",
]

# Apache server-status indicators
APACHE_STATUS_INDICATORS = [
    "Server Version",
    "Server MPM",
    "Apache Server Status",
    "requests currently being processed",
    "Server uptime",
]

# Version file indicators
VERSION_FILE_INDICATORS = [
    "version",
    "release",
    "changelog",
    "Version",
    "Release",
    "Changelog",
]


class SensitivePathAttack(Attack):
    """Detect exposed sensitive paths including admin panels and debug endpoints."""

    name = "exposure.sensitive_paths"
    category = "exposure"
    severity = Severity.HIGH
    description = "Probe for exposed admin panels, debug endpoints, and information disclosure paths"
    target_types = {"app", "wordpress", "generic"}

    async def execute(self, client) -> list[AttackResult]:
        """Run all sensitive path exposure variants."""
        results = []

        results.append(await self._test_phpinfo(client))
        results.append(await self._test_admin_panels(client))
        results.append(await self._test_debug_endpoints(client))
        results.append(await self._test_version_files(client))
        results.append(await self._test_api_docs(client))

        return results

    async def _test_phpinfo(self, client) -> AttackResult:
        """Probe for exposed phpinfo() pages."""
        start = time.monotonic()
        aws_mode = self._is_aws_mode()

        paths = [
            "/phpinfo.php",
            "/info.php",
            "/php_info.php",
            "/test.php",
            "/phptest.php",
            "/php.php",
            "/i.php",
        ]

        vulnerable_paths = []

        try:
            for path in paths:
                try:
                    status_code, body, headers = await client.get(path, cookies={})

                    if status_code == 200 and body:
                        if any(indicator in body for indicator in PHPINFO_INDICATORS):
                            vulnerable_paths.append({
                                "path": path,
                                "status": status_code,
                                "preview": body[:300],
                            })

                except Exception as e:
                    logger.debug("Error probing %s: %s", path, e)

                if aws_mode:
                    await asyncio.sleep(AWS_PROBE_DELAY)

            duration = (time.monotonic() - start) * 1000

            if vulnerable_paths:
                found = [p["path"] for p in vulnerable_paths]
                return self._make_result(
                    variant="phpinfo",
                    status=Status.VULNERABLE,
                    severity=Severity.CRITICAL,
                    evidence=f"phpinfo() page(s) accessible: {', '.join(found)}",
                    details=(
                        f"Found {len(vulnerable_paths)} phpinfo() page(s). "
                        f"These expose PHP configuration, server environment variables, "
                        f"loaded extensions, and potentially sensitive credentials. "
                        f"Remove immediately. Paths: {', '.join(found)}"
                    ),
                    request={"paths_probed": paths},
                    response={"vulnerable_paths": vulnerable_paths},
                    duration_ms=duration,
                )

            return self._make_result(
                variant="phpinfo",
                status=Status.DEFENDED,
                evidence=f"No phpinfo() pages found at {len(paths)} probed paths",
                details=f"Probed {len(paths)} common phpinfo paths; none returned phpinfo() output",
                request={"paths_probed": paths},
                duration_ms=duration,
            )

        except Exception as e:
            return self._make_result(
                variant="phpinfo",
                status=Status.ERROR,
                details=str(e),
                duration_ms=(time.monotonic() - start) * 1000,
            )

    async def _test_admin_panels(self, client) -> AttackResult:
        """Probe for accessible admin panels without authentication."""
        start = time.monotonic()
        aws_mode = self._is_aws_mode()

        paths = [
            "/admin/",
            "/admin",
            "/administrator/",
            "/administrator",
            "/phpmyadmin/",
            "/phpmyadmin",
            "/adminer.php",
            "/adminer/",
            "/pma/",
            "/pma",
            "/mysql/",
            "/db/",
            "/_profiler/",
            "/_profiler",
            "/manage/",
            "/management/",
            "/controlpanel/",
            "/cpanel/",
            "/wp-admin/",
        ]

        accessible_paths = []
        auth_protected_paths = []

        try:
            for path in paths:
                try:
                    status_code, body, headers = await client.get(path, cookies={})

                    if status_code == 200:
                        # 200 without auth is a problem unless it's just a redirect to login
                        body_lower = body[:1000].lower()
                        # Check if it's a login form (not the actual panel)
                        is_login_page = any(kw in body_lower for kw in [
                            "login", "password", "username", "sign in", "log in"
                        ]) and any(kw in body_lower for kw in [
                            "<form", "input type=\"password\"", "input type='password'"
                        ])

                        if is_login_page:
                            # Login form is acceptable — auth required
                            auth_protected_paths.append({
                                "path": path,
                                "status": status_code,
                                "note": "login form present",
                            })
                        else:
                            accessible_paths.append({
                                "path": path,
                                "status": status_code,
                                "preview": body[:200],
                            })

                    elif status_code in (401, 403):
                        auth_protected_paths.append({
                            "path": path,
                            "status": status_code,
                            "note": f"HTTP {status_code}",
                        })

                except Exception as e:
                    logger.debug("Error probing %s: %s", path, e)

                if aws_mode:
                    await asyncio.sleep(AWS_PROBE_DELAY)

            duration = (time.monotonic() - start) * 1000

            if accessible_paths:
                found = [p["path"] for p in accessible_paths]
                return self._make_result(
                    variant="admin_panels",
                    status=Status.VULNERABLE,
                    evidence=f"Admin panel(s) accessible without authentication: {', '.join(found)}",
                    details=(
                        f"Found {len(accessible_paths)} admin panel(s) returning 200 without "
                        f"authentication or login redirect. These may allow unauthorized access "
                        f"to administrative functions. Paths: {', '.join(found)}"
                    ),
                    request={"paths_probed": paths},
                    response={"accessible_paths": accessible_paths, "auth_protected": auth_protected_paths},
                    duration_ms=duration,
                )

            if auth_protected_paths:
                protected = [p["path"] for p in auth_protected_paths]
                return self._make_result(
                    variant="admin_panels",
                    status=Status.DEFENDED,
                    evidence=f"Admin path(s) found but authentication required: {', '.join(protected[:5])}",
                    details=(
                        f"Found {len(auth_protected_paths)} admin path(s) that require authentication "
                        f"(login form or 401/403). Access is properly restricted."
                    ),
                    request={"paths_probed": paths},
                    response={"auth_protected": auth_protected_paths},
                    duration_ms=duration,
                )

            return self._make_result(
                variant="admin_panels",
                status=Status.DEFENDED,
                evidence=f"No admin panels found at {len(paths)} probed paths",
                details=f"Probed {len(paths)} common admin paths; none were accessible",
                request={"paths_probed": paths},
                duration_ms=duration,
            )

        except Exception as e:
            return self._make_result(
                variant="admin_panels",
                status=Status.ERROR,
                details=str(e),
                duration_ms=(time.monotonic() - start) * 1000,
            )

    async def _test_debug_endpoints(self, client) -> AttackResult:
        """Probe for debug and status endpoints that expose sensitive information."""
        start = time.monotonic()
        aws_mode = self._is_aws_mode()

        paths = [
            "/debug",
            "/debug/",
            "/trace",
            "/status",
            "/server-status",
            "/server-info",
            "/health",
            "/healthz",
            "/info",
            "/_debug/",
            "/__debug__/",
            "/actuator",
            "/actuator/env",
            "/actuator/health",
            "/actuator/info",
            "/actuator/metrics",
            "/.env",
            "/env",
        ]

        vulnerable_paths = []
        info_paths = []

        try:
            for path in paths:
                try:
                    status_code, body, headers = await client.get(path, cookies={})

                    if status_code == 200 and body:
                        # Check for sensitive indicators in the response
                        has_sensitive = any(
                            indicator in body
                            for indicator in DEBUG_SENSITIVE_INDICATORS
                        )
                        has_apache_status = any(
                            indicator in body
                            for indicator in APACHE_STATUS_INDICATORS
                        )

                        if has_sensitive or has_apache_status:
                            indicators_found = [
                                ind for ind in (DEBUG_SENSITIVE_INDICATORS + APACHE_STATUS_INDICATORS)
                                if ind in body
                            ]
                            vulnerable_paths.append({
                                "path": path,
                                "status": status_code,
                                "indicators": indicators_found[:5],
                                "preview": body[:300],
                            })
                        elif len(body) > 50:
                            # Accessible but no obvious sensitive content
                            info_paths.append({
                                "path": path,
                                "status": status_code,
                                "size": len(body),
                            })

                except Exception as e:
                    logger.debug("Error probing %s: %s", path, e)

                if aws_mode:
                    await asyncio.sleep(AWS_PROBE_DELAY)

            duration = (time.monotonic() - start) * 1000

            if vulnerable_paths:
                found = [p["path"] for p in vulnerable_paths]
                all_indicators = []
                for p in vulnerable_paths:
                    all_indicators.extend(p.get("indicators", []))
                unique_indicators = list(set(all_indicators))[:10]

                return self._make_result(
                    variant="debug_endpoints",
                    status=Status.VULNERABLE,
                    evidence=(
                        f"Debug/status endpoint(s) expose sensitive data: {', '.join(found)}. "
                        f"Indicators: {', '.join(unique_indicators)}"
                    ),
                    details=(
                        f"Found {len(vulnerable_paths)} debug/status endpoint(s) that expose "
                        f"sensitive server information. These may reveal environment variables, "
                        f"credentials, stack traces, or server internals. "
                        f"Paths: {', '.join(found)}"
                    ),
                    request={"paths_probed": paths},
                    response={"vulnerable_paths": vulnerable_paths},
                    duration_ms=duration,
                )

            if info_paths:
                found = [p["path"] for p in info_paths]
                return self._make_result(
                    variant="debug_endpoints",
                    status=Status.PARTIAL,
                    severity=Severity.MEDIUM,
                    evidence=f"Debug/status endpoint(s) accessible (no obvious sensitive data): {', '.join(found)}",
                    details=(
                        f"Found {len(info_paths)} accessible debug/status endpoint(s). "
                        f"While no obviously sensitive data was detected, these paths should "
                        f"be restricted. Review manually. Paths: {', '.join(found)}"
                    ),
                    request={"paths_probed": paths},
                    response={"accessible_paths": info_paths},
                    duration_ms=duration,
                )

            return self._make_result(
                variant="debug_endpoints",
                status=Status.DEFENDED,
                evidence=f"No exposed debug endpoints found at {len(paths)} probed paths",
                details=f"Probed {len(paths)} common debug/status paths; none returned accessible sensitive content",
                request={"paths_probed": paths},
                duration_ms=duration,
            )

        except Exception as e:
            return self._make_result(
                variant="debug_endpoints",
                status=Status.ERROR,
                details=str(e),
                duration_ms=(time.monotonic() - start) * 1000,
            )

    async def _test_version_files(self, client) -> AttackResult:
        """Probe for version and changelog files that disclose software versions."""
        start = time.monotonic()
        aws_mode = self._is_aws_mode()

        paths = [
            "/VERSION",
            "/version.txt",
            "/version",
            "/CHANGELOG",
            "/CHANGELOG.md",
            "/CHANGELOG.txt",
            "/CHANGES",
            "/CHANGES.md",
            "/CHANGES.txt",
            "/readme.html",
            "/README.md",
            "/README.txt",
            "/readme.txt",
            "/license.txt",
            "/LICENSE",
            "/LICENSE.txt",
            "/INSTALL",
            "/INSTALL.txt",
            "/RELEASE",
            "/release-notes.txt",
        ]

        vulnerable_paths = []

        try:
            for path in paths:
                try:
                    status_code, body, headers = await client.get(path, cookies={})

                    if status_code == 200 and body and len(body.strip()) > 0:
                        content_type = headers.get("Content-Type", "").lower()
                        body_lower = body[:500].lower()

                        # Check it's actually content (not HTML error page)
                        is_html_error = (
                            "<html" in body_lower
                            and any(kw in body_lower for kw in ["not found", "404", "error"])
                            and len(body) < 2000
                        )

                        if not is_html_error:
                            # Check for version indicators
                            has_version_info = any(
                                ind.lower() in body_lower
                                for ind in VERSION_FILE_INDICATORS
                            )
                            # Or just accessible and non-HTML = info disclosure
                            is_plain_text = "text/html" not in content_type

                            if has_version_info or is_plain_text:
                                # Extract first meaningful line as evidence
                                first_content = body.strip()[:200]
                                vulnerable_paths.append({
                                    "path": path,
                                    "status": status_code,
                                    "content_type": content_type,
                                    "preview": first_content,
                                })

                except Exception as e:
                    logger.debug("Error probing %s: %s", path, e)

                if aws_mode:
                    await asyncio.sleep(AWS_PROBE_DELAY)

            duration = (time.monotonic() - start) * 1000

            if vulnerable_paths:
                found = [p["path"] for p in vulnerable_paths]
                return self._make_result(
                    variant="version_files",
                    status=Status.VULNERABLE,
                    severity=Severity.LOW,
                    evidence=f"Version/info file(s) accessible: {', '.join(found)}",
                    details=(
                        f"Found {len(vulnerable_paths)} version disclosure file(s). "
                        f"These reveal software versions that attackers can use to target "
                        f"known CVEs. Restrict or remove these files. "
                        f"Paths: {', '.join(found)}"
                    ),
                    request={"paths_probed": paths},
                    response={"vulnerable_paths": vulnerable_paths},
                    duration_ms=duration,
                )

            return self._make_result(
                variant="version_files",
                status=Status.DEFENDED,
                evidence=f"No version disclosure files found at {len(paths)} probed paths",
                details=f"Probed {len(paths)} common version/info file paths; none were accessible",
                request={"paths_probed": paths},
                duration_ms=duration,
            )

        except Exception as e:
            return self._make_result(
                variant="version_files",
                status=Status.ERROR,
                details=str(e),
                duration_ms=(time.monotonic() - start) * 1000,
            )

    async def _test_api_docs(self, client) -> AttackResult:
        """Probe for publicly accessible API documentation endpoints."""
        start = time.monotonic()
        aws_mode = self._is_aws_mode()

        paths = [
            "/swagger-ui/",
            "/swagger-ui",
            "/swagger-ui.html",
            "/swagger/",
            "/swagger",
            "/api-docs",
            "/api-docs/",
            "/api/docs",
            "/api/docs/",
            "/openapi.json",
            "/openapi.yaml",
            "/swagger.json",
            "/swagger.yaml",
            "/v1/api-docs",
            "/v2/api-docs",
            "/v3/api-docs",
            "/redoc",
            "/redoc/",
            "/docs/",
            "/graphql",
            "/graphiql",
            "/graphiql/",
            "/__graphql",
        ]

        # Indicators that confirm API doc content
        api_doc_indicators = [
            "swagger",
            "openapi",
            "Swagger UI",
            "ReDoc",
            '"paths"',
            '"info"',
            '"openapi"',
            '"swagger"',
            "GraphQL",
            "graphql",
            "mutation",
            "schema",
        ]

        vulnerable_paths = []
        restricted_paths = []

        try:
            for path in paths:
                try:
                    status_code, body, headers = await client.get(path, cookies={})

                    if status_code == 200 and body:
                        content_type = headers.get("Content-Type", "").lower()
                        body_sample = body[:2000]

                        is_api_doc = any(
                            indicator in body_sample
                            for indicator in api_doc_indicators
                        )
                        is_json = "application/json" in content_type
                        is_yaml = "application/yaml" in content_type or "text/yaml" in content_type

                        if is_api_doc or is_json or is_yaml:
                            vulnerable_paths.append({
                                "path": path,
                                "status": status_code,
                                "content_type": content_type,
                                "preview": body_sample[:300],
                            })

                    elif status_code in (401, 403):
                        restricted_paths.append({
                            "path": path,
                            "status": status_code,
                        })

                except Exception as e:
                    logger.debug("Error probing %s: %s", path, e)

                if aws_mode:
                    await asyncio.sleep(AWS_PROBE_DELAY)

            duration = (time.monotonic() - start) * 1000

            if vulnerable_paths:
                found = [p["path"] for p in vulnerable_paths]
                return self._make_result(
                    variant="api_docs",
                    status=Status.VULNERABLE,
                    severity=Severity.MEDIUM,
                    evidence=f"API documentation publicly accessible: {', '.join(found)}",
                    details=(
                        f"Found {len(vulnerable_paths)} publicly accessible API documentation "
                        f"endpoint(s). These expose API endpoints, parameters, authentication "
                        f"schemes, and data models to unauthenticated users. "
                        f"Restrict access to authorized users only. "
                        f"Paths: {', '.join(found)}"
                    ),
                    request={"paths_probed": paths},
                    response={"vulnerable_paths": vulnerable_paths},
                    duration_ms=duration,
                )

            if restricted_paths:
                protected = [p["path"] for p in restricted_paths]
                return self._make_result(
                    variant="api_docs",
                    status=Status.DEFENDED,
                    evidence=f"API doc path(s) found but access restricted: {', '.join(protected)}",
                    details=(
                        f"Found {len(restricted_paths)} API documentation path(s) that return "
                        f"401/403. Access is properly restricted."
                    ),
                    request={"paths_probed": paths},
                    response={"restricted_paths": restricted_paths},
                    duration_ms=duration,
                )

            return self._make_result(
                variant="api_docs",
                status=Status.DEFENDED,
                evidence=f"No publicly accessible API documentation found at {len(paths)} probed paths",
                details=f"Probed {len(paths)} common API doc paths; none were publicly accessible",
                request={"paths_probed": paths},
                duration_ms=duration,
            )

        except Exception as e:
            return self._make_result(
                variant="api_docs",
                status=Status.ERROR,
                details=str(e),
                duration_ms=(time.monotonic() - start) * 1000,
            )

    async def cleanup(self, client) -> None:
        """No persistent state created by sensitive path probes."""
        pass
