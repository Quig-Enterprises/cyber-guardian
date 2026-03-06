"""WordPress plugin audit engine — HIGH severity.

Auto-discovers a plugin's attack surface (REST routes, AJAX actions, files)
and runs targeted security tests against each endpoint. This is the most
comprehensive WordPress attack module in the framework.

Phases:
  1. Recon       — wordpress.org metadata + readme version comparison
  2. Discovery   — REST route enumeration + AJAX action probing
  3. Injection   — auth bypass, SQLi, XSS, nonce checks on discovered endpoints
  4. File-level  — directory listing + direct PHP file access
"""

import json
import re
import time
import asyncio
import logging

from redteam.base import Attack, AttackResult, Severity, Status

logger = logging.getLogger(__name__)

# Payloads used across injection tests
SQLI_PAYLOAD = "' OR 1=1--"
XSS_PAYLOAD = "<script>alert(1)</script>"

# SQL error signatures that indicate the payload reached the database layer
SQL_ERROR_PATTERNS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "pg_query",
    "sqlite3::query",
    "sqlstate[",
    "microsoft ole db",
    "odbc sql server driver",
    "ora-01756",
]

# Common PHP filenames to probe inside a plugin directory
COMMON_PHP_FILES = [
    "{slug}.php",
    "admin.php",
    "ajax.php",
    "api.php",
    "includes/functions.php",
]


class PluginAuditAttack(Attack):
    """Plugin audit engine — auto-discovers and tests plugin attack surfaces."""

    name = "wordpress.plugin_audit"
    category = "wordpress"
    severity = Severity.HIGH
    description = "Plugin audit engine - auto-discovers and tests plugin attack surfaces"
    target_types = {"wordpress"}

    async def execute(self, client) -> list[AttackResult]:
        """Run the full audit pipeline for every configured plugin slug."""
        slugs = self._config.get("target", {}).get("wordpress", {}).get("plugins", [])

        if not slugs:
            return [self._make_result(
                variant="no_plugins",
                status=Status.SKIPPED,
                severity=Severity.INFO,
                evidence="No plugins configured for audit",
                details=(
                    "Set target.wordpress.plugins in config to a list of plugin slugs "
                    "to enable the plugin audit engine."
                ),
            )]

        all_results: list[AttackResult] = []

        for slug in slugs:
            logger.info("Plugin audit starting for: %s", slug)
            try:
                results = await self._audit_plugin(client, slug)
                all_results.extend(results)
            except Exception as exc:
                logger.error("Unhandled error auditing plugin %s: %s", slug, exc)
                all_results.append(self._make_result(
                    variant=f"{slug}/fatal",
                    status=Status.ERROR,
                    details=f"Unhandled exception during audit of {slug}: {exc}",
                ))

        return all_results

    # ==================================================================
    # Top-level per-plugin orchestrator
    # ==================================================================

    async def _audit_plugin(self, client, slug: str) -> list[AttackResult]:
        """Run all four phases against a single plugin slug."""
        results: list[AttackResult] = []

        # Phase 1 — Recon
        results.append(await self._fetch_plugin_info(client, slug))
        results.append(await self._probe_readme(client, slug))

        # Phase 2 — Discovery
        rest_routes = await self._discover_rest_routes(client, slug)
        ajax_actions = await self._discover_ajax_actions(client, slug)

        if rest_routes:
            results.append(self._make_result(
                variant=f"{slug}/rest_routes_found",
                status=Status.VULNERABLE,
                severity=Severity.INFO,
                evidence=f"Discovered {len(rest_routes)} REST routes for {slug}",
                details=json.dumps([r["path"] for r in rest_routes], indent=2),
            ))

        if ajax_actions:
            results.append(self._make_result(
                variant=f"{slug}/ajax_actions_found",
                status=Status.VULNERABLE,
                severity=Severity.INFO,
                evidence=f"Discovered {len(ajax_actions)} AJAX actions for {slug}",
                details=", ".join(ajax_actions),
            ))

        # Phase 3 — Targeted tests on discovered endpoints
        for route in rest_routes:
            results.append(await self._test_route_auth(client, slug, route))
            results.append(await self._test_route_injection(client, slug, route))
            results.append(await self._test_route_nonce(client, slug, route))

        for action in ajax_actions:
            results.append(await self._test_ajax_auth(client, slug, action))
            results.append(await self._test_ajax_injection(client, slug, action))

        # Phase 4 — File-level checks
        results.append(await self._check_directory_listing(client, slug))
        results.extend(await self._check_direct_php_access(client, slug))

        return results

    # ==================================================================
    # Phase 1: Recon
    # ==================================================================

    async def _fetch_plugin_info(self, client, slug: str) -> AttackResult:
        """Fetch metadata from the wordpress.org plugin API."""
        api_url = (
            f"https://api.wordpress.org/plugins/info/1.2/"
            f"?action=plugin_information&request[slug]={slug}"
        )
        start = time.monotonic()
        try:
            async with client._session.get(api_url) as resp:
                duration = (time.monotonic() - start) * 1000
                body = await resp.text()

            if resp.status != 200:
                return self._make_result(
                    variant=f"{slug}/plugin_info",
                    status=Status.ERROR,
                    evidence=f"wordpress.org API returned HTTP {resp.status}",
                    details=f"Could not fetch plugin info for '{slug}' from wordpress.org.",
                    request={"url": api_url},
                    response={"status": resp.status, "body": body[:300]},
                    duration_ms=duration,
                )

            data = json.loads(body)
            version = data.get("version", "unknown")
            tested = data.get("tested", "unknown")
            author = data.get("author", "unknown")
            # Strip HTML from author field
            author_clean = re.sub(r"<[^>]+>", "", author).strip()

            return self._make_result(
                variant=f"{slug}/plugin_info",
                status=Status.DEFENDED,
                severity=Severity.INFO,
                evidence=(
                    f"Plugin: {slug} | Latest: {version} | "
                    f"Tested up to WP {tested} | Author: {author_clean}"
                ),
                details=f"Retrieved metadata from wordpress.org plugin directory.",
                request={"url": api_url},
                response={
                    "version": version,
                    "tested": tested,
                    "author": author_clean,
                    "slug": slug,
                },
                duration_ms=duration,
            )
        except Exception as exc:
            return self._make_result(
                variant=f"{slug}/plugin_info",
                status=Status.ERROR,
                details=f"Error fetching wordpress.org plugin info: {exc}",
                duration_ms=(time.monotonic() - start) * 1000,
            )

    async def _probe_readme(self, client, slug: str) -> AttackResult:
        """Fetch readme.txt from the plugin directory and extract version."""
        path = f"{client.content_path}/plugins/{slug}/readme.txt"
        start = time.monotonic()
        try:
            status_code, body, headers = await client.get(path, cookies={})
            duration = (time.monotonic() - start) * 1000

            if status_code != 200 or not body.strip():
                return self._make_result(
                    variant=f"{slug}/readme",
                    status=Status.DEFENDED,
                    severity=Severity.INFO,
                    evidence=f"readme.txt returned HTTP {status_code} (not accessible)",
                    details="Plugin readme.txt is not publicly accessible.",
                    request={"path": path},
                    response={"status": status_code},
                    duration_ms=duration,
                )

            # Extract Stable tag
            match = re.search(r"Stable\s+tag:\s*(\S+)", body, re.IGNORECASE)
            installed_version = match.group(1) if match else "unknown"

            return self._make_result(
                variant=f"{slug}/readme",
                status=Status.VULNERABLE,
                severity=Severity.LOW,
                evidence=(
                    f"readme.txt accessible — installed version: {installed_version}"
                ),
                details=(
                    f"Plugin readme.txt is publicly accessible at {path}. "
                    f"Stable tag: {installed_version}. This reveals the exact plugin "
                    f"version to attackers for targeted exploit matching."
                ),
                request={"path": path},
                response={"status": status_code, "installed_version": installed_version},
                duration_ms=duration,
            )
        except Exception as exc:
            return self._make_result(
                variant=f"{slug}/readme",
                status=Status.ERROR,
                details=f"Error probing readme.txt: {exc}",
                duration_ms=(time.monotonic() - start) * 1000,
            )

    # ==================================================================
    # Phase 2: Route Discovery
    # ==================================================================

    async def _discover_rest_routes(self, client, slug: str) -> list[dict]:
        """Parse /wp-json/ index and return routes matching this plugin."""
        try:
            status_code, body, headers = await client.get(
                f"{client.rest_prefix}/", cookies={}
            )
            if status_code != 200:
                logger.warning("REST index returned %d for route discovery", status_code)
                return []

            data = json.loads(body)
        except Exception as exc:
            logger.warning("Failed to parse REST index: %s", exc)
            return []

        # Build variations of the slug for matching
        slug_lower = slug.lower()
        slug_underscored = slug_lower.replace("-", "_")
        # Short abbreviation: first letters of each word, e.g. "contact-form-7" -> "cf7"
        parts = slug_lower.split("-")
        abbreviation = "".join(p[0] for p in parts if p) + (parts[-1] if parts[-1].isdigit() else "")

        match_tokens = {slug_lower, slug_underscored}
        if len(abbreviation) >= 2:
            match_tokens.add(abbreviation)

        namespaces = data.get("namespaces", [])
        routes_raw = data.get("routes", {})

        # Find matching namespaces
        matching_namespaces = set()
        for ns in namespaces:
            ns_lower = ns.lower()
            if any(token in ns_lower for token in match_tokens):
                matching_namespaces.add(ns)

        # Collect routes whose path starts with a matching namespace
        discovered = []
        for route_path, route_info in routes_raw.items():
            route_lower = route_path.lower()
            # Match if route belongs to a matching namespace or contains slug
            belongs = any(
                route_lower.startswith(f"/{ns}/") or route_lower == f"/{ns}"
                for ns in matching_namespaces
            )
            if not belongs:
                belongs = any(token in route_lower for token in match_tokens)

            if belongs:
                methods = set()
                args = {}
                endpoints = route_info.get("endpoints", [])
                for ep in endpoints:
                    methods.update(ep.get("methods", []))
                    args.update(ep.get("args", {}))

                discovered.append({
                    "path": f"{client.rest_prefix}{route_path}",
                    "methods": sorted(methods),
                    "args": args,
                })

        logger.info("Discovered %d REST routes for %s", len(discovered), slug)
        return discovered

    async def _discover_ajax_actions(self, client, slug: str) -> list[str]:
        """Probe common AJAX action patterns and return those that exist."""
        slug_clean = slug.replace("-", "_")
        candidates = [
            f"{slug_clean}_save",
            f"{slug_clean}_delete",
            f"{slug_clean}_update",
            f"{slug_clean}_get",
            f"{slug_clean}_export",
            f"{slug_clean}_import",
            f"wp_{slug_clean}_save",
            f"wp_{slug_clean}_delete",
            slug_clean,
        ]

        throttle = self._get_throttle("wordpress.plugin_audit")
        max_probes = throttle.get("max_ajax_probes", 20)
        delay_ms = throttle.get("delay_ms", 0)

        candidates = candidates[:max_probes]
        discovered = []

        for action in candidates:
            try:
                status_code, body, headers = await client.ajax_post(
                    action, authenticated=False
                )
                # An action exists if the response is NOT exactly "0" and NOT a
                # standard WordPress error for missing actions
                body_stripped = body.strip()
                is_missing = (
                    body_stripped == "0"
                    or body_stripped == "-1"
                    or body_stripped == ""
                    or "is not a registered ajax action" in body.lower()
                )
                if not is_missing:
                    discovered.append(action)
                    logger.info("AJAX action discovered: %s (status %d)", action, status_code)

            except Exception as exc:
                logger.debug("Error probing AJAX action %s: %s", action, exc)

            if delay_ms > 0:
                await asyncio.sleep(delay_ms / 1000.0)

        logger.info("Discovered %d AJAX actions for %s", len(discovered), slug)
        return discovered

    # ==================================================================
    # Phase 3: Targeted Tests — REST Routes
    # ==================================================================

    async def _test_route_auth(self, client, slug: str, route: dict) -> AttackResult:
        """Test a REST route for missing authentication on state-changing methods."""
        path = route["path"]
        methods = route["methods"]
        variant = f"{slug}/route_auth:{path}"
        start = time.monotonic()

        state_changing = {"POST", "PUT", "DELETE", "PATCH"}
        test_methods = [m for m in methods if m.upper() in state_changing]
        if not test_methods:
            # GET-only route — less concerning
            try:
                status_code, body, headers = await client.get(path, cookies={})
                duration = (time.monotonic() - start) * 1000
                if status_code == 200 and len(body) > 2:
                    return self._make_result(
                        variant=variant,
                        status=Status.PARTIAL,
                        severity=Severity.MEDIUM,
                        evidence=f"GET {path} accessible unauthenticated (HTTP {status_code})",
                        details="Read-only route accessible without auth. May leak data.",
                        request={"method": "GET", "path": path},
                        response={"status": status_code, "body_length": len(body)},
                        duration_ms=duration,
                    )
                return self._make_result(
                    variant=variant,
                    status=Status.DEFENDED,
                    evidence=f"GET {path} returned HTTP {status_code}",
                    request={"method": "GET", "path": path},
                    response={"status": status_code},
                    duration_ms=duration,
                )
            except Exception as exc:
                return self._make_result(
                    variant=variant, status=Status.ERROR,
                    details=f"Error testing route auth: {exc}",
                    duration_ms=(time.monotonic() - start) * 1000,
                )

        # Test state-changing method without auth
        method = test_methods[0].upper()
        try:
            if method == "POST":
                status_code, body, headers = await client.post(
                    path, json_body={}, cookies={},
                )
            elif method == "DELETE":
                status_code, body, headers = await client.delete(path, cookies={})
            else:
                # PUT/PATCH — send as POST with _method override
                status_code, body, headers = await client.post(
                    path, json_body={"_method": method}, cookies={},
                )
            duration = (time.monotonic() - start) * 1000

            if status_code == 200:
                return self._make_result(
                    variant=variant,
                    status=Status.VULNERABLE,
                    severity=Severity.HIGH,
                    evidence=(
                        f"{method} {path} returned 200 unauthenticated — "
                        f"state-changing endpoint has no auth check"
                    ),
                    details=(
                        f"The endpoint accepted an unauthenticated {method} request and "
                        f"returned HTTP 200. This allows anyone to invoke this action."
                    ),
                    request={"method": method, "path": path, "authenticated": False},
                    response={"status": status_code, "body": body[:300]},
                    duration_ms=duration,
                )

            return self._make_result(
                variant=variant,
                status=Status.DEFENDED,
                evidence=f"{method} {path} returned HTTP {status_code} (auth required)",
                request={"method": method, "path": path},
                response={"status": status_code},
                duration_ms=duration,
            )
        except Exception as exc:
            return self._make_result(
                variant=variant, status=Status.ERROR,
                details=f"Error testing route auth: {exc}",
                duration_ms=(time.monotonic() - start) * 1000,
            )

    async def _test_route_injection(self, client, slug: str, route: dict) -> AttackResult:
        """Send SQLi and XSS payloads in documented route arguments."""
        path = route["path"]
        args = route.get("args", {})
        variant = f"{slug}/route_injection:{path}"
        start = time.monotonic()

        # Build payloads for each string argument
        string_args = [
            name for name, spec in args.items()
            if isinstance(spec, dict) and spec.get("type") in ("string", None)
        ]
        if not string_args:
            return self._make_result(
                variant=variant,
                status=Status.DEFENDED,
                severity=Severity.INFO,
                evidence=f"No injectable string parameters on {path}",
                details="Route has no documented string parameters to test.",
                duration_ms=(time.monotonic() - start) * 1000,
            )

        findings = []
        for arg_name in string_args[:5]:  # Limit to first 5 args
            for label, payload in [("sqli", SQLI_PAYLOAD), ("xss", XSS_PAYLOAD)]:
                try:
                    status_code, body, headers = await client.get(
                        path, params={arg_name: payload}, cookies={},
                    )
                    body_lower = body.lower()

                    if label == "sqli":
                        sql_error = any(p in body_lower for p in SQL_ERROR_PATTERNS)
                        if sql_error:
                            findings.append(
                                f"SQL error triggered via {arg_name} with payload: {payload}"
                            )
                    elif label == "xss":
                        if payload in body:
                            findings.append(
                                f"XSS payload reflected in response via {arg_name}"
                            )
                except Exception as exc:
                    logger.debug("Injection test error on %s/%s: %s", path, arg_name, exc)

        duration = (time.monotonic() - start) * 1000

        if findings:
            return self._make_result(
                variant=variant,
                status=Status.VULNERABLE,
                severity=Severity.HIGH,
                evidence="; ".join(findings),
                details=(
                    f"Injection payloads produced {len(findings)} finding(s) on {path}. "
                    f"Tested parameters: {', '.join(string_args[:5])}"
                ),
                request={"path": path, "tested_args": string_args[:5]},
                response={"findings": findings},
                duration_ms=duration,
            )

        return self._make_result(
            variant=variant,
            status=Status.DEFENDED,
            evidence=f"No injection findings on {path}",
            details=f"SQLi and XSS payloads tested on {len(string_args[:5])} parameters without findings.",
            request={"path": path, "tested_args": string_args[:5]},
            duration_ms=duration,
        )

    async def _test_route_nonce(self, client, slug: str, route: dict) -> AttackResult:
        """Test POST/PUT/DELETE routes for missing nonce/CSRF validation."""
        path = route["path"]
        methods = route["methods"]
        variant = f"{slug}/route_nonce:{path}"
        start = time.monotonic()

        state_changing = {"POST", "PUT", "DELETE", "PATCH"}
        if not any(m.upper() in state_changing for m in methods):
            return self._make_result(
                variant=variant,
                status=Status.DEFENDED,
                severity=Severity.INFO,
                evidence=f"Route {path} has no state-changing methods",
                duration_ms=0,
            )

        try:
            # Send POST with auth cookies but WITHOUT the X-WP-Nonce header
            status_code, body, headers = await client.post(
                path,
                json_body={"test": "nonce_check"},
                headers={"X-WP-Nonce": ""},  # Empty nonce to test validation
            )
            duration = (time.monotonic() - start) * 1000

            # If the request was accepted (200), nonce validation is missing
            if status_code == 200:
                return self._make_result(
                    variant=variant,
                    status=Status.VULNERABLE,
                    severity=Severity.HIGH,
                    evidence=(
                        f"POST {path} accepted without valid nonce (HTTP 200) — "
                        f"missing CSRF protection"
                    ),
                    details=(
                        f"The endpoint accepted a POST request with an empty X-WP-Nonce "
                        f"header. This means CSRF attacks can invoke this action."
                    ),
                    request={"method": "POST", "path": path, "nonce": "empty"},
                    response={"status": status_code, "body": body[:300]},
                    duration_ms=duration,
                )

            return self._make_result(
                variant=variant,
                status=Status.DEFENDED,
                evidence=f"POST {path} rejected without nonce (HTTP {status_code})",
                details="Nonce validation is enforced on this endpoint.",
                request={"method": "POST", "path": path, "nonce": "empty"},
                response={"status": status_code},
                duration_ms=duration,
            )
        except Exception as exc:
            return self._make_result(
                variant=variant, status=Status.ERROR,
                details=f"Error testing nonce validation: {exc}",
                duration_ms=(time.monotonic() - start) * 1000,
            )

    # ==================================================================
    # Phase 3: Targeted Tests — AJAX Actions
    # ==================================================================

    async def _test_ajax_auth(self, client, slug: str, action: str) -> AttackResult:
        """Test an AJAX action for missing authentication."""
        variant = f"{slug}/ajax_auth:{action}"
        start = time.monotonic()
        try:
            status_code, body, headers = await client.ajax_post(
                action, authenticated=False,
            )
            duration = (time.monotonic() - start) * 1000

            body_stripped = body.strip()
            is_empty = body_stripped in ("0", "-1", "")

            if not is_empty and status_code == 200:
                return self._make_result(
                    variant=variant,
                    status=Status.VULNERABLE,
                    severity=Severity.HIGH,
                    evidence=(
                        f"AJAX action '{action}' returned data unauthenticated "
                        f"(HTTP {status_code}, {len(body)} bytes)"
                    ),
                    details=(
                        f"The AJAX action accepted an unauthenticated request and returned "
                        f"meaningful data. This may expose functionality or data to anonymous users."
                    ),
                    request={"action": action, "authenticated": False},
                    response={"status": status_code, "body": body[:300]},
                    duration_ms=duration,
                )

            return self._make_result(
                variant=variant,
                status=Status.DEFENDED,
                evidence=f"AJAX action '{action}' blocked unauthenticated (response: '{body_stripped[:50]}')",
                request={"action": action, "authenticated": False},
                response={"status": status_code, "body": body_stripped[:100]},
                duration_ms=duration,
            )
        except Exception as exc:
            return self._make_result(
                variant=variant, status=Status.ERROR,
                details=f"Error testing AJAX auth: {exc}",
                duration_ms=(time.monotonic() - start) * 1000,
            )

    async def _test_ajax_injection(self, client, slug: str, action: str) -> AttackResult:
        """Send SQLi and XSS payloads as data params to an AJAX action."""
        variant = f"{slug}/ajax_injection:{action}"
        start = time.monotonic()
        findings = []

        for label, payload in [("sqli", SQLI_PAYLOAD), ("xss", XSS_PAYLOAD)]:
            try:
                status_code, body, headers = await client.ajax_post(
                    action,
                    data={"id": payload, "value": payload, "data": payload},
                    authenticated=False,
                )
                body_lower = body.lower()

                if label == "sqli":
                    sql_error = any(p in body_lower for p in SQL_ERROR_PATTERNS)
                    if sql_error:
                        findings.append(f"SQL error triggered via action '{action}' ({label})")
                elif label == "xss":
                    if payload in body:
                        findings.append(f"XSS payload reflected via action '{action}'")

            except Exception as exc:
                logger.debug("AJAX injection test error on %s: %s", action, exc)

        duration = (time.monotonic() - start) * 1000

        if findings:
            return self._make_result(
                variant=variant,
                status=Status.VULNERABLE,
                severity=Severity.HIGH,
                evidence="; ".join(findings),
                details=f"Injection payloads produced findings on AJAX action '{action}'.",
                request={"action": action, "payloads": ["sqli", "xss"]},
                response={"findings": findings},
                duration_ms=duration,
            )

        return self._make_result(
            variant=variant,
            status=Status.DEFENDED,
            evidence=f"No injection findings on AJAX action '{action}'",
            details="SQLi and XSS payloads tested without findings.",
            request={"action": action, "payloads": ["sqli", "xss"]},
            duration_ms=duration,
        )

    # ==================================================================
    # Phase 4: File-level checks
    # ==================================================================

    async def _check_directory_listing(self, client, slug: str) -> AttackResult:
        """Check if the plugin directory has directory listing enabled."""
        path = f"{client.content_path}/plugins/{slug}/"
        variant = f"{slug}/directory_listing"
        start = time.monotonic()
        try:
            status_code, body, headers = await client.get(path, cookies={})
            duration = (time.monotonic() - start) * 1000

            if status_code == 200 and "index of" in body.lower():
                return self._make_result(
                    variant=variant,
                    status=Status.VULNERABLE,
                    severity=Severity.MEDIUM,
                    evidence=f"Directory listing enabled at {path}",
                    details=(
                        f"The plugin directory at {path} has directory listing enabled, "
                        f"exposing the complete file structure to attackers."
                    ),
                    request={"path": path},
                    response={"status": status_code, "body": body[:500]},
                    duration_ms=duration,
                )

            return self._make_result(
                variant=variant,
                status=Status.DEFENDED,
                evidence=f"Directory listing disabled at {path} (HTTP {status_code})",
                request={"path": path},
                response={"status": status_code},
                duration_ms=duration,
            )
        except Exception as exc:
            return self._make_result(
                variant=variant, status=Status.ERROR,
                details=f"Error checking directory listing: {exc}",
                duration_ms=(time.monotonic() - start) * 1000,
            )

    async def _check_direct_php_access(self, client, slug: str) -> list[AttackResult]:
        """Probe common PHP files inside the plugin directory for direct access."""
        results = []

        for template in COMMON_PHP_FILES:
            filename = template.format(slug=slug)
            path = f"{client.content_path}/plugins/{slug}/{filename}"
            variant = f"{slug}/direct_php:{filename}"
            start = time.monotonic()

            try:
                status_code, body, headers = await client.get(path, cookies={})
                duration = (time.monotonic() - start) * 1000

                content_type = headers.get("Content-Type", "").lower()
                is_php_output = (
                    status_code == 200
                    and "text/html" in content_type
                    and len(body.strip()) > 0
                    and "<?php" not in body[:100]  # Not raw source
                )

                if is_php_output:
                    results.append(self._make_result(
                        variant=variant,
                        status=Status.VULNERABLE,
                        severity=Severity.MEDIUM,
                        evidence=f"Direct PHP access to {path} returned output (HTTP 200)",
                        details=(
                            f"The file {path} is directly accessible and produced PHP output. "
                            f"Direct file access can bypass WordPress security and nonce checks."
                        ),
                        request={"path": path},
                        response={
                            "status": status_code,
                            "content_type": content_type,
                            "body": body[:300],
                        },
                        duration_ms=duration,
                    ))
                else:
                    results.append(self._make_result(
                        variant=variant,
                        status=Status.DEFENDED,
                        evidence=f"{path} returned HTTP {status_code}",
                        details=f"Direct PHP access properly blocked or file not found.",
                        request={"path": path},
                        response={"status": status_code},
                        duration_ms=duration,
                    ))
            except Exception as exc:
                results.append(self._make_result(
                    variant=variant, status=Status.ERROR,
                    details=f"Error testing direct PHP access to {filename}: {exc}",
                    duration_ms=(time.monotonic() - start) * 1000,
                ))

        return results

    async def cleanup(self, client) -> None:
        """No persistent state created by plugin audit tests."""
        pass
