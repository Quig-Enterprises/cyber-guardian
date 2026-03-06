"""System refresh from trusted state — NIST SP 800-172 Control 3.14.4e.

Verifies that system components are periodically refreshed from a known
trusted state, limiting the persistence window for Advanced Persistent
Threats (APTs). Long-lived systems, stale components, and long-lived
sessions all expand the window an attacker has to maintain persistence
after an initial compromise.
"""

import json
import re
import time
from datetime import datetime, timezone

from redteam.base import Attack, AttackResult, Severity, Status


class SystemRefreshAttack(Attack):
    name = "compliance.system_refresh"
    category = "compliance"
    severity = Severity.MEDIUM
    description = (
        "NIST 800-172 3.14.4e — Verify systems are refreshed from known "
        "trusted state to limit APT persistence"
    )

    # Uptime threshold in days — systems older than this have not been refreshed
    UPTIME_THRESHOLD_DAYS = 90

    # Session lifetime threshold in seconds — 24 hours
    SESSION_LIFETIME_THRESHOLD_SECONDS = 86400

    # Static content staleness threshold in days
    STALE_CONTENT_THRESHOLD_DAYS = 90

    # Cache max-age threshold in seconds — 1 day
    CACHE_MAX_AGE_THRESHOLD_SECONDS = 86400

    # Endpoints to probe for status/uptime information
    STATUS_ENDPOINTS = [
        "/server-status",
        "/server-info",
        "/status",
        "/health",
        "/api/status",
        "/api/health",
    ]

    # Static resources to check for staleness
    STATIC_RESOURCES = [
        "/admin/login.php",
        "/admin/css/style.css",
        "/admin/js/app.js",
        "/js/app.js",
        "/css/style.css",
    ]

    # Dynamic endpoints to check for cache headers
    DYNAMIC_ENDPOINTS = [
        "/api/ai_chat.php",
        "/api/admin/users.php",
        "/api/admin/settings.php",
    ]

    # Known outdated server tokens — maps substring to (current_major, description)
    OUTDATED_SERVER_SIGNATURES = [
        # Apache: 2.4.x is current major series; 2.2.x is EOL
        (r"Apache/2\.2\.", "Apache 2.2.x (EOL; current major is 2.4.x)"),
        (r"Apache/1\.", "Apache 1.x (EOL; current major is 2.4.x)"),
        # nginx: 1.x is current; anything below 1.18 is multiple majors behind
        (r"nginx/0\.", "nginx 0.x (EOL; current major is 1.x)"),
        (r"nginx/1\.([0-9]|1[0-7])\.", "nginx <1.18 (multiple major releases behind)"),
        # PHP: 8.x is current; 7.x is EOL
        (r"PHP/5\.", "PHP 5.x (EOL; current major is 8.x)"),
        (r"PHP/7\.", "PHP 7.x (EOL; current major is 8.x)"),
        # OpenSSL in server banners
        (r"OpenSSL/0\.", "OpenSSL 0.x (EOL; current major is 3.x)"),
        (r"OpenSSL/1\.0\.", "OpenSSL 1.0.x (EOL; current series is 3.x)"),
    ]

    # ----------------------------------------------------------------
    # Helpers
    # ----------------------------------------------------------------

    def _parse_date_header(self, headers: dict) -> datetime | None:
        """Parse the HTTP Date header into a timezone-aware datetime."""
        for key, val in headers.items():
            if key.lower() == "date":
                try:
                    # RFC 7231 date format
                    return datetime.strptime(
                        val.strip(), "%a, %d %b %Y %H:%M:%S %Z"
                    ).replace(tzinfo=timezone.utc)
                except ValueError:
                    return None
        return None

    def _parse_last_modified(self, headers: dict) -> datetime | None:
        """Parse the Last-Modified header into a timezone-aware datetime."""
        for key, val in headers.items():
            if key.lower() == "last-modified":
                try:
                    return datetime.strptime(
                        val.strip(), "%a, %d %b %Y %H:%M:%S %Z"
                    ).replace(tzinfo=timezone.utc)
                except ValueError:
                    return None
        return None

    def _get_header(self, headers: dict, name: str) -> str:
        """Case-insensitive header lookup. Returns empty string if not found."""
        for key, val in headers.items():
            if key.lower() == name.lower():
                return val.strip()
        return ""

    def _extract_max_age(self, cache_control: str) -> int | None:
        """Extract max-age value in seconds from a Cache-Control header string."""
        match = re.search(r"max-age\s*=\s*(\d+)", cache_control, re.IGNORECASE)
        if match:
            return int(match.group(1))
        return None

    # ----------------------------------------------------------------
    # Variant 1: server_uptime_disclosure
    # ----------------------------------------------------------------

    async def _check_server_uptime_disclosure(self, client) -> AttackResult:
        now = datetime.now(timezone.utc)

        uptime_sources: list[str] = []
        date_samples: list[datetime] = []
        request_log: list[dict] = []

        # Collect Date headers across multiple baseline requests
        for _ in range(3):
            status_code, body, headers = await client.get("/")
            dt = self._parse_date_header(headers)
            if dt:
                date_samples.append(dt)

        # Probe known status/uptime endpoints
        for path in self.STATUS_ENDPOINTS:
            status_code, body, headers = await client.get(path)
            request_log.append({"path": path, "status": status_code})

            if status_code != 200:
                continue

            body_lower = body.lower()

            # Look for explicit uptime strings in the response body
            uptime_patterns = [
                r"uptime[:\s]+(\d+)\s*day",
                r"server\s+uptime[:\s]+(\d+)",
                r"up\s+(\d+)\s+day",
                r"running\s+for\s+(\d+)\s+day",
            ]
            for pattern in uptime_patterns:
                m = re.search(pattern, body_lower)
                if m:
                    days = int(m.group(1))
                    uptime_sources.append(
                        f"{path}: body discloses uptime of {days} day(s). "
                        f"Pattern matched: '{pattern}'"
                    )

            # Check for X-Uptime or similar custom headers
            x_uptime = self._get_header(headers, "x-uptime")
            if x_uptime:
                uptime_sources.append(
                    f"{path}: X-Uptime header present: '{x_uptime}'"
                )

        # Determine verdict
        if uptime_sources:
            # Try to extract a day count for threshold comparison
            day_match = re.search(r"(\d+)\s*day", uptime_sources[0], re.IGNORECASE)
            days_found = int(day_match.group(1)) if day_match else None

            if days_found is not None and days_found > self.UPTIME_THRESHOLD_DAYS:
                uptime_status = Status.VULNERABLE
                uptime_evidence = (
                    f"Server discloses uptime of {days_found} days, which exceeds "
                    f"the {self.UPTIME_THRESHOLD_DAYS}-day refresh threshold. "
                    f"Sources: {'; '.join(uptime_sources)}"
                )
                uptime_detail = (
                    f"The server has been running for {days_found} days without a "
                    "system refresh. NIST SP 800-172 3.14.4e requires periodic "
                    "refresh from a known trusted state to limit APT persistence. "
                    "A system running for more than 90 days without a refresh "
                    "provides a wide window for persistent threats."
                )
            else:
                uptime_status = Status.PARTIAL
                uptime_evidence = (
                    f"Server discloses uptime information. "
                    f"Sources: {'; '.join(uptime_sources)}"
                )
                uptime_detail = (
                    "Uptime information is disclosed but could not be confirmed "
                    f"to exceed the {self.UPTIME_THRESHOLD_DAYS}-day threshold. "
                    "Disclosing uptime assists attackers in identifying staleness. "
                    "Uptime endpoints should be disabled or restricted."
                )
        elif date_samples:
            # No uptime endpoints but we have Date header samples
            uptime_status = Status.PARTIAL
            sample_str = date_samples[-1].isoformat() if date_samples else "unknown"
            uptime_evidence = (
                f"No uptime disclosure found on status endpoints. "
                f"Date header observed: {sample_str}. "
                "Cannot determine server uptime from available headers."
            )
            uptime_detail = (
                "No explicit uptime information was disclosed. The Date header "
                "confirms the server is responding but does not reveal uptime. "
                "Manual verification of system refresh cadence is recommended "
                "to confirm NIST SP 800-172 3.14.4e compliance."
            )
        else:
            uptime_status = Status.DEFENDED
            uptime_evidence = (
                "No uptime information disclosed via status endpoints, "
                "response headers, or body content."
            )
            uptime_detail = (
                "The server does not expose uptime information through any "
                "probed channel. Status and diagnostic endpoints are not "
                "publicly accessible. Uptime disclosure is not a concern."
            )

        return self._make_result(
            variant="server_uptime_disclosure",
            status=uptime_status,
            evidence=uptime_evidence,
            details=uptime_detail,
            request={"status_endpoints_probed": request_log},
            response={
                "uptime_sources": uptime_sources,
                "date_samples": [d.isoformat() for d in date_samples],
            },
        )

    # ----------------------------------------------------------------
    # Variant 2: session_longevity
    # ----------------------------------------------------------------

    async def _check_session_longevity(self, client) -> AttackResult:
        # Probe the login page to obtain a Set-Cookie header
        status_code, body, headers = await client.get("/admin/login.php")

        set_cookie = self._get_header(headers, "set-cookie")
        if not set_cookie:
            # Try root and api paths
            for path in ["/", "/api/ai_chat.php", "/admin/"]:
                status_code, body, headers = await client.get(path)
                set_cookie = self._get_header(headers, "set-cookie")
                if set_cookie:
                    break

        request_info = {"path": "/admin/login.php", "method": "GET"}

        if not set_cookie:
            return self._make_result(
                variant="session_longevity",
                status=Status.PARTIAL,
                evidence="No Set-Cookie header observed on any probed endpoint.",
                details=(
                    "Session cookie attributes could not be evaluated because no "
                    "Set-Cookie header was returned by the server on any tested "
                    "path. Manual inspection of authenticated session handling is "
                    "recommended to verify NIST SP 800-172 3.14.4e compliance."
                ),
                request=request_info,
                response={"set_cookie": ""},
            )

        # Parse Max-Age and Expires from the Set-Cookie value
        max_age_match = re.search(
            r"max-age\s*=\s*(\d+)", set_cookie, re.IGNORECASE
        )
        expires_match = re.search(
            r"expires\s*=\s*([^;]+)", set_cookie, re.IGNORECASE
        )

        max_age_seconds: int | None = None
        expires_dt: datetime | None = None
        session_lifetime_seconds: int | None = None
        no_expiry = False

        if max_age_match:
            max_age_seconds = int(max_age_match.group(1))
            session_lifetime_seconds = max_age_seconds
        elif expires_match:
            expires_str = expires_match.group(1).strip()
            try:
                expires_dt = datetime.strptime(
                    expires_str, "%a, %d %b %Y %H:%M:%S %Z"
                ).replace(tzinfo=timezone.utc)
                now = datetime.now(timezone.utc)
                delta = (expires_dt - now).total_seconds()
                session_lifetime_seconds = int(delta) if delta > 0 else 0
            except ValueError:
                pass
        else:
            # No Max-Age or Expires — session cookie (ends at browser close)
            # but some frameworks issue effectively permanent tokens
            no_expiry = True

        if no_expiry:
            session_status = Status.PARTIAL
            session_evidence = (
                f"Session cookie has no Max-Age or Expires attribute. "
                f"Set-Cookie: {set_cookie[:300]}"
            )
            session_detail = (
                "The session cookie carries no explicit expiry. While this "
                "technically means the session ends when the browser closes, "
                "stolen tokens remain valid indefinitely server-side unless "
                "the session store enforces a TTL. Long-lived or non-expiring "
                "sessions increase the APT persistence window. "
                "NIST SP 800-172 3.14.4e recommends limiting session lifetime "
                "to constrain persistence opportunities."
            )
        elif session_lifetime_seconds is not None and session_lifetime_seconds > self.SESSION_LIFETIME_THRESHOLD_SECONDS:
            hours = session_lifetime_seconds // 3600
            session_status = Status.PARTIAL
            session_evidence = (
                f"Session cookie lifetime is {hours} hours "
                f"({session_lifetime_seconds}s), exceeding the "
                f"{self.SESSION_LIFETIME_THRESHOLD_SECONDS // 3600}-hour threshold. "
                f"Set-Cookie: {set_cookie[:300]}"
            )
            session_detail = (
                f"Sessions remain valid for {hours} hours. Long-lived sessions "
                "expand the window during which a stolen or persisted session "
                "token can be exploited. NIST SP 800-172 3.14.4e requires "
                "periodic refresh from a trusted state; session lifetime "
                "directly contributes to the APT persistence window."
            )
        elif session_lifetime_seconds is not None:
            hours = max(session_lifetime_seconds // 3600, 0)
            session_status = Status.DEFENDED
            session_evidence = (
                f"Session cookie lifetime is {hours} hours "
                f"({session_lifetime_seconds}s), within the acceptable threshold. "
                f"Set-Cookie: {set_cookie[:300]}"
            )
            session_detail = (
                f"Session expiry is set to {hours} hours, which is within the "
                f"{self.SESSION_LIFETIME_THRESHOLD_SECONDS // 3600}-hour "
                "threshold. Short-lived sessions reduce the APT persistence "
                "window in line with NIST SP 800-172 3.14.4e intent."
            )
        else:
            session_status = Status.PARTIAL
            session_evidence = (
                f"Session cookie Expires value could not be parsed. "
                f"Set-Cookie: {set_cookie[:300]}"
            )
            session_detail = (
                "Session cookie expiry could not be determined from the "
                "Set-Cookie header. Manual inspection is recommended."
            )

        return self._make_result(
            variant="session_longevity",
            status=session_status,
            evidence=session_evidence,
            details=session_detail,
            request=request_info,
            response={
                "set_cookie": set_cookie[:500],
                "max_age_seconds": max_age_seconds,
                "expires": expires_dt.isoformat() if expires_dt else None,
                "no_expiry": no_expiry,
                "session_lifetime_seconds": session_lifetime_seconds,
            },
        )

    # ----------------------------------------------------------------
    # Variant 3: stale_response_detection
    # ----------------------------------------------------------------

    async def _check_stale_response_detection(self, client) -> AttackResult:
        now = datetime.now(timezone.utc)
        stale_resources: list[str] = []
        request_log: list[dict] = []
        response_log: list[dict] = []

        for path in self.STATIC_RESOURCES:
            status_code, body, headers = await client.get(path)
            request_log.append({"path": path, "status": status_code})

            if status_code not in (200, 304):
                response_log.append({"path": path, "skipped": True})
                continue

            last_modified = self._parse_last_modified(headers)
            etag = self._get_header(headers, "etag")

            response_log.append({
                "path": path,
                "status": status_code,
                "last_modified": last_modified.isoformat() if last_modified else None,
                "etag": etag or None,
            })

            if last_modified:
                age_days = (now - last_modified).days
                if age_days > self.STALE_CONTENT_THRESHOLD_DAYS:
                    stale_resources.append(
                        f"{path}: Last-Modified {last_modified.strftime('%Y-%m-%d')} "
                        f"({age_days} days ago)"
                    )

        if stale_resources:
            stale_status = Status.PARTIAL
            stale_evidence = (
                f"{len(stale_resources)} static resource(s) have not been "
                f"modified in more than {self.STALE_CONTENT_THRESHOLD_DAYS} days: "
                + "; ".join(stale_resources)
            )
            stale_detail = (
                f"Static resources show Last-Modified dates older than "
                f"{self.STALE_CONTENT_THRESHOLD_DAYS} days, suggesting that "
                "static content (CSS, JS, PHP login pages) has not been "
                "regenerated from a trusted baseline in the same period. "
                "NIST SP 800-172 3.14.4e requires periodic system refresh; "
                "infrequently updated static assets may indicate that the "
                "broader system refresh cadence is also inadequate."
            )
        else:
            probed_with_headers = [r for r in response_log if r.get("last_modified")]
            if probed_with_headers:
                stale_status = Status.DEFENDED
                stale_evidence = (
                    f"All {len(probed_with_headers)} probed static resource(s) "
                    f"show Last-Modified dates within the "
                    f"{self.STALE_CONTENT_THRESHOLD_DAYS}-day threshold."
                )
                stale_detail = (
                    "Static content modification dates are recent, suggesting "
                    "that content has been refreshed within the expected window. "
                    "This is consistent with NIST SP 800-172 3.14.4e refresh "
                    "requirements."
                )
            else:
                stale_status = Status.PARTIAL
                stale_evidence = (
                    "No static resources returned Last-Modified headers. "
                    "Staleness could not be assessed from available responses."
                )
                stale_detail = (
                    "None of the probed static resources returned Last-Modified "
                    "headers, so content freshness cannot be determined via HTTP. "
                    "Manual verification of system refresh cadence is recommended."
                )

        return self._make_result(
            variant="stale_response_detection",
            status=stale_status,
            evidence=stale_evidence,
            details=stale_detail,
            request={"resources_probed": request_log},
            response={"resources": response_log, "stale": stale_resources},
        )

    # ----------------------------------------------------------------
    # Variant 4: component_version_staleness
    # ----------------------------------------------------------------

    async def _check_component_version_staleness(self, client) -> AttackResult:
        status_code, body, headers = await client.get("/")
        server_header = self._get_header(headers, "server")
        x_powered_by = self._get_header(headers, "x-powered-by")

        combined_banner = " ".join(filter(None, [server_header, x_powered_by]))
        request_info = {"path": "/", "method": "GET"}
        response_info = {
            "server": server_header,
            "x_powered_by": x_powered_by,
        }

        if not combined_banner.strip():
            return self._make_result(
                variant="component_version_staleness",
                status=Status.DEFENDED,
                evidence=(
                    "No Server or X-Powered-By header present. "
                    "Version information is not disclosed."
                ),
                details=(
                    "The server does not disclose version information via "
                    "Server or X-Powered-By headers. This reduces the ability "
                    "to determine whether components are stale or outdated. "
                    "Version suppression is a positive security practice."
                ),
                request=request_info,
                response=response_info,
            )

        outdated_found: list[str] = []
        for pattern, description in self.OUTDATED_SERVER_SIGNATURES:
            if re.search(pattern, combined_banner, re.IGNORECASE):
                outdated_found.append(description)

        if outdated_found:
            version_status = Status.VULNERABLE
            version_evidence = (
                f"Outdated component version(s) detected in server banner "
                f"'{combined_banner}': " + "; ".join(outdated_found)
            )
            version_detail = (
                "Server banner reveals one or more software components that "
                "are more than one major release behind the current version. "
                "Outdated components indicate that the system has not been "
                "refreshed from a current trusted baseline. "
                "NIST SP 800-172 3.14.4e requires periodic refresh; running "
                "EOL or outdated software suggests this requirement is not met "
                "and exposes the system to known, unpatched vulnerabilities."
            )
        else:
            version_status = Status.DEFENDED
            version_evidence = (
                f"Server banner '{combined_banner}' does not match any known "
                "outdated version signatures."
            )
            version_detail = (
                "Detected server components do not match known outdated version "
                "patterns. The software appears to be on a current major release, "
                "consistent with periodic system refresh per NIST SP 800-172 "
                "3.14.4e. Note: version suppression would provide stronger "
                "assurance by not disclosing version information at all."
            )

        return self._make_result(
            variant="component_version_staleness",
            status=version_status,
            evidence=version_evidence,
            details=version_detail,
            request=request_info,
            response={**response_info, "outdated_found": outdated_found},
        )

    # ----------------------------------------------------------------
    # Variant 5: cache_persistence
    # ----------------------------------------------------------------

    async def _check_cache_persistence(self, client) -> AttackResult:
        long_cache_findings: list[str] = []
        request_log: list[dict] = []
        response_log: list[dict] = []

        for path in self.DYNAMIC_ENDPOINTS:
            status_code, body, headers = await client.get(path)
            request_log.append({"path": path, "status": status_code})

            cache_control = self._get_header(headers, "cache-control")
            pragma = self._get_header(headers, "pragma")

            max_age = self._extract_max_age(cache_control) if cache_control else None
            is_public = "public" in cache_control.lower() if cache_control else False

            response_log.append({
                "path": path,
                "status": status_code,
                "cache_control": cache_control or None,
                "pragma": pragma or None,
                "max_age_seconds": max_age,
                "public": is_public,
            })

            if max_age is not None and max_age > self.CACHE_MAX_AGE_THRESHOLD_SECONDS:
                hours = max_age // 3600
                long_cache_findings.append(
                    f"{path}: Cache-Control max-age={max_age}s ({hours}h) "
                    "on dynamic endpoint exceeds 24-hour threshold."
                )
            elif is_public and max_age is None:
                long_cache_findings.append(
                    f"{path}: Cache-Control includes 'public' without explicit "
                    "max-age on a dynamic endpoint — caches may store and serve "
                    "stale or compromised responses indefinitely."
                )

        if long_cache_findings:
            cache_status = Status.PARTIAL
            cache_evidence = (
                f"{len(long_cache_findings)} dynamic endpoint(s) have long-lived "
                "or unbounded public cache policies: "
                + "; ".join(long_cache_findings)
            )
            cache_detail = (
                "Dynamic API endpoints have cache configurations that allow "
                f"responses to persist beyond the {self.CACHE_MAX_AGE_THRESHOLD_SECONDS // 3600}-hour "
                "threshold. Long-lived caches can preserve stale or compromised "
                "response data even after a system has been refreshed from a "
                "trusted state, undermining the effectiveness of system refresh. "
                "NIST SP 800-172 3.14.4e requires that refresh resets system "
                "state to a known-good baseline; long-lived caches can delay "
                "or circumvent this protection."
            )
        else:
            probed_with_headers = [
                r for r in response_log if r.get("cache_control") is not None
            ]
            if probed_with_headers:
                cache_status = Status.DEFENDED
                cache_evidence = (
                    f"All {len(probed_with_headers)} dynamic endpoint(s) have "
                    "cache policies within acceptable limits (max-age <= 24h "
                    "or no-store/no-cache directives)."
                )
                cache_detail = (
                    "Dynamic endpoints use short-lived or no-cache policies. "
                    "Caches will not persist stale or compromised responses "
                    "beyond acceptable windows, supporting the effectiveness "
                    "of system refresh per NIST SP 800-172 3.14.4e."
                )
            else:
                cache_status = Status.PARTIAL
                cache_evidence = (
                    "Dynamic endpoints returned no Cache-Control headers. "
                    "Cache behavior is undefined — intermediate caches may "
                    "apply their own heuristic TTLs."
                )
                cache_detail = (
                    "The absence of explicit Cache-Control headers on dynamic "
                    "endpoints means that intermediate proxies and CDNs may "
                    "cache responses using heuristic TTLs. This could allow "
                    "stale or compromised data to persist in caches even after "
                    "a system refresh. Explicit no-store or no-cache directives "
                    "are recommended on dynamic API endpoints."
                )

        return self._make_result(
            variant="cache_persistence",
            status=cache_status,
            evidence=cache_evidence,
            details=cache_detail,
            request={"endpoints_probed": request_log},
            response={
                "endpoints": response_log,
                "long_cache_findings": long_cache_findings,
            },
        )

    # ----------------------------------------------------------------
    # execute
    # ----------------------------------------------------------------

    async def execute(self, client) -> list[AttackResult]:
        results = []

        results.append(await self._check_server_uptime_disclosure(client))
        results.append(await self._check_session_longevity(client))
        results.append(await self._check_stale_response_detection(client))
        results.append(await self._check_component_version_staleness(client))
        results.append(await self._check_cache_persistence(client))

        return results
