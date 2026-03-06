"""TLS/SSL security configuration tests.

Tests the target's HTTPS availability, HTTP-to-HTTPS redirection,
HSTS configuration, and secure cookie flags.

Evaluation:
- HTTPS not available -> VULNERABLE
- HTTP does not redirect to HTTPS -> VULNERABLE
- HSTS missing preload directive -> PARTIAL
- Cookies missing Secure flag on HTTPS site -> VULNERABLE
"""

import time
import ssl
import logging
from urllib.parse import urlparse

from redteam.base import Attack, AttackResult, Severity, Status

logger = logging.getLogger(__name__)


class TLSSecurityAttack(Attack):
    """Test TLS/SSL configuration of the target."""

    name = "web.tls_security"
    category = "web"
    severity = Severity.MEDIUM
    description = "TLS/SSL configuration and transport security tests"
    target_types = {"generic"}

    async def execute(self, client) -> list[AttackResult]:
        """Run all TLS security checks."""
        results = []
        self._parsed_url = urlparse(client.base_url)
        self._is_https = self._parsed_url.scheme == "https"
        self._hostname = self._parsed_url.hostname
        self._port = self._parsed_url.port or (443 if self._is_https else 80)

        results.append(await self._test_https_available(client))
        results.append(await self._test_http_redirect(client))
        results.append(await self._test_mixed_content_headers(client))
        results.append(await self._test_hsts_preload(client))
        results.append(await self._test_secure_cookies(client))

        return results

    async def _test_https_available(self, client) -> AttackResult:
        """Check if the target is reachable over HTTPS."""
        start = time.monotonic()
        try:
            if self._is_https:
                # Already using HTTPS, verify it works
                status_code, body, headers = await client.get("/", cookies={})
                duration = (time.monotonic() - start) * 1000
                return self._make_result(
                    variant="https_available",
                    status=Status.DEFENDED,
                    evidence=f"Site served over HTTPS (status {status_code})",
                    details="Target is accessible via HTTPS",
                    response={"status": status_code, "scheme": "https"},
                    duration_ms=duration,
                )
            else:
                # Base URL is HTTP; try connecting to HTTPS equivalent
                https_url = client.base_url.replace("http://", "https://", 1)
                try:
                    import aiohttp
                    timeout = aiohttp.ClientTimeout(total=10)
                    async with aiohttp.ClientSession(timeout=timeout) as session:
                        async with session.get(f"{https_url}/", ssl=True) as resp:
                            duration = (time.monotonic() - start) * 1000
                            return self._make_result(
                                variant="https_available",
                                status=Status.PARTIAL,
                                evidence=f"HTTPS available at {https_url} (status {resp.status}) but base URL uses HTTP",
                                details="HTTPS is available but the target is configured to use HTTP. Switch to HTTPS as default.",
                                response={"https_status": resp.status, "base_scheme": "http"},
                                duration_ms=duration,
                            )
                except Exception as https_err:
                    duration = (time.monotonic() - start) * 1000
                    return self._make_result(
                        variant="https_available",
                        status=Status.VULNERABLE,
                        evidence=f"HTTPS not available: {https_err}",
                        details="Target does not support HTTPS; all traffic is unencrypted and vulnerable to interception",
                        response={"base_scheme": "http", "https_error": str(https_err)[:200]},
                        duration_ms=duration,
                    )
        except Exception as e:
            return self._make_result(
                variant="https_available",
                status=Status.ERROR,
                details=str(e),
                duration_ms=(time.monotonic() - start) * 1000,
            )

    async def _test_http_redirect(self, client) -> AttackResult:
        """Check if HTTP requests are redirected to HTTPS."""
        start = time.monotonic()
        try:
            # Build the HTTP URL equivalent
            if self._is_https:
                http_url = client.base_url.replace("https://", "http://", 1)
            else:
                http_url = client.base_url

            try:
                import aiohttp
                timeout = aiohttp.ClientTimeout(total=10)
                async with aiohttp.ClientSession(timeout=timeout) as session:
                    async with session.get(
                        f"{http_url}/",
                        allow_redirects=False,
                        ssl=False,
                    ) as resp:
                        duration = (time.monotonic() - start) * 1000
                        status_code = resp.status
                        location = dict(resp.headers).get("Location", "")

                if status_code in (301, 302, 307, 308) and "https://" in location.lower():
                    return self._make_result(
                        variant="http_redirect",
                        status=Status.DEFENDED,
                        evidence=f"HTTP redirects to HTTPS ({status_code} -> {location})",
                        details="HTTP requests are properly redirected to HTTPS",
                        response={"status": status_code, "Location": location},
                        duration_ms=duration,
                    )
                elif status_code in (301, 302, 307, 308):
                    return self._make_result(
                        variant="http_redirect",
                        status=Status.PARTIAL,
                        evidence=f"HTTP redirects but not to HTTPS ({status_code} -> {location})",
                        details="HTTP redirects but the target is not HTTPS",
                        response={"status": status_code, "Location": location},
                        duration_ms=duration,
                    )
                else:
                    return self._make_result(
                        variant="http_redirect",
                        status=Status.VULNERABLE,
                        evidence=f"HTTP serves content directly (status {status_code}, no HTTPS redirect)",
                        details="HTTP requests serve content without redirecting to HTTPS; users can be served unencrypted content",
                        response={"status": status_code, "Location": location or "none"},
                        duration_ms=duration,
                    )
            except Exception as conn_err:
                duration = (time.monotonic() - start) * 1000
                # If HTTP connection fails, it might mean only HTTPS is available (which is fine)
                if self._is_https:
                    return self._make_result(
                        variant="http_redirect",
                        status=Status.DEFENDED,
                        evidence=f"HTTP port not reachable: {conn_err}",
                        details="HTTP is not available; only HTTPS is served (good configuration)",
                        duration_ms=duration,
                    )
                else:
                    return self._make_result(
                        variant="http_redirect",
                        status=Status.ERROR,
                        details=f"Could not connect to HTTP endpoint: {conn_err}",
                        duration_ms=duration,
                    )
        except Exception as e:
            return self._make_result(
                variant="http_redirect",
                status=Status.ERROR,
                details=str(e),
                duration_ms=(time.monotonic() - start) * 1000,
            )

    async def _test_mixed_content_headers(self, client) -> AttackResult:
        """Check for CSP directives that prevent mixed content."""
        start = time.monotonic()
        try:
            status_code, body, headers = await client.get("/", cookies={})
            duration = (time.monotonic() - start) * 1000

            csp = headers.get("Content-Security-Policy", "")
            csp_lower = csp.lower()

            has_upgrade = "upgrade-insecure-requests" in csp_lower
            has_block_mixed = "block-all-mixed-content" in csp_lower

            if has_upgrade and has_block_mixed:
                return self._make_result(
                    variant="mixed_content_headers",
                    status=Status.DEFENDED,
                    severity=Severity.INFO,
                    evidence="CSP includes both upgrade-insecure-requests and block-all-mixed-content",
                    details="Strong mixed content protection via CSP directives",
                    response={"CSP": csp[:300]},
                    duration_ms=duration,
                )
            elif has_upgrade:
                return self._make_result(
                    variant="mixed_content_headers",
                    status=Status.DEFENDED,
                    severity=Severity.INFO,
                    evidence="CSP includes upgrade-insecure-requests",
                    details="Mixed content will be auto-upgraded to HTTPS",
                    response={"CSP": csp[:300]},
                    duration_ms=duration,
                )
            elif has_block_mixed:
                return self._make_result(
                    variant="mixed_content_headers",
                    status=Status.DEFENDED,
                    severity=Severity.INFO,
                    evidence="CSP includes block-all-mixed-content",
                    details="Mixed content will be blocked by the browser",
                    response={"CSP": csp[:300]},
                    duration_ms=duration,
                )
            else:
                return self._make_result(
                    variant="mixed_content_headers",
                    status=Status.PARTIAL,
                    severity=Severity.INFO,
                    evidence="No mixed content CSP directives found",
                    details="CSP does not include upgrade-insecure-requests or block-all-mixed-content; browsers may still load HTTP resources on HTTPS pages",
                    response={"CSP": csp[:300] if csp else "missing"},
                    duration_ms=duration,
                )
        except Exception as e:
            return self._make_result(
                variant="mixed_content_headers",
                status=Status.ERROR,
                details=str(e),
                duration_ms=(time.monotonic() - start) * 1000,
            )

    async def _test_hsts_preload(self, client) -> AttackResult:
        """Check HSTS header for preload directive."""
        start = time.monotonic()
        try:
            status_code, body, headers = await client.get("/", cookies={})
            duration = (time.monotonic() - start) * 1000

            hsts = headers.get("Strict-Transport-Security", "")
            if not hsts:
                return self._make_result(
                    variant="hsts_preload",
                    status=Status.VULNERABLE,
                    evidence="Strict-Transport-Security header missing",
                    details="No HSTS; browsers will not enforce HTTPS on subsequent visits",
                    response={"Strict-Transport-Security": "missing"},
                    duration_ms=duration,
                )

            hsts_lower = hsts.lower()
            has_preload = "preload" in hsts_lower
            has_includesub = "includesubdomains" in hsts_lower

            if has_preload and has_includesub:
                return self._make_result(
                    variant="hsts_preload",
                    status=Status.DEFENDED,
                    severity=Severity.INFO,
                    evidence=f"HSTS with preload and includeSubDomains: {hsts}",
                    details="HSTS is configured with preload and includeSubDomains; eligible for browser preload lists",
                    response={"Strict-Transport-Security": hsts},
                    duration_ms=duration,
                )
            elif has_preload:
                return self._make_result(
                    variant="hsts_preload",
                    status=Status.PARTIAL,
                    severity=Severity.INFO,
                    evidence=f"HSTS has preload but missing includeSubDomains: {hsts}",
                    details="HSTS preload requires includeSubDomains to be eligible for browser preload lists",
                    response={"Strict-Transport-Security": hsts},
                    duration_ms=duration,
                )
            else:
                return self._make_result(
                    variant="hsts_preload",
                    status=Status.PARTIAL,
                    evidence=f"HSTS present but no preload directive: {hsts}",
                    details="HSTS is set but without preload; site is not eligible for browser HSTS preload lists",
                    response={"Strict-Transport-Security": hsts},
                    duration_ms=duration,
                )
        except Exception as e:
            return self._make_result(
                variant="hsts_preload",
                status=Status.ERROR,
                details=str(e),
                duration_ms=(time.monotonic() - start) * 1000,
            )

    async def _test_secure_cookies(self, client) -> AttackResult:
        """Check Set-Cookie headers for Secure flag on HTTPS sites."""
        start = time.monotonic()
        try:
            login_endpoint = self._get_login_endpoint()
            status_code, body, headers = await client.get(login_endpoint, cookies={})
            duration = (time.monotonic() - start) * 1000

            # aiohttp returns multi-value headers as separate entries;
            # dict(resp.headers) only captures the last value.
            # We need to check all Set-Cookie headers from the raw response.
            # Since the client returns dict, we work with what we have.
            set_cookie = headers.get("Set-Cookie", "")

            if not set_cookie:
                return self._make_result(
                    variant="secure_cookies",
                    status=Status.DEFENDED,
                    severity=Severity.INFO,
                    evidence="No Set-Cookie headers returned from login endpoint",
                    details=f"GET {login_endpoint} did not set any cookies",
                    request={"endpoint": login_endpoint},
                    response={"status": status_code},
                    duration_ms=duration,
                )

            # Parse Set-Cookie for Secure flag
            cookies_without_secure = []
            cookies_with_secure = []
            # Handle potential multiple cookies in a single header value
            cookie_parts = set_cookie.split(",")
            for cookie_str in cookie_parts:
                cookie_str = cookie_str.strip()
                if not cookie_str:
                    continue
                cookie_name = cookie_str.split("=")[0].strip() if "=" in cookie_str else cookie_str[:50]
                flags = cookie_str.lower()
                if "secure" in flags:
                    cookies_with_secure.append(cookie_name)
                else:
                    cookies_without_secure.append(cookie_name)

            if cookies_without_secure and self._is_https:
                return self._make_result(
                    variant="secure_cookies",
                    status=Status.VULNERABLE,
                    evidence=f"Cookies missing Secure flag: {', '.join(cookies_without_secure)}",
                    details="Cookies without the Secure flag can be sent over unencrypted HTTP connections, enabling session hijacking",
                    request={"endpoint": login_endpoint},
                    response={"insecure_cookies": cookies_without_secure, "secure_cookies": cookies_with_secure},
                    duration_ms=duration,
                )
            elif cookies_without_secure:
                # Site is HTTP, Secure flag would be irrelevant
                return self._make_result(
                    variant="secure_cookies",
                    status=Status.PARTIAL,
                    severity=Severity.INFO,
                    evidence=f"Cookies without Secure flag (site uses HTTP): {', '.join(cookies_without_secure)}",
                    details="Site uses HTTP so Secure flag is not applicable, but the site should migrate to HTTPS first",
                    request={"endpoint": login_endpoint},
                    response={"insecure_cookies": cookies_without_secure},
                    duration_ms=duration,
                )
            else:
                return self._make_result(
                    variant="secure_cookies",
                    status=Status.DEFENDED,
                    evidence=f"All cookies have Secure flag: {', '.join(cookies_with_secure)}",
                    details="All cookies are marked Secure; they will only be sent over HTTPS",
                    request={"endpoint": login_endpoint},
                    response={"secure_cookies": cookies_with_secure},
                    duration_ms=duration,
                )
        except Exception as e:
            return self._make_result(
                variant="secure_cookies",
                status=Status.ERROR,
                details=str(e),
                duration_ms=(time.monotonic() - start) * 1000,
            )

    async def cleanup(self, client) -> None:
        """No persistent state created by TLS tests."""
        pass
