"""Open redirect vulnerability tests.

Tests whether the application can be tricked into redirecting users to
arbitrary external domains via URL parameters, which is commonly exploited
in phishing attacks.

Evaluation:
- Response redirects to evil domain -> VULNERABLE
- Response redirects to javascript: URI -> VULNERABLE
- No redirect to external domain -> DEFENDED
"""

import time
import logging

from redteam.base import Attack, AttackResult, Severity, Status

logger = logging.getLogger(__name__)

# Evil domain used as redirect target (not a real site)
EVIL_DOMAIN = "evil.com"
EVIL_URL = f"https://{EVIL_DOMAIN}"

# Common parameter names that accept redirect URLs
REDIRECT_PARAMS = [
    "redirect", "url", "next", "return", "returnTo",
    "goto", "dest", "continue", "redirect_uri", "redir",
]


class OpenRedirectAttack(Attack):
    """Test for open redirect vulnerabilities via URL parameters."""

    name = "web.open_redirect"
    category = "web"
    severity = Severity.MEDIUM
    description = "Open redirect vulnerability detection via URL parameters"
    target_types = {"generic"}

    async def execute(self, client) -> list[AttackResult]:
        """Run all open redirect variants."""
        results = []

        results.append(await self._test_common_params(client))
        results.append(await self._test_login_redirect(client))
        results.append(await self._test_protocol_bypass(client))
        results.append(await self._test_javascript_redirect(client))

        return results

    def _is_evil_redirect(self, status_code: int, headers: dict) -> bool:
        """Check if response is a redirect pointing to evil domain."""
        if status_code not in (301, 302, 303, 307, 308):
            return False
        location = headers.get("Location", "")
        return EVIL_DOMAIN in location.lower()

    async def _test_common_params(self, client) -> AttackResult:
        """Try common redirect parameters on each test endpoint."""
        start = time.monotonic()
        endpoints = self._get_test_endpoints()
        vulnerable_findings = []

        try:
            for endpoint in endpoints:
                for param in REDIRECT_PARAMS:
                    try:
                        url = f"{client.base_url}{endpoint}"
                        async with client._session.get(
                            url,
                            params={param: EVIL_URL},
                            allow_redirects=False,
                        ) as resp:
                            status_code = resp.status
                            headers = dict(resp.headers)

                        if self._is_evil_redirect(status_code, headers):
                            vulnerable_findings.append({
                                "endpoint": endpoint,
                                "param": param,
                                "status": status_code,
                                "location": headers.get("Location", ""),
                            })
                    except Exception:
                        continue

            duration = (time.monotonic() - start) * 1000

            if vulnerable_findings:
                first = vulnerable_findings[0]
                return self._make_result(
                    variant="common_params",
                    status=Status.VULNERABLE,
                    evidence=f"Open redirect via ?{first['param']}= on {first['endpoint']} -> {first['location']}",
                    details=f"Found {len(vulnerable_findings)} open redirect(s) via URL parameters. Attackers can craft phishing URLs using your domain.",
                    request={"endpoints_tested": endpoints, "params_tested": REDIRECT_PARAMS},
                    response={"findings": vulnerable_findings},
                    duration_ms=duration,
                )
            else:
                return self._make_result(
                    variant="common_params",
                    status=Status.DEFENDED,
                    evidence="No open redirects found via common URL parameters",
                    details=f"Tested {len(REDIRECT_PARAMS)} parameter names across {len(endpoints)} endpoints",
                    request={"endpoints_tested": endpoints, "params_tested": REDIRECT_PARAMS},
                    duration_ms=duration,
                )
        except Exception as e:
            return self._make_result(
                variant="common_params",
                status=Status.ERROR,
                details=str(e),
                duration_ms=(time.monotonic() - start) * 1000,
            )

    async def _test_login_redirect(self, client) -> AttackResult:
        """Try redirect parameters on the login endpoint."""
        start = time.monotonic()
        login_endpoint = self._get_login_endpoint()
        login_params = ["redirect_to", "next", "return", "returnTo", "redirect", "continue"]
        vulnerable_findings = []

        try:
            for param in login_params:
                try:
                    url = f"{client.base_url}{login_endpoint}"
                    async with client._session.get(
                        url,
                        params={param: EVIL_URL},
                        allow_redirects=False,
                    ) as resp:
                        status_code = resp.status
                        headers = dict(resp.headers)

                    if self._is_evil_redirect(status_code, headers):
                        vulnerable_findings.append({
                            "param": param,
                            "status": status_code,
                            "location": headers.get("Location", ""),
                        })
                except Exception:
                    continue

            duration = (time.monotonic() - start) * 1000

            if vulnerable_findings:
                first = vulnerable_findings[0]
                return self._make_result(
                    variant="login_redirect",
                    status=Status.VULNERABLE,
                    evidence=f"Login page open redirect via ?{first['param']}= -> {first['location']}",
                    details=f"Login page redirects to external domain. This is especially dangerous for phishing — attackers can create legitimate-looking login URLs.",
                    request={"endpoint": login_endpoint, "params_tested": login_params},
                    response={"findings": vulnerable_findings},
                    duration_ms=duration,
                )
            else:
                return self._make_result(
                    variant="login_redirect",
                    status=Status.DEFENDED,
                    evidence="Login endpoint does not redirect to external domains",
                    details=f"Tested {len(login_params)} redirect parameters on {login_endpoint}",
                    request={"endpoint": login_endpoint, "params_tested": login_params},
                    duration_ms=duration,
                )
        except Exception as e:
            return self._make_result(
                variant="login_redirect",
                status=Status.ERROR,
                details=str(e),
                duration_ms=(time.monotonic() - start) * 1000,
            )

    async def _test_protocol_bypass(self, client) -> AttackResult:
        """Try protocol-relative and encoding tricks to bypass naive validation."""
        start = time.monotonic()
        bypass_payloads = [
            f"//{EVIL_DOMAIN}",
            f"\\/\\/{EVIL_DOMAIN}",
            f"https:{EVIL_DOMAIN}",
            f"%2f%2f{EVIL_DOMAIN}",
            f"/{EVIL_DOMAIN}",
            f"\\{EVIL_DOMAIN}",
        ]
        endpoints = self._get_test_endpoints()
        vulnerable_findings = []

        try:
            for endpoint in endpoints:
                for payload in bypass_payloads:
                    for param in ["redirect", "url", "next", "return"]:
                        try:
                            url = f"{client.base_url}{endpoint}"
                            async with client._session.get(
                                url,
                                params={param: payload},
                                allow_redirects=False,
                            ) as resp:
                                status_code = resp.status
                                headers = dict(resp.headers)

                            if self._is_evil_redirect(status_code, headers):
                                vulnerable_findings.append({
                                    "endpoint": endpoint,
                                    "param": param,
                                    "payload": payload,
                                    "status": status_code,
                                    "location": headers.get("Location", ""),
                                })
                                # One finding per endpoint is enough
                                break
                        except Exception:
                            continue
                    if vulnerable_findings:
                        break

            duration = (time.monotonic() - start) * 1000

            if vulnerable_findings:
                first = vulnerable_findings[0]
                return self._make_result(
                    variant="protocol_bypass",
                    status=Status.VULNERABLE,
                    evidence=f"Bypass payload '{first['payload']}' via ?{first['param']}= caused redirect to {first['location']}",
                    details=f"Redirect validation bypassed using protocol-relative or encoded URL. Found {len(vulnerable_findings)} bypass(es).",
                    request={"payloads_tested": bypass_payloads},
                    response={"findings": vulnerable_findings},
                    duration_ms=duration,
                )
            else:
                return self._make_result(
                    variant="protocol_bypass",
                    status=Status.DEFENDED,
                    evidence="No protocol bypass payloads caused an external redirect",
                    details=f"Tested {len(bypass_payloads)} bypass payloads across {len(endpoints)} endpoints",
                    request={"payloads_tested": bypass_payloads},
                    duration_ms=duration,
                )
        except Exception as e:
            return self._make_result(
                variant="protocol_bypass",
                status=Status.ERROR,
                details=str(e),
                duration_ms=(time.monotonic() - start) * 1000,
            )

    async def _test_javascript_redirect(self, client) -> AttackResult:
        """Try javascript: URI in redirect parameters."""
        start = time.monotonic()
        js_payloads = [
            "javascript:alert(1)",
            "javascript:alert(document.domain)",
            "jAvAsCrIpT:alert(1)",
            "data:text/html,<script>alert(1)</script>",
        ]
        endpoints = self._get_test_endpoints()
        vulnerable_findings = []

        try:
            for endpoint in endpoints:
                for payload in js_payloads:
                    for param in ["redirect", "url", "next", "return"]:
                        try:
                            url = f"{client.base_url}{endpoint}"
                            async with client._session.get(
                                url,
                                params={param: payload},
                                allow_redirects=False,
                            ) as resp:
                                status_code = resp.status
                                headers = dict(resp.headers)

                            location = headers.get("Location", "")
                            if status_code in (301, 302, 303, 307, 308) and "javascript:" in location.lower():
                                vulnerable_findings.append({
                                    "endpoint": endpoint,
                                    "param": param,
                                    "payload": payload,
                                    "location": location,
                                })
                                break
                        except Exception:
                            continue

            duration = (time.monotonic() - start) * 1000

            if vulnerable_findings:
                first = vulnerable_findings[0]
                return self._make_result(
                    variant="javascript_redirect",
                    status=Status.VULNERABLE,
                    evidence=f"javascript: URI in Location header via ?{first['param']}={first['payload']} -> {first['location']}",
                    details="Server reflects javascript: URI in redirect Location header, enabling XSS via redirect",
                    request={"payloads_tested": js_payloads},
                    response={"findings": vulnerable_findings},
                    duration_ms=duration,
                )
            else:
                return self._make_result(
                    variant="javascript_redirect",
                    status=Status.DEFENDED,
                    evidence="No javascript: URI reflected in redirect headers",
                    details=f"Tested {len(js_payloads)} javascript/data URI payloads across endpoints",
                    request={"payloads_tested": js_payloads},
                    duration_ms=duration,
                )
        except Exception as e:
            return self._make_result(
                variant="javascript_redirect",
                status=Status.ERROR,
                details=str(e),
                duration_ms=(time.monotonic() - start) * 1000,
            )

    async def cleanup(self, client) -> None:
        """No persistent state created by redirect tests."""
        pass
