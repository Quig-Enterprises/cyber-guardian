"""HTTP methods testing for any web target.

Tests which HTTP methods the server supports and whether dangerous methods
(TRACE, PUT, DELETE) are enabled that could lead to security issues.

Evaluation:
- TRACE enabled (request echoed) -> VULNERABLE (XST attacks)
- PUT returns 200/201 -> VULNERABLE (arbitrary file upload)
- DELETE returns 200/204 -> VULNERABLE (arbitrary file deletion)
- Made-up method accepted with 200 -> PARTIAL (lax method validation)
- Dangerous methods return 405/403/501 -> DEFENDED
"""

import time
import logging

from redteam.base import Attack, AttackResult, Severity, Status

logger = logging.getLogger(__name__)


class HTTPMethodsAttack(Attack):
    """Test which HTTP methods are allowed and identify dangerous ones."""

    name = "web.http_methods"
    category = "web"
    severity = Severity.MEDIUM
    description = "HTTP method enumeration and dangerous method detection"
    target_types = {"generic"}

    async def execute(self, client) -> list[AttackResult]:
        """Run all HTTP method checks."""
        results = []
        endpoints = self._get_test_endpoints()
        self._test_endpoint = endpoints[0]

        results.append(await self._test_options_check(client))
        results.append(await self._test_trace_enabled(client))
        results.append(await self._test_put_enabled(client))
        results.append(await self._test_delete_enabled(client))
        results.append(await self._test_arbitrary_methods(client))

        return results

    async def _test_options_check(self, client) -> AttackResult:
        """Send OPTIONS request and parse Allow header."""
        start = time.monotonic()
        try:
            url = f"{client.base_url}{self._test_endpoint}"
            async with client._session.request("OPTIONS", url) as resp:
                duration = (time.monotonic() - start) * 1000
                headers = dict(resp.headers)
                allow = headers.get("Allow", "")
                status_code = resp.status

            methods = [m.strip() for m in allow.split(",") if m.strip()] if allow else []

            return self._make_result(
                variant="options_check",
                status=Status.DEFENDED,
                severity=Severity.INFO,
                evidence=f"OPTIONS returned Allow: {allow}" if allow else "No Allow header in OPTIONS response",
                details=f"Server advertises methods: {', '.join(methods)}" if methods else f"OPTIONS returned {status_code} with no Allow header",
                request={"method": "OPTIONS", "endpoint": self._test_endpoint},
                response={"status": status_code, "Allow": allow, "methods": methods},
                duration_ms=duration,
            )
        except Exception as e:
            return self._make_result(
                variant="options_check",
                status=Status.ERROR,
                details=str(e),
                duration_ms=(time.monotonic() - start) * 1000,
            )

    async def _test_trace_enabled(self, client) -> AttackResult:
        """Send TRACE request to check for cross-site tracing (XST) vulnerability."""
        start = time.monotonic()
        try:
            url = f"{client.base_url}{self._test_endpoint}"
            trace_headers = {"X-RedTeam-Trace": "canary-value-12345"}
            async with client._session.request("TRACE", url, headers=trace_headers) as resp:
                duration = (time.monotonic() - start) * 1000
                body = await resp.text()
                status_code = resp.status

            # TRACE should echo back the request; check if our canary appears
            if status_code == 200 and "canary-value-12345" in body:
                return self._make_result(
                    variant="trace_enabled",
                    status=Status.VULNERABLE,
                    evidence=f"TRACE echoed request body (status {status_code})",
                    details="TRACE method enabled; vulnerable to Cross-Site Tracing (XST) attacks that can steal credentials",
                    request={"method": "TRACE", "headers": trace_headers},
                    response={"status": status_code, "body_preview": body[:300]},
                    duration_ms=duration,
                )
            elif status_code == 200:
                return self._make_result(
                    variant="trace_enabled",
                    status=Status.PARTIAL,
                    evidence=f"TRACE returned 200 but did not echo request",
                    details="Server accepts TRACE but does not echo request body",
                    request={"method": "TRACE"},
                    response={"status": status_code, "body_preview": body[:200]},
                    duration_ms=duration,
                )
            else:
                return self._make_result(
                    variant="trace_enabled",
                    status=Status.DEFENDED,
                    evidence=f"TRACE returned {status_code}",
                    details="TRACE method properly disabled or rejected",
                    request={"method": "TRACE"},
                    response={"status": status_code},
                    duration_ms=duration,
                )
        except Exception as e:
            return self._make_result(
                variant="trace_enabled",
                status=Status.ERROR,
                details=str(e),
                duration_ms=(time.monotonic() - start) * 1000,
            )

    async def _test_put_enabled(self, client) -> AttackResult:
        """Try PUT to check for arbitrary file write risk."""
        start = time.monotonic()
        try:
            url = f"{client.base_url}{self._test_endpoint}"
            dummy_body = "redteam-put-test-content"
            async with client._session.request("PUT", url, data=dummy_body) as resp:
                duration = (time.monotonic() - start) * 1000
                body = await resp.text()
                status_code = resp.status

            if status_code in (200, 201):
                return self._make_result(
                    variant="put_enabled",
                    status=Status.VULNERABLE,
                    evidence=f"PUT returned {status_code}",
                    details="PUT method accepted; potential arbitrary file write or resource creation risk",
                    request={"method": "PUT", "endpoint": self._test_endpoint},
                    response={"status": status_code, "body_preview": body[:200]},
                    duration_ms=duration,
                )
            elif status_code in (401, 403, 405, 501):
                return self._make_result(
                    variant="put_enabled",
                    status=Status.DEFENDED,
                    evidence=f"PUT returned {status_code}",
                    details="PUT method properly rejected",
                    request={"method": "PUT"},
                    response={"status": status_code},
                    duration_ms=duration,
                )
            else:
                return self._make_result(
                    variant="put_enabled",
                    status=Status.PARTIAL,
                    evidence=f"PUT returned unexpected status {status_code}",
                    details=f"Server returned {status_code} for PUT request; review manually",
                    request={"method": "PUT"},
                    response={"status": status_code, "body_preview": body[:200]},
                    duration_ms=duration,
                )
        except Exception as e:
            return self._make_result(
                variant="put_enabled",
                status=Status.ERROR,
                details=str(e),
                duration_ms=(time.monotonic() - start) * 1000,
            )

    async def _test_delete_enabled(self, client) -> AttackResult:
        """Try DELETE to check for arbitrary deletion risk."""
        start = time.monotonic()
        try:
            url = f"{client.base_url}{self._test_endpoint}"
            async with client._session.request("DELETE", url) as resp:
                duration = (time.monotonic() - start) * 1000
                body = await resp.text()
                status_code = resp.status

            if status_code in (200, 204):
                return self._make_result(
                    variant="delete_enabled",
                    status=Status.VULNERABLE,
                    evidence=f"DELETE returned {status_code}",
                    details="DELETE method accepted; potential arbitrary resource deletion risk",
                    request={"method": "DELETE", "endpoint": self._test_endpoint},
                    response={"status": status_code, "body_preview": body[:200]},
                    duration_ms=duration,
                )
            elif status_code in (401, 403, 405, 501):
                return self._make_result(
                    variant="delete_enabled",
                    status=Status.DEFENDED,
                    evidence=f"DELETE returned {status_code}",
                    details="DELETE method properly rejected",
                    request={"method": "DELETE"},
                    response={"status": status_code},
                    duration_ms=duration,
                )
            else:
                return self._make_result(
                    variant="delete_enabled",
                    status=Status.PARTIAL,
                    evidence=f"DELETE returned unexpected status {status_code}",
                    details=f"Server returned {status_code} for DELETE; review manually",
                    request={"method": "DELETE"},
                    response={"status": status_code, "body_preview": body[:200]},
                    duration_ms=duration,
                )
        except Exception as e:
            return self._make_result(
                variant="delete_enabled",
                status=Status.ERROR,
                details=str(e),
                duration_ms=(time.monotonic() - start) * 1000,
            )

    async def _test_arbitrary_methods(self, client) -> AttackResult:
        """Try a made-up HTTP method to test method validation."""
        start = time.monotonic()
        try:
            url = f"{client.base_url}{self._test_endpoint}"
            async with client._session.request("FOOBAR", url) as resp:
                duration = (time.monotonic() - start) * 1000
                body = await resp.text()
                status_code = resp.status

            if status_code == 200:
                return self._make_result(
                    variant="arbitrary_methods",
                    status=Status.PARTIAL,
                    evidence=f"FOOBAR method returned 200",
                    details="Server does not validate HTTP methods; accepts arbitrary method names",
                    request={"method": "FOOBAR"},
                    response={"status": status_code, "body_preview": body[:200]},
                    duration_ms=duration,
                )
            elif status_code in (400, 405, 501):
                return self._make_result(
                    variant="arbitrary_methods",
                    status=Status.DEFENDED,
                    evidence=f"FOOBAR method returned {status_code}",
                    details="Server properly rejects unknown HTTP methods",
                    request={"method": "FOOBAR"},
                    response={"status": status_code},
                    duration_ms=duration,
                )
            else:
                return self._make_result(
                    variant="arbitrary_methods",
                    status=Status.DEFENDED,
                    evidence=f"FOOBAR method returned {status_code}",
                    details=f"Server returned {status_code} for unknown method",
                    request={"method": "FOOBAR"},
                    response={"status": status_code},
                    duration_ms=duration,
                )
        except Exception as e:
            return self._make_result(
                variant="arbitrary_methods",
                status=Status.ERROR,
                details=str(e),
                duration_ms=(time.monotonic() - start) * 1000,
            )

    async def cleanup(self, client) -> None:
        """No persistent state created by method tests."""
        pass
