"""CORS (Cross-Origin Resource Sharing) misconfiguration tests.

Tests whether the API returns overly permissive CORS headers that would
allow malicious sites to make authenticated cross-origin requests.

Evaluation:
- Access-Control-Allow-Origin: * AND Access-Control-Allow-Credentials: true -> CRITICAL
- Access-Control-Allow-Origin: * without credentials -> HIGH
- Origin echoed back with credentials allowed -> CRITICAL
- Restrictive or absent CORS headers -> DEFENDED
"""

import time
import logging

from redteam.base import Attack, AttackResult, Severity, Status

logger = logging.getLogger(__name__)


class CORSAttack(Attack):
    """Test CORS configuration for overly permissive policies."""

    name = "web.cors"
    category = "web"
    severity = Severity.HIGH
    description = "CORS misconfiguration and credential exposure tests"
    target_types = {"generic"}

    async def execute(self, client) -> list[AttackResult]:
        """Run all CORS variants."""
        results = []
        endpoints = self._get_test_endpoints()
        self._test_endpoint = endpoints[0]
        self._test_endpoint_2 = endpoints[1] if len(endpoints) > 1 else endpoints[0]

        results.append(await self._test_preflight_evil_origin(client))
        results.append(await self._test_get_with_evil_origin(client))
        results.append(await self._test_credentials_header(client))

        return results

    async def _test_preflight_evil_origin(self, client) -> AttackResult:
        """Send OPTIONS preflight from evil.com and check ACAO header."""
        start = time.monotonic()
        try:
            # Simulate preflight by sending POST with evil Origin
            # (OPTIONS is typically handled by the web server, so we test
            # via actual request with Origin header to see response headers)
            status_code, body, headers = await client.post(
                self._test_endpoint,
                json_body={"action": "get_messages", "session_id": "redteam-cors-test"},
                headers={
                    "Origin": "https://evil.com",
                    "Access-Control-Request-Method": "POST",
                    "Access-Control-Request-Headers": "Content-Type",
                },
            )
            duration = (time.monotonic() - start) * 1000

            acao = headers.get("Access-Control-Allow-Origin", "")
            acac = headers.get("Access-Control-Allow-Credentials", "").lower()

            if acao == "*" and acac == "true":
                return self._make_result(
                    variant="preflight_evil_origin",
                    status=Status.VULNERABLE,
                    severity=Severity.CRITICAL,
                    evidence=f"ACAO: {acao}, ACAC: {acac}",
                    details="Wildcard ACAO with credentials allowed - any site can make authenticated requests",
                    request={"Origin": "https://evil.com"},
                    response={"ACAO": acao, "ACAC": acac, "status": status_code},
                    duration_ms=duration,
                )
            elif acao == "https://evil.com":
                sev = Severity.CRITICAL if acac == "true" else Severity.HIGH
                return self._make_result(
                    variant="preflight_evil_origin",
                    status=Status.VULNERABLE,
                    severity=sev,
                    evidence=f"Server reflected evil Origin: ACAO={acao}, ACAC={acac}",
                    details="Origin reflection - server echoes back any Origin value",
                    request={"Origin": "https://evil.com"},
                    response={"ACAO": acao, "ACAC": acac},
                    duration_ms=duration,
                )
            elif acao == "*":
                return self._make_result(
                    variant="preflight_evil_origin",
                    status=Status.VULNERABLE,
                    severity=Severity.HIGH,
                    evidence=f"ACAO: * (wildcard without credentials)",
                    details="Wildcard CORS allows any site to read responses (no credentials)",
                    request={"Origin": "https://evil.com"},
                    response={"ACAO": acao, "ACAC": acac or "not set"},
                    duration_ms=duration,
                )
            else:
                return self._make_result(
                    variant="preflight_evil_origin",
                    status=Status.DEFENDED,
                    evidence=f"ACAO: '{acao}' (not permissive)",
                    details="CORS properly configured - evil origin not allowed",
                    request={"Origin": "https://evil.com"},
                    response={"ACAO": acao or "not set", "ACAC": acac or "not set"},
                    duration_ms=duration,
                )
        except Exception as e:
            return self._make_result(
                variant="preflight_evil_origin",
                status=Status.ERROR,
                details=str(e),
                duration_ms=(time.monotonic() - start) * 1000,
            )

    async def _test_get_with_evil_origin(self, client) -> AttackResult:
        """GET with Origin: evil.com and check if credentials are allowed."""
        start = time.monotonic()
        try:
            status_code, body, headers = await client.get(
                self._test_endpoint,
                params={"action": "get_messages", "session_id": "redteam-cors-test"},
                headers={"Origin": "https://evil.com"},
            )
            duration = (time.monotonic() - start) * 1000

            acao = headers.get("Access-Control-Allow-Origin", "")
            acac = headers.get("Access-Control-Allow-Credentials", "").lower()

            if acao in ("*", "https://evil.com") and acac == "true":
                return self._make_result(
                    variant="get_evil_origin",
                    status=Status.VULNERABLE,
                    severity=Severity.CRITICAL,
                    evidence=f"GET responds with ACAO={acao}, ACAC={acac}",
                    details="Authenticated GET requests readable from evil.com with credentials",
                    request={"Origin": "https://evil.com", "method": "GET"},
                    response={"ACAO": acao, "ACAC": acac},
                    duration_ms=duration,
                )
            elif acao in ("*", "https://evil.com"):
                return self._make_result(
                    variant="get_evil_origin",
                    status=Status.VULNERABLE,
                    severity=Severity.HIGH,
                    evidence=f"GET responds with ACAO={acao} (no credentials)",
                    details="GET responses readable from evil.com but without cookies",
                    request={"Origin": "https://evil.com"},
                    response={"ACAO": acao, "ACAC": acac or "not set"},
                    duration_ms=duration,
                )
            else:
                return self._make_result(
                    variant="get_evil_origin",
                    status=Status.DEFENDED,
                    evidence=f"ACAO: '{acao}' - evil origin not reflected",
                    details="GET CORS properly restricted",
                    request={"Origin": "https://evil.com"},
                    response={"ACAO": acao or "not set"},
                    duration_ms=duration,
                )
        except Exception as e:
            return self._make_result(
                variant="get_evil_origin",
                status=Status.ERROR,
                details=str(e),
                duration_ms=(time.monotonic() - start) * 1000,
            )

    async def _test_credentials_header(self, client) -> AttackResult:
        """Check if Access-Control-Allow-Credentials is true on any endpoint."""
        start = time.monotonic()
        try:
            # Test multiple endpoints for credential exposure
            endpoints = [
                (self._test_endpoint, {"action": "get_messages", "session_id": "redteam-cors-test"}),
                (self._test_endpoint_2, {"action": "get_notes", "bearing_id": "test"}),
            ]

            credentials_found = False
            evidence_details = []

            for endpoint, params in endpoints:
                status_code, body, headers = await client.get(
                    endpoint,
                    params=params,
                    headers={"Origin": "https://evil.com"},
                )
                acac = headers.get("Access-Control-Allow-Credentials", "").lower()
                if acac == "true":
                    credentials_found = True
                    evidence_details.append(f"{endpoint}: ACAC=true")

            duration = (time.monotonic() - start) * 1000

            if credentials_found:
                return self._make_result(
                    variant="credentials_allowed",
                    status=Status.VULNERABLE,
                    severity=Severity.HIGH,
                    evidence=f"Credentials allowed on: {', '.join(evidence_details)}",
                    details="Access-Control-Allow-Credentials: true enables cookie-based cross-origin requests",
                    request={"checked_endpoints": [e[0] for e in endpoints]},
                    response={"findings": evidence_details},
                    duration_ms=duration,
                )
            else:
                return self._make_result(
                    variant="credentials_allowed",
                    status=Status.DEFENDED,
                    evidence="No endpoints return Access-Control-Allow-Credentials: true",
                    details="Cross-origin requests cannot include cookies",
                    request={"checked_endpoints": [e[0] for e in endpoints]},
                    response={"credentials_allowed": False},
                    duration_ms=duration,
                )
        except Exception as e:
            return self._make_result(
                variant="credentials_allowed",
                status=Status.ERROR,
                details=str(e),
                duration_ms=(time.monotonic() - start) * 1000,
            )

    async def cleanup(self, client) -> None:
        """No persistent state created by CORS tests."""
        pass
