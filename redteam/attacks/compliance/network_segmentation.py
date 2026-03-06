"""Network segmentation of CUI-processing systems — NIST SP 800-172 Control 3.13.4e.

Verifies that Controlled Unclassified Information (CUI) processing endpoints
are properly isolated from non-CUI network segments. Tests admin API exposure,
internal debug endpoint visibility, database port reachability from the web
tier, CORS misconfiguration, dangerous HTTP method enablement, and path
traversal across segment boundaries.
"""

import json
import socket
from urllib.parse import urlparse

from redteam.base import Attack, AttackResult, Severity, Status


class NetworkSegmentationAttack(Attack):
    name = "compliance.network_segmentation"
    category = "compliance"
    severity = Severity.HIGH
    description = (
        "NIST SP 800-172 3.13.4e — Verify CUI-processing endpoints are "
        "isolated from non-CUI segments: admin API access, internal endpoint "
        "exposure, DB port reachability, CORS policy, HTTP method controls, "
        "and path traversal segmentation"
    )

    ADMIN_ENDPOINTS = [
        "/api/admin/users.php",
        "/api/admin/settings.php",
        "/api/admin/services.php",
    ]

    INTERNAL_ENDPOINTS = [
        "/api/phpinfo.php",
        "/api/debug.php",
        "/api/test.php",
        "/server-status",
        "/server-info",
        "/.env",
        "/api/.env",
    ]

    DB_PORT = 5432

    CUI_ENDPOINT = "/api/ai_chat.php"

    TRAVERSAL_PAYLOADS = [
        "/api/../../../etc/passwd",
        "/api/..%2f..%2f..%2fetc%2fpasswd",
    ]

    async def execute(self, client) -> list[AttackResult]:
        results = []

        # ----------------------------------------------------------------
        # 1. admin_api_public_access
        # ----------------------------------------------------------------
        accessible = []
        partially_exposed = []
        admin_request_paths = []

        for path in self.ADMIN_ENDPOINTS:
            status_code, body, headers = await client.get(path)
            admin_request_paths.append({"path": path, "status": status_code})

            if status_code == 200:
                # Determine if the response contains sensitive data
                body_lower = body.lower()
                sensitive_indicators = [
                    "user", "email", "password", "setting", "service",
                    "config", "admin", "role", "token", "secret",
                ]
                if any(ind in body_lower for ind in sensitive_indicators):
                    accessible.append(
                        f"{path}: HTTP {status_code} — response contains "
                        f"sensitive data. Preview: {body[:150]}"
                    )
                else:
                    partially_exposed.append(
                        f"{path}: HTTP {status_code} — accessible but "
                        "response does not appear to contain sensitive data."
                    )

        if accessible:
            admin_status = Status.VULNERABLE
            admin_evidence = "\n".join(accessible)
            admin_detail = (
                f"{len(accessible)} admin API endpoint(s) return HTTP 200 with "
                "sensitive data and no authentication. An attacker on any network "
                "segment can read admin data without credentials. "
                "NIST SP 800-172 3.13.4e requires that CUI systems be separated "
                "from general-access networks."
            )
        elif partially_exposed:
            admin_status = Status.PARTIAL
            admin_evidence = "\n".join(partially_exposed)
            admin_detail = (
                "Admin endpoint(s) return HTTP 200 without authentication, but "
                "the response body does not appear to contain sensitive content. "
                "Endpoints should require authentication regardless."
            )
        else:
            admin_status = Status.DEFENDED
            admin_evidence = (
                "All admin endpoints returned 401 or 403 without authentication."
            )
            admin_detail = (
                "Admin API endpoints are protected — unauthenticated requests "
                "are rejected. Proper access control enforced at the API layer."
            )

        results.append(self._make_result(
            variant="admin_api_public_access",
            status=admin_status,
            evidence=admin_evidence,
            details=admin_detail,
            request={"paths_tested": admin_request_paths},
            response={"accessible": accessible, "partial": partially_exposed},
        ))

        # ----------------------------------------------------------------
        # 2. internal_endpoints_exposed
        # ----------------------------------------------------------------
        exposed_internal = []
        internal_request_log = []

        for path in self.INTERNAL_ENDPOINTS:
            status_code, body, headers = await client.get(path)
            internal_request_log.append({"path": path, "status": status_code})

            if status_code == 200:
                exposed_internal.append(
                    f"{path}: HTTP {status_code} — endpoint is publicly "
                    f"reachable. Body preview: {body[:150]}"
                )

        if exposed_internal:
            internal_status = Status.VULNERABLE
            internal_evidence = "\n".join(exposed_internal)
            internal_detail = (
                f"{len(exposed_internal)} internal/debug endpoint(s) are "
                "reachable from the public network. Debug and diagnostic "
                "endpoints may expose server configuration, environment "
                "variables, or PHP internals. NIST SP 800-172 3.13.4e requires "
                "that such interfaces be confined to trusted internal segments."
            )
        else:
            internal_status = Status.DEFENDED
            internal_evidence = (
                "All internal and debug endpoints returned 403 or 404."
            )
            internal_detail = (
                "Internal/debug endpoints are not accessible from the public "
                "network. Attack surface is appropriately reduced."
            )

        results.append(self._make_result(
            variant="internal_endpoints_exposed",
            status=internal_status,
            evidence=internal_evidence,
            details=internal_detail,
            request={"paths_tested": internal_request_log},
            response={"exposed": exposed_internal},
        ))

        # ----------------------------------------------------------------
        # 3. database_port_exposure
        # ----------------------------------------------------------------
        parsed = urlparse(client.base_url)
        db_host = parsed.hostname or "localhost"

        db_reachable = False
        db_error_detail = ""

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result_code = sock.connect_ex((db_host, self.DB_PORT))
            sock.close()
            db_reachable = result_code == 0
        except OSError as exc:
            db_error_detail = str(exc)

        if db_reachable:
            db_status = Status.VULNERABLE
            db_evidence = (
                f"TCP port {self.DB_PORT} (PostgreSQL) on host '{db_host}' "
                "accepted a connection from the web-accessible network."
            )
            db_detail = (
                f"The database port {self.DB_PORT} is reachable from the same "
                "network context as the web application. The database tier should "
                "be isolated in a dedicated network segment with no direct "
                "inbound connectivity from the web/DMZ tier. "
                "NIST SP 800-172 3.13.4e requires CUI systems to be separated "
                "from other systems to limit lateral movement opportunities."
            )
        elif db_error_detail:
            db_status = Status.ERROR
            db_evidence = f"Socket error testing {db_host}:{self.DB_PORT} — {db_error_detail}"
            db_detail = (
                "Could not conclusively determine database port reachability "
                f"due to a socket error: {db_error_detail}"
            )
        else:
            db_status = Status.DEFENDED
            db_evidence = (
                f"TCP connection to {db_host}:{self.DB_PORT} was refused or "
                "timed out — port is not reachable from this network context."
            )
            db_detail = (
                "Database port is not accessible from the web-accessible network "
                "context. The database tier appears to be properly segmented."
            )

        results.append(self._make_result(
            variant="database_port_exposure",
            status=db_status,
            evidence=db_evidence,
            details=db_detail,
            request={"host": db_host, "port": self.DB_PORT, "timeout_seconds": 3},
            response={"reachable": db_reachable, "error": db_error_detail},
        ))

        # ----------------------------------------------------------------
        # 4. cors_segmentation
        # ----------------------------------------------------------------
        evil_origin = "https://evil.com"
        cors_status_code, cors_body, cors_headers = await client.get(
            self.CUI_ENDPOINT,
            headers={"Origin": evil_origin},
        )

        acao = ""
        for key, val in cors_headers.items():
            if key.lower() == "access-control-allow-origin":
                acao = val.strip()
                break

        if acao == "*":
            cors_status = Status.VULNERABLE
            cors_evidence = (
                f"Access-Control-Allow-Origin: * — wildcard CORS policy on "
                f"{self.CUI_ENDPOINT}. Any origin can make credentialed "
                "cross-origin requests to this CUI endpoint."
            )
            cors_detail = (
                "The CUI endpoint uses a wildcard CORS policy, allowing any "
                "external website to issue cross-origin requests and read "
                "responses. This undermines network segmentation at the "
                "application layer. NIST SP 800-172 3.13.4e requires CUI "
                "systems to restrict access to authorized segments and origins."
            )
        elif acao and evil_origin in acao:
            cors_status = Status.VULNERABLE
            cors_evidence = (
                f"Access-Control-Allow-Origin reflects the attacker-supplied "
                f"origin '{evil_origin}' on {self.CUI_ENDPOINT}."
            )
            cors_detail = (
                "The server reflects arbitrary Origin headers, effectively "
                "granting cross-origin access to any requester. This allows "
                "cross-site requests from untrusted origins to read CUI "
                "endpoint responses."
            )
        elif acao:
            cors_status = Status.DEFENDED
            cors_evidence = (
                f"Access-Control-Allow-Origin: '{acao}' — origin '{evil_origin}' "
                "is not reflected or wildcarded."
            )
            cors_detail = (
                "CORS policy restricts allowed origins. The evil.com origin was "
                "not granted access. CUI endpoint CORS is properly configured."
            )
        else:
            cors_status = Status.DEFENDED
            cors_evidence = (
                f"No Access-Control-Allow-Origin header returned for "
                f"Origin: {evil_origin} on {self.CUI_ENDPOINT}."
            )
            cors_detail = (
                "No CORS header returned for the untrusted origin. "
                "Cross-origin access is implicitly denied."
            )

        results.append(self._make_result(
            variant="cors_segmentation",
            status=cors_status,
            evidence=cors_evidence,
            details=cors_detail,
            request={
                "path": self.CUI_ENDPOINT,
                "headers": {"Origin": evil_origin},
            },
            response={
                "status_code": cors_status_code,
                "access_control_allow_origin": acao,
            },
        ))

        # ----------------------------------------------------------------
        # 5. http_method_exposure
        # ----------------------------------------------------------------
        method_issues = []

        # Use raw aiohttp session for OPTIONS and TRACE
        try:
            full_url = client.base_url.rstrip("/") + self.CUI_ENDPOINT

            async with client._session.options(full_url) as options_resp:
                options_code = options_resp.status
                options_resp_headers = dict(options_resp.headers)
                allow_header = options_resp_headers.get("Allow", "")

            dangerous_methods = ["TRACE", "PUT", "DELETE", "CONNECT"]
            found_dangerous = [
                m for m in dangerous_methods
                if m in allow_header.upper()
            ]

            if found_dangerous:
                method_issues.append(
                    f"OPTIONS {self.CUI_ENDPOINT}: Allow header lists "
                    f"dangerous methods: {', '.join(found_dangerous)}. "
                    f"Full Allow: '{allow_header}'"
                )

            # TRACE probe
            async with client._session.request("TRACE", full_url) as trace_resp:
                trace_code = trace_resp.status
                if trace_code == 200:
                    method_issues.append(
                        f"TRACE {self.CUI_ENDPOINT}: returned HTTP {trace_code}. "
                        "TRACE is enabled and may allow cross-site tracing (XST) attacks."
                    )

            if method_issues:
                method_status = Status.VULNERABLE
                method_evidence = "\n".join(method_issues)
                method_detail = (
                    "Dangerous HTTP methods are available on a CUI endpoint. "
                    "TRACE enables cross-site tracing attacks; PUT/DELETE could "
                    "allow unauthorized modification of CUI resources. "
                    "NIST SP 800-172 3.13.4e requires that access to CUI systems "
                    "be strictly controlled, including at the HTTP method level."
                )
            else:
                method_status = Status.DEFENDED
                method_evidence = (
                    f"OPTIONS returned HTTP {options_code} with Allow: '{allow_header}'. "
                    "No dangerous methods detected. TRACE returned non-200."
                )
                method_detail = (
                    "HTTP method exposure is controlled — dangerous methods "
                    "(TRACE, PUT, DELETE) are not advertised or enabled on the "
                    "CUI endpoint."
                )

        except Exception as exc:
            method_status = Status.ERROR
            method_evidence = f"Could not complete HTTP method probe: {exc}"
            method_detail = (
                "An error occurred while testing HTTP method exposure. "
                "Manual verification of TRACE and OPTIONS is recommended."
            )

        results.append(self._make_result(
            variant="http_method_exposure",
            status=method_status,
            evidence=method_evidence,
            details=method_detail,
            request={"path": self.CUI_ENDPOINT, "methods_tested": ["OPTIONS", "TRACE"]},
            response={"issues": method_issues},
        ))

        # ----------------------------------------------------------------
        # 6. directory_traversal_segmentation
        # ----------------------------------------------------------------
        traversal_hits = []
        traversal_log = []

        passwd_indicators = ["root:x:", "root:0:0", "/bin/bash", "/bin/sh", "daemon:"]

        for payload in self.TRAVERSAL_PAYLOADS:
            status_code, body, headers = await client.get(payload)
            traversal_log.append({"path": payload, "status": status_code})

            if status_code == 200 and any(
                ind in body for ind in passwd_indicators
            ):
                traversal_hits.append(
                    f"GET {payload}: HTTP {status_code} — response contains "
                    f"/etc/passwd content. Preview: {body[:200]}"
                )
            elif status_code == 200 and len(body) > 20:
                # 200 but unclear content — flag as partial
                traversal_hits.append(
                    f"GET {payload}: HTTP {status_code} — unexpected 200 response "
                    f"(may indicate traversal). Preview: {body[:150]}"
                )

        confirmed_traversal = [
            h for h in traversal_hits
            if any(ind in h for ind in passwd_indicators)
        ]

        if confirmed_traversal:
            trav_status = Status.VULNERABLE
            trav_evidence = "\n".join(confirmed_traversal)
            trav_detail = (
                "Path traversal bypassed the API segment boundary and returned "
                "contents of /etc/passwd. An attacker can read arbitrary files "
                "from the filesystem, crossing segment boundaries at the OS level. "
                "NIST SP 800-172 3.13.4e requires that CUI systems enforce "
                "strict boundaries preventing access to resources outside the "
                "authorized segment."
            )
        elif traversal_hits:
            trav_status = Status.PARTIAL
            trav_evidence = "\n".join(traversal_hits)
            trav_detail = (
                "Traversal payloads returned HTTP 200 with unexpected content, "
                "but /etc/passwd indicators were not confirmed. Manual review "
                "of the response bodies is recommended."
            )
        else:
            trav_status = Status.DEFENDED
            trav_evidence = (
                "All directory traversal payloads were blocked (non-200 responses)."
            )
            trav_detail = (
                "Path traversal attempts are blocked by the web server or "
                "application. The API segment boundary is enforced against "
                "filesystem escape attempts."
            )

        results.append(self._make_result(
            variant="directory_traversal_segmentation",
            status=trav_status,
            evidence=trav_evidence,
            details=trav_detail,
            request={"payloads_tested": traversal_log},
            response={"traversal_hits": traversal_hits},
        ))

        return results
