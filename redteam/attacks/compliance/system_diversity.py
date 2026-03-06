"""System component diversity — NIST SP 800-172 Control 3.13.1e.

Checks whether the system relies on homogeneous components (single OS, single
web server, single database engine) which facilitates APT common-mode attacks.
A monoculture environment means a single exploit, vulnerability, or supply-chain
compromise can propagate uniformly across all components.
"""

import json
import re

from redteam.base import Attack, AttackResult, Severity, Status


class SystemDiversityAttack(Attack):
    name = "compliance.system_diversity"
    category = "compliance"
    severity = Severity.LOW
    description = (
        "NIST 800-172 3.13.1e — Assess system component diversity to reduce "
        "malicious code propagation"
    )

    PROBE_ENDPOINTS = ["/", "/admin/", "/api/ai_chat.php", "/admin/login.php"]

    SECURITY_HEADERS = [
        "x-frame-options",
        "content-security-policy",
        "strict-transport-security",
    ]

    ERROR_ENDPOINTS = [
        ("/api/ai_chat.php", {"Content-Type": "application/json"}, "{}"),
        ("/admin/login.php", {"Content-Type": "application/x-www-form-urlencoded"}, "user=&pass="),
        ("/api/nonexistent_endpoint_probe.php", {}, ""),
    ]

    async def execute(self, client) -> list[AttackResult]:
        results = []

        # ----------------------------------------------------------------
        # 1. web_server_monoculture
        # ----------------------------------------------------------------
        server_headers = {}
        server_request_log = []

        for path in self.PROBE_ENDPOINTS:
            status_code, body, headers = await client.get(path)
            server_val = ""
            for key, val in headers.items():
                if key.lower() == "server":
                    server_val = val.strip()
                    break
            server_headers[path] = server_val
            server_request_log.append({
                "path": path,
                "status": status_code,
                "server": server_val,
            })

        # Normalise: strip version numbers for software-identity comparison
        def _software_name(header_val: str) -> str:
            return re.split(r"[/\s]", header_val.strip())[0].lower() if header_val else ""

        software_names = {_software_name(v) for v in server_headers.values() if v}
        non_empty_values = [v for v in server_headers.values() if v]
        unique_values = set(non_empty_values)

        if len(non_empty_values) == 0:
            ws_status = Status.DEFENDED
            ws_evidence = "No Server headers returned across any probed endpoint."
            ws_detail = (
                "All endpoints suppress the Server header. This is a positive "
                "security practice that also prevents monoculture fingerprinting. "
                "NIST SP 800-172 3.13.1e — no web server monoculture evidence detected."
            )
        elif len(unique_values) == 1 and len(non_empty_values) >= 2:
            ws_status = Status.PARTIAL
            ws_evidence = (
                f"All {len(non_empty_values)} responding endpoints report the same "
                f"Server header: '{next(iter(unique_values))}'. "
                f"Endpoint detail: {json.dumps(server_request_log)}"
            )
            ws_detail = (
                "The web tier is homogeneous — every probed endpoint advertises "
                "the same server software. A single exploit targeting this server "
                "software would affect all endpoints equally. "
                "NIST SP 800-172 3.13.1e recommends architectural diversity to "
                "limit common-mode vulnerability propagation. Consider introducing "
                "a reverse proxy or CDN layer with a different technology to "
                "reduce monoculture risk."
            )
        elif len(software_names) == 1 and len(non_empty_values) >= 2:
            # Same software family, different version strings
            ws_status = Status.PARTIAL
            ws_evidence = (
                f"All endpoints run the same server software family "
                f"('{next(iter(software_names))}'). "
                f"Version strings: {json.dumps(list(unique_values))}. "
                f"Endpoint detail: {json.dumps(server_request_log)}"
            )
            ws_detail = (
                "All endpoints share the same server software family despite "
                "minor version differences. A class-level vulnerability in this "
                "software family would affect the entire web tier simultaneously. "
                "NIST SP 800-172 3.13.1e calls for component diversity to limit "
                "common-mode attack propagation."
            )
        else:
            ws_status = Status.DEFENDED
            ws_evidence = (
                f"Multiple distinct Server values detected across endpoints: "
                f"{json.dumps(list(unique_values))}. "
                f"Endpoint detail: {json.dumps(server_request_log)}"
            )
            ws_detail = (
                "The web tier shows server software diversity — different "
                "endpoints report different Server headers, indicating layered "
                "or heterogeneous infrastructure. This reduces the blast radius "
                "of a single-software exploit. NIST SP 800-172 3.13.1e — "
                "component diversity appears present at the web tier."
            )

        results.append(self._make_result(
            variant="web_server_monoculture",
            status=ws_status,
            evidence=ws_evidence,
            details=ws_detail,
            request={"endpoints_probed": self.PROBE_ENDPOINTS},
            response={"server_headers": server_headers, "unique_values": list(unique_values)},
        ))

        # ----------------------------------------------------------------
        # 2. technology_stack_fingerprint
        # ----------------------------------------------------------------
        stack_inventory = {}
        stack_request_log = []

        for path in self.PROBE_ENDPOINTS:
            status_code, body, headers = await client.get(path)
            endpoint_tech = []

            for key, val in headers.items():
                key_lower = key.lower()
                if key_lower == "x-powered-by":
                    endpoint_tech.append(f"X-Powered-By: {val}")
                    stack_inventory.setdefault("powered_by", set()).add(val.strip())
                if key_lower == "set-cookie":
                    # Identify framework-specific cookie names
                    cookie_name = val.split("=")[0].strip().lower()
                    if "phpsessid" in cookie_name:
                        endpoint_tech.append("Cookie: PHPSESSID (PHP session)")
                        stack_inventory.setdefault("session_tech", set()).add("PHP")
                    elif "jsessionid" in cookie_name:
                        endpoint_tech.append("Cookie: JSESSIONID (Java/Servlet)")
                        stack_inventory.setdefault("session_tech", set()).add("Java")
                    elif "asp.net_sessionid" in cookie_name:
                        endpoint_tech.append("Cookie: ASP.NET_SessionId (.NET)")
                        stack_inventory.setdefault("session_tech", set()).add(".NET")

            # Detect .php extension in path
            if path.endswith(".php"):
                stack_inventory.setdefault("file_extensions", set()).add("php")
                endpoint_tech.append("Path extension: .php")

            # Inspect body for framework signatures
            body_lower = body.lower()
            if "wp-content" in body_lower or "wordpress" in body_lower:
                stack_inventory.setdefault("cms", set()).add("WordPress")
                endpoint_tech.append("Body: WordPress indicators")
            if "laravel" in body_lower:
                stack_inventory.setdefault("framework", set()).add("Laravel")
                endpoint_tech.append("Body: Laravel indicators")
            if "symfony" in body_lower:
                stack_inventory.setdefault("framework", set()).add("Symfony")
                endpoint_tech.append("Body: Symfony indicators")

            stack_request_log.append({
                "path": path,
                "status": status_code,
                "tech_indicators": endpoint_tech,
            })

        # Serialise sets for JSON
        stack_inventory_serialisable = {
            k: list(v) for k, v in stack_inventory.items()
        }

        # Assess diversity
        tech_categories = len(stack_inventory)
        all_single_tech = all(len(v) == 1 for v in stack_inventory.values())

        php_dominant = (
            stack_inventory.get("file_extensions", set()) == {"php"}
            and len(stack_inventory.get("powered_by", set())) <= 1
            and len(stack_inventory.get("session_tech", set())) <= 1
        )

        if php_dominant or (tech_categories > 0 and all_single_tech):
            fp_status = Status.PARTIAL
            fp_evidence = (
                f"Technology stack fingerprint reveals a single-technology environment. "
                f"Inventory: {json.dumps(stack_inventory_serialisable)}. "
                f"Endpoint detail: {json.dumps(stack_request_log)}"
            )
            fp_detail = (
                "The detected technology stack is homogeneous — a single primary "
                "language/framework is present throughout. A single vulnerability "
                "in this technology (e.g., a PHP RCE, a framework deserialization "
                "flaw) would affect the entire application surface uniformly. "
                "NIST SP 800-172 3.13.1e recommends architectural diversity: "
                "consider introducing diverse components (e.g., a Go or Python "
                "microservice, a different CMS tier) to reduce monoculture risk "
                "and limit malicious-code propagation."
            )
        elif tech_categories == 0:
            fp_status = Status.DEFENDED
            fp_evidence = (
                "No technology stack indicators detected in headers, cookies, or "
                "body content across probed endpoints. Stack is well-obscured."
            )
            fp_detail = (
                "The system does not expose technology stack indicators in observable "
                "HTTP artifacts. This prevents fingerprinting and is consistent with "
                "NIST SP 800-172 3.13.1e diversity requirements — no monoculture "
                "evidence found through passive fingerprinting."
            )
        else:
            fp_status = Status.DEFENDED
            fp_evidence = (
                f"Multiple technology indicators detected: "
                f"{json.dumps(stack_inventory_serialisable)}. "
                f"Endpoint detail: {json.dumps(stack_request_log)}"
            )
            fp_detail = (
                "The technology stack shows some diversity across observable "
                "indicators. Multiple languages or frameworks appear to be in use. "
                "NIST SP 800-172 3.13.1e — component diversity present, limiting "
                "common-mode attack propagation."
            )

        results.append(self._make_result(
            variant="technology_stack_fingerprint",
            status=fp_status,
            evidence=fp_evidence,
            details=fp_detail,
            request={"endpoints_probed": self.PROBE_ENDPOINTS},
            response={"stack_inventory": stack_inventory_serialisable, "endpoint_detail": stack_request_log},
        ))

        # ----------------------------------------------------------------
        # 3. security_header_diversity
        # ----------------------------------------------------------------
        endpoint_sec_headers = {}
        sec_request_log = []

        for path in self.PROBE_ENDPOINTS:
            status_code, body, headers = await client.get(path)
            present = {}
            for key, val in headers.items():
                if key.lower() in self.SECURITY_HEADERS:
                    present[key.lower()] = val.strip()
            endpoint_sec_headers[path] = present
            sec_request_log.append({
                "path": path,
                "status": status_code,
                "security_headers": present,
            })

        # Compare postures: count endpoints with weaker vs stronger postures
        header_sets = [frozenset(v.keys()) for v in endpoint_sec_headers.values()]
        unique_postures = len(set(header_sets))
        min_headers = min((len(s) for s in header_sets), default=0)
        max_headers = max((len(s) for s in header_sets), default=0)
        posture_gap = max_headers - min_headers

        # Identify weaker endpoints
        weaker_endpoints = [
            path for path, headers_present in endpoint_sec_headers.items()
            if len(headers_present) < max_headers
        ]

        if unique_postures > 1 and posture_gap >= 1:
            sh_status = Status.PARTIAL
            sh_evidence = (
                f"Security header posture is inconsistent across endpoints. "
                f"{len(weaker_endpoints)} endpoint(s) have a weaker posture than "
                f"the strongest ({max_headers} headers): {weaker_endpoints}. "
                f"Posture gap: {posture_gap} missing header(s) on weaker endpoints. "
                f"Detail: {json.dumps(sec_request_log)}"
            )
            sh_detail = (
                "Different endpoints present different security header postures, "
                "indicating they may be served by distinct components with "
                "inconsistent hardening. While diversity itself is positive, "
                "inconsistent security policies suggest some components are "
                "inadequately hardened. Weaker endpoints may represent legacy "
                "or less-maintained technology components. "
                "NIST SP 800-172 3.13.1e — ensure all diverse components meet "
                "a consistent baseline security posture to avoid introducing "
                "weak links through architectural heterogeneity."
            )
        elif unique_postures == 1 and max_headers == 0:
            sh_status = Status.PARTIAL
            sh_evidence = (
                f"No security headers ({', '.join(self.SECURITY_HEADERS)}) detected "
                f"on any of the {len(self.PROBE_ENDPOINTS)} probed endpoints. "
                f"Detail: {json.dumps(sec_request_log)}"
            )
            sh_detail = (
                "Security headers are absent across all probed endpoints. While "
                "this is consistent (suggesting a single component or a uniformly "
                "misconfigured set), the absence indicates inadequate hardening "
                "regardless of diversity. A monoculture of poorly-configured "
                "components amplifies the risk of common-mode failures. "
                "NIST SP 800-172 3.13.1e — apply security headers uniformly "
                "across all components."
            )
        else:
            sh_status = Status.DEFENDED
            sh_evidence = (
                f"Security header posture is consistent across all endpoints "
                f"({max_headers} header(s) present on each). "
                f"Detail: {json.dumps(sec_request_log)}"
            )
            sh_detail = (
                "All probed endpoints present a uniform security header posture. "
                "Consistent hardening across components indicates that security "
                "policy is applied uniformly regardless of underlying technology. "
                "NIST SP 800-172 3.13.1e — consistent security posture observed."
            )

        results.append(self._make_result(
            variant="security_header_diversity",
            status=sh_status,
            evidence=sh_evidence,
            details=sh_detail,
            request={"endpoints_probed": self.PROBE_ENDPOINTS, "headers_checked": self.SECURITY_HEADERS},
            response={"endpoint_postures": {k: dict(v) for k, v in endpoint_sec_headers.items()}, "unique_postures": unique_postures},
        ))

        # ----------------------------------------------------------------
        # 4. dns_infrastructure
        # ----------------------------------------------------------------
        CDN_HEADERS = ["x-cdn", "via", "x-cache", "cf-ray", "x-amz-cf-id", "x-varnish",
                       "x-cache-hits", "x-cache-status", "x-served-by", "x-proxy-cache"]
        LB_HEADERS = ["x-request-id", "x-upstream", "x-forwarded-server",
                      "x-envoy-upstream-service-time"]

        cdn_indicators = []
        lb_indicators = []
        infra_request_log = []

        for path in self.PROBE_ENDPOINTS:
            status_code, body, headers = await client.get(path)
            endpoint_cdn = []
            endpoint_lb = []

            for key, val in headers.items():
                key_lower = key.lower()
                if key_lower in CDN_HEADERS:
                    endpoint_cdn.append(f"{key}: {val}")
                    cdn_indicators.append(f"{path} → {key}: {val}")
                if key_lower in LB_HEADERS:
                    endpoint_lb.append(f"{key}: {val}")
                    lb_indicators.append(f"{path} → {key}: {val}")

            infra_request_log.append({
                "path": path,
                "status": status_code,
                "cdn_headers": endpoint_cdn,
                "lb_headers": endpoint_lb,
            })

        has_cdn = len(cdn_indicators) > 0
        has_lb = len(lb_indicators) > 0

        if not has_cdn and not has_lb:
            dns_status = Status.PARTIAL
            dns_evidence = (
                "No CDN or load-balancer headers detected across any probed endpoint. "
                f"CDN headers checked: {CDN_HEADERS}. "
                f"LB headers checked: {LB_HEADERS}. "
                f"Detail: {json.dumps(infra_request_log)}"
            )
            dns_detail = (
                "No CDN or load-balancing infrastructure was detected from HTTP "
                "response headers. The system appears to be served from a single "
                "origin without traffic distribution or CDN diversity. This "
                "represents a single point of failure and eliminates the geographic "
                "and infrastructure diversity that CDN/LB layers provide. "
                "NIST SP 800-172 3.13.1e — consider introducing CDN or load "
                "balancing to distribute risk and reduce the impact of single-node "
                "compromises or availability attacks."
            )
        elif has_cdn:
            dns_status = Status.DEFENDED
            dns_evidence = (
                f"CDN presence detected via headers: {json.dumps(cdn_indicators)}. "
                + (f"Load balancer indicators also present: {json.dumps(lb_indicators)}. " if has_lb else "")
                + f"Detail: {json.dumps(infra_request_log)}"
            )
            dns_detail = (
                "CDN infrastructure detected. A CDN layer introduces geographic "
                "and infrastructure diversity, reducing the impact of single-origin "
                "compromises and providing some common-mode attack mitigation. "
                "NIST SP 800-172 3.13.1e — CDN/infrastructure diversity present."
            )
        else:
            dns_status = Status.DEFENDED
            dns_evidence = (
                f"Load balancer indicators detected: {json.dumps(lb_indicators)}. "
                f"No CDN headers. Detail: {json.dumps(infra_request_log)}"
            )
            dns_detail = (
                "Load balancing infrastructure detected, indicating traffic is "
                "distributed across multiple backend instances. This provides "
                "horizontal diversity that limits single-node failure impact. "
                "NIST SP 800-172 3.13.1e — load balancer diversity present."
            )

        results.append(self._make_result(
            variant="dns_infrastructure",
            status=dns_status,
            evidence=dns_evidence,
            details=dns_detail,
            request={"endpoints_probed": self.PROBE_ENDPOINTS, "cdn_headers_checked": CDN_HEADERS, "lb_headers_checked": LB_HEADERS},
            response={"cdn_indicators": cdn_indicators, "lb_indicators": lb_indicators},
        ))

        # ----------------------------------------------------------------
        # 5. error_handling_uniformity
        # ----------------------------------------------------------------
        error_responses = []
        error_request_log = []

        for path, extra_headers, body_payload in self.ERROR_ENDPOINTS:
            # Send a malformed/empty request to provoke an error response
            if body_payload:
                status_code, resp_body, headers = await client.post(
                    path,
                    data=body_payload,
                    headers=extra_headers,
                )
            else:
                status_code, resp_body, headers = await client.get(path)

            content_type = ""
            for key, val in headers.items():
                if key.lower() == "content-type":
                    content_type = val.strip()
                    break

            # Characterise the error format
            error_format = "unknown"
            body_stripped = resp_body.strip()
            if body_stripped.startswith("{") or body_stripped.startswith("["):
                try:
                    json.loads(body_stripped)
                    error_format = "json"
                except (json.JSONDecodeError, ValueError):
                    error_format = "json-like"
            elif re.search(r"<html|<body|<title", body_stripped, re.IGNORECASE):
                # Check for specific framework error pages
                if re.search(r"php\s*(fatal|parse|warning|error)", body_stripped, re.IGNORECASE):
                    error_format = "php-error-page"
                elif "apache" in body_stripped.lower() or "nginx" in body_stripped.lower():
                    error_format = "server-error-page"
                else:
                    error_format = "html"
            elif body_stripped == "":
                error_format = "empty"
            else:
                error_format = "plaintext"

            error_responses.append({
                "path": path,
                "status_code": status_code,
                "content_type": content_type,
                "error_format": error_format,
                "body_preview": resp_body[:120],
            })
            error_request_log.append({
                "path": path,
                "method": "POST" if body_payload else "GET",
                "status": status_code,
                "error_format": error_format,
            })

        # Check uniformity of error format
        error_formats = [r["error_format"] for r in error_responses]
        unique_formats = set(error_formats)
        all_identical = len(unique_formats) == 1

        if all_identical and len(error_responses) >= 2:
            err_status = Status.PARTIAL
            err_evidence = (
                f"All {len(error_responses)} error probes returned identical "
                f"format: '{next(iter(unique_formats))}'. "
                f"Detail: {json.dumps(error_request_log)}"
            )
            err_detail = (
                "All probed endpoints return errors in an identical format, "
                "suggesting a single centralised error handler or framework "
                "is in use across the entire application. While consistent "
                "error handling reduces information leakage, it is also a "
                "monoculture indicator — a single exploit that bypasses this "
                "error handler would affect every endpoint uniformly. "
                "NIST SP 800-172 3.13.1e — uniform error handling suggests "
                "component monoculture; consider segmenting error handling "
                "across independently implemented service tiers."
            )
        else:
            err_status = Status.DEFENDED
            err_evidence = (
                f"Error responses vary across endpoints — {len(unique_formats)} "
                f"distinct format(s) detected: {json.dumps(list(unique_formats))}. "
                f"Detail: {json.dumps(error_request_log)}"
            )
            err_detail = (
                "Different endpoints return errors in different formats, indicating "
                "that distinct components or error-handling mechanisms are in use "
                "across the system. This is consistent with architectural diversity. "
                "NIST SP 800-172 3.13.1e — diverse error handling suggests "
                "heterogeneous components, reducing common-mode attack propagation."
            )

        results.append(self._make_result(
            variant="error_handling_uniformity",
            status=err_status,
            evidence=err_evidence,
            details=err_detail,
            request={"endpoints_probed": [e[0] for e in self.ERROR_ENDPOINTS]},
            response={"error_responses": error_responses, "unique_formats": list(unique_formats)},
        ))

        return results
