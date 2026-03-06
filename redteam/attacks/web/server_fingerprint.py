"""Server technology fingerprinting via response headers and content.

Identifies server software, frameworks, and versions from HTTP response
headers, common files, error pages, and technology-specific markers.

Evaluation:
- Version numbers exposed -> VULNERABLE (information disclosure)
- Technology identified without version -> INFO
- No identifying information found -> DEFENDED
"""

import time
import re
import logging

from redteam.base import Attack, AttackResult, Severity, Status

logger = logging.getLogger(__name__)


# Known technology markers in response headers
TECH_HEADERS = {
    "X-AspNet-Version": "ASP.NET",
    "X-AspNetMvc-Version": "ASP.NET MVC",
    "X-Drupal-Cache": "Drupal",
    "X-Drupal-Dynamic-Cache": "Drupal",
    "X-Generator": "CMS/Framework",
    "X-Shopify-Stage": "Shopify",
    "X-Varnish": "Varnish Cache",
    "X-Cache": "Cache Layer",
    "Via": "Proxy/CDN",
    "X-Turbo-Charged-By": "LiteSpeed",
    "X-Litespeed-Cache": "LiteSpeed Cache",
    "X-WordPress-Cache": "WordPress",
    "X-Pingback": "WordPress",
    "X-Redirect-By": "WordPress",
    "CF-RAY": "Cloudflare",
    "X-Sucuri-ID": "Sucuri WAF",
    "X-CDN": "CDN",
    "X-Served-By": "Platform/CDN",
    "X-Runtime": "Ruby/Rails",
    "X-Request-Id": "Rails/Phoenix",
    "X-Django-Debug": "Django",
}

# Error page signatures for technology identification
ERROR_SIGNATURES = {
    "Apache": [
        r"Apache/[\d.]+ Server at",
        r"<address>Apache/",
    ],
    "nginx": [
        r"<center>nginx/",
        r"<hr><center>nginx",
    ],
    "IIS": [
        r"Microsoft-IIS/",
        r"<h2>404 - File or directory not found",
    ],
    "Tomcat": [
        r"Apache Tomcat/",
        r"<h1>HTTP Status 404",
    ],
    "Express": [
        r"Cannot GET /",
        r"<!DOCTYPE html>\s*<html.*<head>\s*<title>Error</title>",
    ],
    "Django": [
        r"Page not found \(404\)",
        r"You're seeing this error because you have <code>DEBUG = True</code>",
    ],
    "Rails": [
        r"Action Controller: Exception Caught",
        r"Routing Error",
    ],
    "Spring": [
        r"Whitelabel Error Page",
        r"There was an unexpected error",
    ],
    "Laravel": [
        r"Whoops, looks like something went wrong",
        r"Symfony\\Component\\HttpKernel",
    ],
    "Flask": [
        r"<!DOCTYPE HTML PUBLIC.*<title>404 Not Found</title>",
    ],
}


class ServerFingerprintAttack(Attack):
    """Identify server technologies from response headers and content."""

    name = "web.server_fingerprint"
    category = "web"
    severity = Severity.INFO
    description = "Server technology fingerprinting and version detection"
    target_types = {"generic"}

    async def execute(self, client) -> list[AttackResult]:
        """Run all fingerprinting checks."""
        results = []

        results.append(await self._test_server_header(client))
        results.append(await self._test_powered_by(client))
        results.append(await self._test_common_files(client))
        results.append(await self._test_error_page_fingerprint(client))
        results.append(await self._test_response_header_analysis(client))

        return results

    async def _test_server_header(self, client) -> AttackResult:
        """Check Server response header for software identification."""
        start = time.monotonic()
        try:
            status_code, body, headers = await client.get("/", cookies={})
            duration = (time.monotonic() - start) * 1000

            server = headers.get("Server", "")
            if not server:
                return self._make_result(
                    variant="server_header",
                    status=Status.DEFENDED,
                    evidence="Server header not present",
                    details="Server does not disclose its identity via the Server header",
                    response={"Server": "missing"},
                    duration_ms=duration,
                )

            has_version = bool(re.search(r'\d+\.\d+', server))
            if has_version:
                return self._make_result(
                    variant="server_header",
                    status=Status.VULNERABLE,
                    severity=Severity.LOW,
                    evidence=f"Server: {server}",
                    details=f"Server header exposes software and version: {server}. Attackers can target known vulnerabilities for this version.",
                    response={"Server": server},
                    duration_ms=duration,
                )
            else:
                return self._make_result(
                    variant="server_header",
                    status=Status.DEFENDED,
                    evidence=f"Server: {server} (no version number)",
                    details=f"Server identified as '{server}' but version number is not disclosed",
                    response={"Server": server},
                    duration_ms=duration,
                )
        except Exception as e:
            return self._make_result(
                variant="server_header",
                status=Status.ERROR,
                details=str(e),
                duration_ms=(time.monotonic() - start) * 1000,
            )

    async def _test_powered_by(self, client) -> AttackResult:
        """Check X-Powered-By header for technology/version exposure."""
        start = time.monotonic()
        try:
            status_code, body, headers = await client.get("/", cookies={})
            duration = (time.monotonic() - start) * 1000

            powered_by = headers.get("X-Powered-By", "")
            if not powered_by:
                return self._make_result(
                    variant="powered_by_header",
                    status=Status.DEFENDED,
                    evidence="X-Powered-By header not present",
                    details="Server does not disclose its technology stack via X-Powered-By",
                    response={"X-Powered-By": "missing"},
                    duration_ms=duration,
                )

            has_version = bool(re.search(r'\d+\.\d+', powered_by))
            if has_version:
                return self._make_result(
                    variant="powered_by_header",
                    status=Status.VULNERABLE,
                    severity=Severity.LOW,
                    evidence=f"X-Powered-By: {powered_by}",
                    details=f"Technology and version exposed: {powered_by}. Remove this header to reduce attack surface.",
                    response={"X-Powered-By": powered_by},
                    duration_ms=duration,
                )
            else:
                return self._make_result(
                    variant="powered_by_header",
                    status=Status.DEFENDED,
                    evidence=f"X-Powered-By: {powered_by} (no version)",
                    details=f"Framework identified as '{powered_by}' but version not disclosed",
                    response={"X-Powered-By": powered_by},
                    duration_ms=duration,
                )
        except Exception as e:
            return self._make_result(
                variant="powered_by_header",
                status=Status.ERROR,
                details=str(e),
                duration_ms=(time.monotonic() - start) * 1000,
            )

    async def _test_common_files(self, client) -> AttackResult:
        """Probe for common technology indicator files."""
        start = time.monotonic()
        probe_paths = [
            "/robots.txt",
            "/sitemap.xml",
            "/humans.txt",
            "/crossdomain.xml",
            "/.well-known/security.txt",
        ]
        findings = []
        try:
            for path in probe_paths:
                try:
                    status_code, body, headers = await client.get(path, cookies={})
                    if status_code == 200 and len(body.strip()) > 0:
                        # Summarize content (first 200 chars)
                        summary = body.strip()[:200]
                        findings.append({"path": path, "status": status_code, "summary": summary})
                except Exception:
                    continue

            duration = (time.monotonic() - start) * 1000

            if findings:
                found_paths = [f["path"] for f in findings]
                return self._make_result(
                    variant="common_files",
                    status=Status.DEFENDED,
                    evidence=f"Found {len(findings)} common files: {', '.join(found_paths)}",
                    details="Common web files detected; review for sensitive information disclosure",
                    request={"probed_paths": probe_paths},
                    response={"findings": findings},
                    duration_ms=duration,
                )
            else:
                return self._make_result(
                    variant="common_files",
                    status=Status.DEFENDED,
                    evidence="No common indicator files found",
                    details=f"Probed {len(probe_paths)} common paths, none returned content",
                    request={"probed_paths": probe_paths},
                    duration_ms=duration,
                )
        except Exception as e:
            return self._make_result(
                variant="common_files",
                status=Status.ERROR,
                details=str(e),
                duration_ms=(time.monotonic() - start) * 1000,
            )

    async def _test_error_page_fingerprint(self, client) -> AttackResult:
        """Analyze the 404 error page for technology signatures."""
        start = time.monotonic()
        try:
            status_code, body, headers = await client.get(
                "/nonexistent_redteam_probe_xyz123", cookies={}
            )
            duration = (time.monotonic() - start) * 1000

            detected = []
            for tech_name, patterns in ERROR_SIGNATURES.items():
                for pattern in patterns:
                    if re.search(pattern, body, re.IGNORECASE | re.DOTALL):
                        detected.append(tech_name)
                        break

            if detected:
                return self._make_result(
                    variant="error_page_fingerprint",
                    status=Status.VULNERABLE,
                    severity=Severity.LOW,
                    evidence=f"Error page reveals technology: {', '.join(set(detected))}",
                    details=f"The 404 error page contains signatures identifying: {', '.join(set(detected))}. Use a custom error page to avoid information disclosure.",
                    request={"path": "/nonexistent_redteam_probe_xyz123"},
                    response={"status": status_code, "detected_tech": list(set(detected)), "body_preview": body[:300]},
                    duration_ms=duration,
                )
            else:
                return self._make_result(
                    variant="error_page_fingerprint",
                    status=Status.DEFENDED,
                    evidence=f"Error page ({status_code}) does not reveal technology",
                    details="The error page does not contain recognizable technology signatures",
                    request={"path": "/nonexistent_redteam_probe_xyz123"},
                    response={"status": status_code, "body_preview": body[:200]},
                    duration_ms=duration,
                )
        except Exception as e:
            return self._make_result(
                variant="error_page_fingerprint",
                status=Status.ERROR,
                details=str(e),
                duration_ms=(time.monotonic() - start) * 1000,
            )

    async def _test_response_header_analysis(self, client) -> AttackResult:
        """Collect all response headers and identify technology markers."""
        start = time.monotonic()
        try:
            status_code, body, headers = await client.get("/", cookies={})
            duration = (time.monotonic() - start) * 1000

            findings = {}
            for header_name, tech_name in TECH_HEADERS.items():
                value = headers.get(header_name, "")
                if value:
                    findings[header_name] = {"technology": tech_name, "value": value}

            if findings:
                summary = "; ".join(
                    f"{h}: {f['value'][:80]} ({f['technology']})"
                    for h, f in findings.items()
                )
                return self._make_result(
                    variant="response_header_analysis",
                    status=Status.DEFENDED,
                    evidence=f"Technology markers found in {len(findings)} headers: {summary[:500]}",
                    details="Response headers reveal technology stack components",
                    request={"method": "GET", "path": "/"},
                    response={"tech_headers": findings, "total_headers": len(headers)},
                    duration_ms=duration,
                )
            else:
                return self._make_result(
                    variant="response_header_analysis",
                    status=Status.DEFENDED,
                    evidence="No known technology markers found in response headers",
                    details="Response headers do not contain recognized technology-identifying headers",
                    request={"method": "GET", "path": "/"},
                    response={"total_headers": len(headers)},
                    duration_ms=duration,
                )
        except Exception as e:
            return self._make_result(
                variant="response_header_analysis",
                status=Status.ERROR,
                details=str(e),
                duration_ms=(time.monotonic() - start) * 1000,
            )

    async def cleanup(self, client) -> None:
        """No persistent state created by fingerprinting."""
        pass
