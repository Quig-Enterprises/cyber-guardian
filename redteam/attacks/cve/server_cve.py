"""Server software CVE lookup attack module."""

import re
import time
import logging

from redteam.base import Attack, AttackResult, Severity, Status
from redteam.cve.engine import CVEEngine

logger = logging.getLogger(__name__)

# Patterns for extracting server software and version from headers
SERVER_RE = re.compile(r"^(nginx|apache|Apache)(?:[/ ]([\d.]+))?", re.IGNORECASE)
POWERED_BY_PHP_RE = re.compile(r"PHP/([\d.]+)", re.IGNORECASE)
POWERED_BY_ASP_RE = re.compile(r"ASP\.NET(?:[/ ]([\d.]+))?", re.IGNORECASE)

# Map raw header names to canonical software names for CVE lookup
SERVER_NAME_MAP = {
    "nginx": "nginx",
    "apache": "apache http server",
    "apache/": "apache http server",
    "openresty": "openresty",
    "litespeed": "litespeed",
    "caddy": "caddy",
    "iis": "microsoft iis",
}


class ServerCVEAttack(Attack):
    """Known CVE lookup for detected server software from HTTP headers."""

    name = "cve.server_cve"
    category = "cve"
    severity = Severity.HIGH
    description = "Known CVE lookup for detected server software"
    target_types = {"generic", "wordpress", "app"}

    async def execute(self, client) -> list[AttackResult]:
        results: list[AttackResult] = []
        start = time.monotonic()

        # Fetch headers from homepage
        try:
            status, body, headers = await client.get("/", cookies={})
        except Exception as exc:
            results.append(self._make_result(
                variant="server/connection_error",
                status=Status.ERROR,
                details=f"Failed to connect for header inspection: {exc}",
                duration_ms=(time.monotonic() - start) * 1000,
            ))
            return results

        # Detect all server software from headers
        detected: list[tuple[str, str]] = []  # (software_name, version)

        # Parse Server header
        server_header = headers.get("Server", "") or headers.get("server", "")
        if server_header:
            parsed = self._parse_server_header(server_header)
            if parsed:
                detected.append(parsed)

        # Parse X-Powered-By header
        powered_by = headers.get("X-Powered-By", "") or headers.get("x-powered-by", "")
        if powered_by:
            # PHP
            php_match = POWERED_BY_PHP_RE.search(powered_by)
            if php_match:
                detected.append(("php", php_match.group(1)))

            # ASP.NET
            asp_match = POWERED_BY_ASP_RE.search(powered_by)
            if asp_match:
                detected.append(("asp.net", asp_match.group(1) or ""))

        if not detected:
            results.append(self._make_result(
                variant="server/no_software",
                status=Status.DEFENDED,
                evidence="No server software version disclosed in headers",
                details="Server and X-Powered-By headers do not reveal software versions. "
                        "This is good security practice.",
                request={"method": "GET", "path": "/"},
                response={"status": status, "headers": {
                    "Server": server_header, "X-Powered-By": powered_by,
                }},
                duration_ms=(time.monotonic() - start) * 1000,
            ))
            return results

        # Query CVE engine for each detected software
        engine = CVEEngine(self._config)

        for software_name, version in detected:
            lookup_start = time.monotonic()

            if not version:
                # Software detected but no version; flag as info disclosure only
                results.append(self._make_result(
                    variant=f"server/{software_name}/no_version",
                    status=Status.PARTIAL,
                    severity=Severity.LOW,
                    evidence=f"Server software '{software_name}' detected but no version",
                    details=f"The server identifies as '{software_name}' but does not "
                            f"disclose a specific version. CVE lookup skipped.",
                    request={"method": "GET", "path": "/"},
                    response={"headers": {"Server": server_header, "X-Powered-By": powered_by}},
                    duration_ms=(time.monotonic() - lookup_start) * 1000,
                ))
                continue

            try:
                cves = await engine.lookup_server(software_name, version)
            except Exception as exc:
                logger.error("CVE lookup failed for %s/%s: %s", software_name, version, exc)
                results.append(self._make_result(
                    variant=f"server/{software_name}/engine_error",
                    status=Status.ERROR,
                    details=f"CVE engine error for {software_name} {version}: {exc}",
                    duration_ms=(time.monotonic() - lookup_start) * 1000,
                ))
                continue

            if not cves:
                results.append(self._make_result(
                    variant=f"server/{software_name}/no_cves",
                    status=Status.DEFENDED,
                    evidence=f"No known CVEs for {software_name} {version}",
                    details=f"Server software {software_name} version {version} "
                            f"has no known CVEs in configured data sources.",
                    duration_ms=(time.monotonic() - lookup_start) * 1000,
                ))
                continue

            for cve in cves:
                # Store finding in shared state for verification
                if hasattr(self, '_state'):
                    self._state.store_cve_finding(software_name, version, cve)

                risk = cve.risk_score
                if risk >= 4.0:
                    status_val = Status.VULNERABLE
                else:
                    status_val = Status.PARTIAL

                sev = self._cvss_to_severity(cve.cvss_v31_score)
                exploit_info = ""
                if cve.exploit_refs:
                    exploit_info = (
                        f" Exploits: {', '.join(r.url for r in cve.exploit_refs[:3])}"
                    )
                kev_info = " [CISA KEV]" if cve.in_kev else ""

                results.append(self._make_result(
                    variant=f"server/{software_name}/{cve.cve_id}",
                    status=status_val,
                    severity=sev,
                    evidence=(
                        f"{cve.cve_id} (CVSS {cve.cvss_v31_score or 'N/A'}, "
                        f"risk {risk:.1f}){kev_info}"
                    ),
                    details=(
                        f"{software_name} {version}: {cve.description[:300]}"
                        f"{' Fixed in: ' + cve.fixed_version if cve.fixed_version else ''}"
                        f"{exploit_info}"
                    ),
                    duration_ms=(time.monotonic() - lookup_start) * 1000,
                ))

        return results

    @staticmethod
    def _parse_server_header(header: str) -> tuple[str, str] | None:
        """Parse Server header to extract software name and version.

        Examples:
            "nginx/1.24.0" -> ("nginx", "1.24.0")
            "Apache/2.4.57 (Ubuntu)" -> ("apache http server", "2.4.57")
            "cloudflare" -> None (no version)
        """
        match = SERVER_RE.match(header.strip())
        if match:
            raw_name = match.group(1).lower()
            version = match.group(2) or ""
            canonical = SERVER_NAME_MAP.get(raw_name, raw_name)
            return (canonical, version)

        # Try simple "name/version" pattern for unlisted servers
        parts = header.strip().split("/", 1)
        if len(parts) == 2:
            name = parts[0].strip().lower()
            ver = parts[1].strip().split()[0] if parts[1].strip() else ""
            # Only return if version looks like a version number
            if ver and re.match(r"[\d.]+", ver):
                canonical = SERVER_NAME_MAP.get(name, name)
                return (canonical, ver)

        return None

    @staticmethod
    def _cvss_to_severity(score) -> Severity:
        """Map CVSS score to Severity enum."""
        if score is None:
            return Severity.MEDIUM
        if score >= 9.0:
            return Severity.CRITICAL
        if score >= 7.0:
            return Severity.HIGH
        if score >= 4.0:
            return Severity.MEDIUM
        return Severity.LOW
