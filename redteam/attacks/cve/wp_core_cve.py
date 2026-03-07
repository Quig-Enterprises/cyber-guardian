"""WordPress core CVE lookup attack module."""

import re
import time
import logging

from redteam.base import Attack, AttackResult, Severity, Status
from redteam.cve.engine import CVEEngine

logger = logging.getLogger(__name__)

VERSION_README_RE = re.compile(r"Version\s+([\d.]+)", re.IGNORECASE)
GENERATOR_META_RE = re.compile(
    r'<meta\s+name=["\']generator["\']\s+content=["\']WordPress\s+([\d.]+)["\']',
    re.IGNORECASE,
)
FEED_GENERATOR_RE = re.compile(
    r"<generator>https?://wordpress\.org/\?v=([\d.]+)</generator>",
    re.IGNORECASE,
)


class WPCoreCVEAttack(Attack):
    """Known CVE lookup for WordPress core version."""

    name = "cve.wp_core_cve"
    category = "cve"
    severity = Severity.HIGH
    description = "Known CVE lookup for WordPress core version"
    target_types = {"wordpress"}

    async def execute(self, client) -> list[AttackResult]:
        results: list[AttackResult] = []
        start = time.monotonic()

        # Detect WordPress version using multiple methods
        version = await self._detect_wp_version(client)

        if not version:
            results.append(self._make_result(
                variant="wp_core/detection",
                status=Status.ERROR,
                details="Could not detect WordPress core version via readme.html, "
                        "generator meta tag, or RSS feed.",
                duration_ms=(time.monotonic() - start) * 1000,
            ))
            return results

        # Query the CVE engine
        try:
            engine = CVEEngine(self._config)
            cves = await engine.lookup_wordpress_core(version)
        except Exception as exc:
            logger.error("CVE engine lookup failed for WordPress %s: %s", version, exc)
            results.append(self._make_result(
                variant="wp_core/engine_error",
                status=Status.ERROR,
                details=f"CVE engine error for WordPress {version}: {exc}",
                duration_ms=(time.monotonic() - start) * 1000,
            ))
            return results

        if not cves:
            results.append(self._make_result(
                variant="wp_core/no_cves",
                status=Status.DEFENDED,
                evidence=f"No known CVEs found for WordPress {version}",
                details=f"WordPress core version {version} has no known CVEs "
                        f"in the configured data sources.",
                duration_ms=(time.monotonic() - start) * 1000,
            ))
            return results

        # Each CVE becomes an AttackResult
        for cve in cves:
            risk = cve.risk_score
            if risk >= 4.0:
                status = Status.VULNERABLE
            else:
                status = Status.PARTIAL

            sev = self._cvss_to_severity(cve.cvss_v31_score)
            exploit_info = ""
            if cve.exploit_refs:
                exploit_info = f" Exploits: {', '.join(r.url for r in cve.exploit_refs[:3])}"
            kev_info = " [CISA KEV]" if cve.in_kev else ""

            results.append(self._make_result(
                variant=f"wp_core/{cve.cve_id}",
                status=status,
                severity=sev,
                evidence=(
                    f"{cve.cve_id} (CVSS {cve.cvss_v31_score or 'N/A'}, "
                    f"risk {risk:.1f}){kev_info}"
                ),
                details=(
                    f"WordPress {version}: {cve.description[:300]}"
                    f"{' Fixed in: ' + cve.fixed_version if cve.fixed_version else ''}"
                    f"{exploit_info}"
                ),
                duration_ms=(time.monotonic() - start) * 1000,
            ))

        return results

    async def _detect_wp_version(self, client) -> str:
        """Try multiple methods to detect WordPress version."""
        # Method 1: readme.html
        try:
            status, body, _ = await client.get("/readme.html", cookies={})
            if status == 200:
                match = VERSION_README_RE.search(body)
                if match:
                    return match.group(1)
        except Exception:
            pass

        # Method 2: RSS feed generator tag
        try:
            status, body, _ = await client.get("/feed/", cookies={})
            if status == 200:
                match = FEED_GENERATOR_RE.search(body)
                if match:
                    return match.group(1)
        except Exception:
            pass

        # Method 3: homepage generator meta tag
        try:
            status, body, _ = await client.get("/", cookies={})
            if status == 200:
                match = GENERATOR_META_RE.search(body)
                if match:
                    return match.group(1)
        except Exception:
            pass

        return ""

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
