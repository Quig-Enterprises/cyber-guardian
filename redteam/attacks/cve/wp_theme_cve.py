"""WordPress theme CVE lookup attack module."""

import re
import time
import logging

from redteam.base import Attack, AttackResult, Severity, Status
from redteam.cve.engine import CVEEngine
from redteam.cve.models import CVEQuery

logger = logging.getLogger(__name__)

# Match theme slug from stylesheet link: /wp-content/themes/{slug}/style.css
THEME_SLUG_RE = re.compile(
    r"wp-content/themes/([\w-]+)/", re.IGNORECASE,
)
# Match "Version:" line in style.css header
THEME_VERSION_RE = re.compile(
    r"^\s*Version:\s*([\d.]+)", re.IGNORECASE | re.MULTILINE,
)


class WPThemeCVEAttack(Attack):
    """Known CVE lookup for active WordPress theme."""

    name = "cve.wp_theme_cve"
    category = "cve"
    severity = Severity.MEDIUM
    description = "Known CVE lookup for active WordPress theme"
    target_types = {"wordpress"}

    async def execute(self, client) -> list[AttackResult]:
        results: list[AttackResult] = []
        start = time.monotonic()

        # Step 1: Detect active theme slug from homepage
        slug = await self._detect_theme_slug(client)

        if not slug:
            results.append(self._make_result(
                variant="wp_theme/detection",
                status=Status.ERROR,
                details="Could not detect active WordPress theme from homepage "
                        "stylesheet links.",
                duration_ms=(time.monotonic() - start) * 1000,
            ))
            return results

        # Step 2: Detect theme version from style.css
        version = await self._detect_theme_version(client, slug)

        if not version:
            results.append(self._make_result(
                variant=f"{slug}/detection",
                status=Status.ERROR,
                details=f"Could not detect version for theme '{slug}' "
                        f"from style.css Version header.",
                duration_ms=(time.monotonic() - start) * 1000,
            ))
            return results

        # Step 3: Query the CVE engine
        try:
            engine = CVEEngine(self._config)
            query = CVEQuery(
                software=slug,
                version=version,
                ecosystem="wordpress-theme",
            )
            cves = await engine.lookup(query)
        except Exception as exc:
            logger.error("CVE lookup failed for theme %s/%s: %s", slug, version, exc)
            results.append(self._make_result(
                variant=f"{slug}/engine_error",
                status=Status.ERROR,
                details=f"CVE engine error for theme {slug} {version}: {exc}",
                duration_ms=(time.monotonic() - start) * 1000,
            ))
            return results

        if not cves:
            results.append(self._make_result(
                variant=f"{slug}/no_cves",
                status=Status.DEFENDED,
                evidence=f"No known CVEs for theme {slug} {version}",
                details=f"Theme '{slug}' version {version} has no known CVEs.",
                duration_ms=(time.monotonic() - start) * 1000,
            ))
            return results

        for cve in cves:
            # Store finding in shared state for verification
            if hasattr(self, '_state'):
                self._state.store_cve_finding(f"wp-theme-{slug}", version, cve)

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
            vuln_type = f" ({cve.wp_vuln_type})" if cve.wp_vuln_type else ""

            results.append(self._make_result(
                variant=f"{slug}/{cve.cve_id}",
                status=status_val,
                severity=sev,
                evidence=(
                    f"{cve.cve_id} (CVSS {cve.cvss_v31_score or 'N/A'}, "
                    f"risk {risk:.1f}){kev_info}{vuln_type}"
                ),
                details=(
                    f"Theme {slug} {version}: {cve.description[:300]}"
                    f"{' Fixed in: ' + (cve.wp_fixed_in or cve.fixed_version) if (cve.wp_fixed_in or cve.fixed_version) else ''}"
                    f"{exploit_info}"
                ),
                duration_ms=(time.monotonic() - start) * 1000,
            ))

        return results

    async def _detect_theme_slug(self, client) -> str:
        """Detect active theme slug from homepage stylesheet links."""
        try:
            status, body, _ = await client.get("/", cookies={})
            if status == 200:
                matches = THEME_SLUG_RE.findall(body)
                if matches:
                    # Return the most common theme slug (usually the active one)
                    from collections import Counter
                    counts = Counter(matches)
                    return counts.most_common(1)[0][0]
        except Exception:
            pass
        return ""

    async def _detect_theme_version(self, client, slug: str) -> str:
        """Detect theme version from style.css Version header."""
        content_path = self._config.get("target", {}).get(
            "wordpress", {}
        ).get("content_path", "/wp-content")

        path = f"{content_path}/themes/{slug}/style.css"
        try:
            status, body, _ = await client.get(path, cookies={})
            if status == 200:
                match = THEME_VERSION_RE.search(body[:2000])
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
