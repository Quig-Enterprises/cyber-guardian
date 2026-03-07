"""WordPress plugin CVE lookup attack module."""

import re
import time
import logging

from redteam.base import Attack, AttackResult, Severity, Status
from redteam.cve.engine import CVEEngine

logger = logging.getLogger(__name__)

STABLE_TAG_RE = re.compile(r"Stable\s+tag:\s*([\d.]+)", re.IGNORECASE)


class WPPluginCVEAttack(Attack):
    """Known CVE lookup for installed WordPress plugins."""

    name = "cve.wp_plugin_cve"
    category = "cve"
    severity = Severity.HIGH
    description = "Known CVE lookup for installed WordPress plugins"
    target_types = {"wordpress"}

    async def execute(self, client) -> list[AttackResult]:
        results: list[AttackResult] = []

        # Get configured plugin slugs
        wp_config = self._config.get("target", {}).get("wordpress", {})
        plugins = wp_config.get("plugins", [])

        if not plugins:
            results.append(self._make_result(
                variant="wp_plugins/no_plugins",
                status=Status.SKIPPED,
                details="No WordPress plugins configured in target.wordpress.plugins. "
                        "Use --plugin <slug> to specify plugins to audit.",
            ))
            return results

        engine = CVEEngine(self._config)

        for slug in plugins:
            start = time.monotonic()

            # Detect plugin version
            version = await self._detect_plugin_version(client, slug)

            if not version:
                results.append(self._make_result(
                    variant=f"{slug}/detection",
                    status=Status.ERROR,
                    details=f"Could not detect version for plugin '{slug}' "
                            f"via readme.txt Stable tag.",
                    duration_ms=(time.monotonic() - start) * 1000,
                ))
                continue

            # Query CVE engine
            try:
                cves = await engine.lookup_wordpress_plugin(slug, version)
            except Exception as exc:
                logger.error("CVE lookup failed for plugin %s/%s: %s", slug, version, exc)
                results.append(self._make_result(
                    variant=f"{slug}/engine_error",
                    status=Status.ERROR,
                    details=f"CVE engine error for {slug} {version}: {exc}",
                    duration_ms=(time.monotonic() - start) * 1000,
                ))
                continue

            if not cves:
                results.append(self._make_result(
                    variant=f"{slug}/no_cves",
                    status=Status.DEFENDED,
                    evidence=f"No known CVEs for {slug} {version}",
                    details=f"Plugin '{slug}' version {version} has no known CVEs.",
                    duration_ms=(time.monotonic() - start) * 1000,
                ))
                continue

            for cve in cves:
                # Store finding in shared state for verification
                if hasattr(self, '_state'):
                    self._state.store_cve_finding(f"wp-plugin-{slug}", version, cve)

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
                fixed_info = ""
                if cve.wp_fixed_in:
                    fixed_info = f" Fixed in: {cve.wp_fixed_in}"
                elif cve.fixed_version:
                    fixed_info = f" Fixed in: {cve.fixed_version}"
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
                        f"{slug} {version}: {cve.description[:300]}"
                        f"{fixed_info}{exploit_info}"
                    ),
                    duration_ms=(time.monotonic() - start) * 1000,
                ))

        return results

    async def _detect_plugin_version(self, client, slug: str) -> str:
        """Detect plugin version via readme.txt Stable tag."""
        content_path = self._config.get("target", {}).get(
            "wordpress", {}
        ).get("content_path", "/wp-content")

        path = f"{content_path}/plugins/{slug}/readme.txt"
        try:
            status, body, _ = await client.get(path, cookies={})
            if status == 200:
                match = STABLE_TAG_RE.search(body)
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
