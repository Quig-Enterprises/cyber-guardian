"""WordPress plugin enumeration attacks — MEDIUM severity.

Probes for installed plugins by checking for readme.txt files and known
directory structures. Enumerates plugin names and versions, and tests
for directory listing on plugin directories.
"""

import asyncio
import re
import time
import logging

from redteam.base import Attack, AttackResult, Severity, Status

logger = logging.getLogger(__name__)

TOP_PLUGIN_SLUGS = [
    "akismet",
    "contact-form-7",
    "woocommerce",
    "jetpack",
    "yoast-seo",
    "wordfence",
    "elementor",
    "classic-editor",
    "wpforms-lite",
    "all-in-one-seo-pack",
    "really-simple-ssl",
    "updraftplus",
    "wp-super-cache",
    "w3-total-cache",
    "redirection",
    "sucuri-scanner",
    "limit-login-attempts-reloaded",
    "loginizer",
    "google-analytics-for-wordpress",
    "wp-mail-smtp",
    "duplicator",
    "litespeed-cache",
    "tablepress",
    "advanced-custom-fields",
    "wordpress-importer",
    "regenerate-thumbnails",
    "wp-migrate-db",
    "query-monitor",
    "debug-bar",
    "user-role-editor",
]

VERSION_RE = re.compile(r"Stable tag:\s*([^\s\n]+)", re.IGNORECASE)


class PluginEnumerationAttack(Attack):
    """Enumerate installed WordPress plugins via readme.txt probing."""

    name = "wordpress.plugin_enumeration"
    category = "wordpress"
    severity = Severity.MEDIUM
    description = "Enumerate installed plugins and versions via readme.txt probing"
    target_types = {"wordpress"}

    async def execute(self, client) -> list[AttackResult]:
        results = []

        # Phase 1: Probe top plugins for readme.txt
        found_plugins = await self._probe_top_plugins(client, results)

        # Phase 2: Check directory listing on found plugins
        await self._check_directory_listing(client, found_plugins, results)

        # Phase 3: Summary result
        results.append(self._build_summary(found_plugins))

        return results

    async def _probe_top_plugins(self, client, results: list) -> dict[str, str]:
        """Check each plugin slug for readme.txt. Returns {slug: version}."""
        throttle = self._get_throttle("wordpress.plugin_enumeration")
        max_plugins = throttle.get("max_plugins", 30)
        delay_ms = throttle.get("delay_ms", 0)

        slugs = TOP_PLUGIN_SLUGS[:max_plugins]
        found: dict[str, str] = {}

        for slug in slugs:
            path = f"{client.content_path}/plugins/{slug}/readme.txt"
            start = time.monotonic()
            try:
                status, body, headers = await client.get(path, cookies={})
                duration = (time.monotonic() - start) * 1000

                if status == 200 and len(body) > 50:
                    # Extract version from "Stable tag:" line
                    version = "unknown"
                    match = VERSION_RE.search(body)
                    if match:
                        version = match.group(1)

                    found[slug] = version
                    results.append(self._make_result(
                        variant="top_plugins_probe",
                        status=Status.VULNERABLE,
                        severity=Severity.INFO,
                        evidence=f"Plugin '{slug}' found, version: {version}",
                        details=(
                            f"readme.txt accessible at {path}. "
                            f"Plugin: {slug}, Version: {version}. "
                            f"Plugin enumeration reveals installed software for targeted attacks."
                        ),
                        request={"method": "GET", "path": path},
                        response={"status": status, "body": body[:300]},
                        duration_ms=duration,
                    ))
                else:
                    results.append(self._make_result(
                        variant="top_plugins_probe",
                        status=Status.DEFENDED,
                        evidence=f"Plugin '{slug}' not found (HTTP {status})",
                        details=f"readme.txt at {path} returned HTTP {status}.",
                        request={"method": "GET", "path": path},
                        response={"status": status},
                        duration_ms=duration,
                    ))
            except Exception as e:
                results.append(self._make_result(
                    variant="top_plugins_probe",
                    status=Status.ERROR,
                    details=f"Error probing plugin '{slug}': {e}",
                    duration_ms=(time.monotonic() - start) * 1000,
                ))

            if delay_ms > 0:
                await asyncio.sleep(delay_ms / 1000.0)

        return found

    async def _check_directory_listing(self, client, found_plugins: dict, results: list) -> None:
        """Check if directory listing is enabled for each found plugin."""
        for slug in found_plugins:
            path = f"{client.content_path}/plugins/{slug}/"
            start = time.monotonic()
            try:
                status, body, headers = await client.get(path, cookies={})
                duration = (time.monotonic() - start) * 1000

                if status == 200 and "Index of" in body:
                    results.append(self._make_result(
                        variant="directory_listing",
                        status=Status.VULNERABLE,
                        severity=Severity.MEDIUM,
                        evidence=f"Directory listing enabled for plugin '{slug}'",
                        details=(
                            f"GET {path} returned directory listing (HTTP {status}). "
                            f"Attackers can enumerate all plugin files to find vulnerable "
                            f"scripts or configuration files."
                        ),
                        request={"method": "GET", "path": path},
                        response={"status": status, "body": body[:300]},
                        duration_ms=duration,
                    ))
                else:
                    results.append(self._make_result(
                        variant="directory_listing",
                        status=Status.DEFENDED,
                        evidence=f"No directory listing for plugin '{slug}' (HTTP {status})",
                        details=f"Plugin directory {path} does not expose directory listing.",
                        request={"method": "GET", "path": path},
                        response={"status": status},
                        duration_ms=duration,
                    ))
            except Exception as e:
                results.append(self._make_result(
                    variant="directory_listing",
                    status=Status.ERROR,
                    details=f"Error checking directory listing for '{slug}': {e}",
                    duration_ms=(time.monotonic() - start) * 1000,
                ))

    def _build_summary(self, found_plugins: dict) -> AttackResult:
        """Aggregate result summarizing all found plugins."""
        count = len(found_plugins)
        if count > 0:
            listing = ", ".join(
                f"{slug} ({ver})" for slug, ver in found_plugins.items()
            )
            return self._make_result(
                variant="plugin_summary",
                status=Status.VULNERABLE,
                severity=Severity.INFO,
                evidence=f"{count} plugin(s) discovered: {listing}",
                details=(
                    f"Enumerated {count} installed plugin(s) via readme.txt probing. "
                    f"Plugins: {listing}. "
                    f"This constitutes information disclosure that aids targeted attacks."
                ),
            )
        return self._make_result(
            variant="plugin_summary",
            status=Status.DEFENDED,
            evidence="No plugins discovered via readme.txt probing",
            details="None of the top plugin slugs returned a valid readme.txt.",
        )
