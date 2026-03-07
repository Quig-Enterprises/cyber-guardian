"""Nginx CVE verifier."""

import logging
from typing import Any

from .base import CVEVerifier, VerificationResult
from ..parsers.nginx_parser import NginxConfigParser

logger = logging.getLogger(__name__)


class NginxCVEVerifier(CVEVerifier):
    """Verifies Nginx CVEs by checking configuration files."""

    # CVE ID → verification method mapping
    VERIFIABLE_CVES = {
        "CVE-2019-11043": "_verify_cve_2019_11043",
        "CVE-2013-4547": "_verify_cve_2013_4547",
    }

    def can_verify(self, cve_id: str) -> bool:
        """Return True if this verifier can verify the given CVE."""
        return cve_id in self.VERIFIABLE_CVES and self._is_enabled(cve_id)

    async def verify(self, client: Any, cve_id: str, software: str, version: str) -> VerificationResult:
        """Verify if CVE is actually exploitable based on nginx configuration."""
        if not self.can_verify(cve_id):
            return VerificationResult(
                cve_id=cve_id,
                verified_vulnerable=False,
                verified_defended=False,
                evidence="Verification not available for this CVE",
                config_source="none",
                confidence="none",
            )

        method_name = self.VERIFIABLE_CVES[cve_id]
        method = getattr(self, method_name)
        return await method(client, version)

    async def _verify_cve_2019_11043(self, client: Any, version: str) -> VerificationResult:
        r"""Verify CVE-2019-11043: PHP-FPM Nginx underflow RCE.

        This CVE requires a specific vulnerable nginx configuration pattern:
            location ~ \.php$ {
                fastcgi_split_path_info ^(.+\.php)(/.+)$;
                fastcgi_pass unix:/run/php-fpm.sock;
            }

        The vulnerability is NOT in nginx itself, but in the configuration.
        If this directive is absent, the server is not vulnerable.
        """
        config = await self._fetch_nginx_config(client)

        if not config:
            return VerificationResult(
                cve_id="CVE-2019-11043",
                verified_vulnerable=False,
                verified_defended=False,
                evidence="Cannot access nginx config for verification",
                config_source="none",
                confidence="none",
            )

        parser = NginxConfigParser(config)
        has_vulnerable_pattern = parser.has_vulnerable_fastcgi_split_path_info()

        # Determine source for evidence message
        mode = self.config.get("cve", {}).get("verification", {}).get("mode", "probe")
        source_detail = "filesystem (DEFINITIVE)" if mode in ["blueteam", "both"] and "From:" in config else "HTTP endpoint"

        if has_vulnerable_pattern:
            return VerificationResult(
                cve_id="CVE-2019-11043",
                verified_vulnerable=True,
                verified_defended=False,
                evidence=f"[VERIFIED VULNERABLE - {source_detail}] Vulnerable fastcgi_split_path_info pattern found",
                config_source="nginx.conf",
                confidence="high",
            )
        else:
            # Check if PHP handling is present at all
            if parser.has_fastcgi_config():
                return VerificationResult(
                    cve_id="CVE-2019-11043",
                    verified_vulnerable=False,
                    verified_defended=True,
                    evidence=f"[VERIFIED DEFENDED - {source_detail}] PHP-FPM configured but no vulnerable fastcgi_split_path_info pattern",
                    config_source="nginx.conf",
                    confidence="high",
                )
            else:
                return VerificationResult(
                    cve_id="CVE-2019-11043",
                    verified_vulnerable=False,
                    verified_defended=True,
                    evidence=f"[VERIFIED DEFENDED - {source_detail}] No PHP-FPM configuration found",
                    config_source="nginx.conf",
                    confidence="high",
                )

    async def _verify_cve_2013_4547(self, client: Any, version: str) -> VerificationResult:
        """Verify CVE-2013-4547: Nginx space parsing vulnerability.

        This CVE affects nginx < 1.5.7 when using PHP-FPM with certain
        configurations. Requires specific location block patterns.
        """
        config = await self._fetch_nginx_config(client)

        if not config:
            return VerificationResult(
                cve_id="CVE-2013-4547",
                verified_vulnerable=False,
                verified_defended=False,
                evidence="Cannot access nginx config for verification",
                config_source="none",
                confidence="none",
            )

        # For this CVE, just check if version is patched
        # More sophisticated config checking could be added later
        try:
            ver_parts = version.split('.')
            major = int(ver_parts[0])
            minor = int(ver_parts[1]) if len(ver_parts) > 1 else 0
            patch = int(ver_parts[2]) if len(ver_parts) > 2 else 0

            # Fixed in 1.5.7
            is_patched = (major > 1) or (major == 1 and minor > 5) or (major == 1 and minor == 5 and patch >= 7)

            if is_patched:
                return VerificationResult(
                    cve_id="CVE-2013-4547",
                    verified_vulnerable=False,
                    verified_defended=True,
                    evidence=f"[VERIFIED DEFENDED] Nginx {version} is patched (>= 1.5.7)",
                    config_source="version_check",
                    confidence="high",
                )
            else:
                return VerificationResult(
                    cve_id="CVE-2013-4547",
                    verified_vulnerable=True,
                    verified_defended=False,
                    evidence=f"[VERIFIED VULNERABLE] Nginx {version} is unpatched (< 1.5.7)",
                    config_source="version_check",
                    confidence="medium",
                )
        except (ValueError, IndexError):
            return VerificationResult(
                cve_id="CVE-2013-4547",
                verified_vulnerable=False,
                verified_defended=False,
                evidence=f"Cannot parse version: {version}",
                config_source="none",
                confidence="none",
            )

    async def _fetch_nginx_config(self, client: Any) -> str | None:
        """Attempt to fetch nginx configuration file.

        Tries multiple methods based on mode setting:
        1. Blue team config provider (reads actual filesystem) - DEFINITIVE
        2. HTTP endpoint probing (exposed configs) - PARTIAL
        3. Directory traversal probes (high aggressiveness) - RISKY

        Returns:
            Config file contents or None if inaccessible
        """
        # Method 1: Try blue team config provider first (DEFINITIVE)
        mode = self.config.get("cve", {}).get("verification", {}).get("mode", "probe")
        logger.info(f"Config verification mode: {mode}")

        if mode in ["blueteam", "both"]:
            logger.info("Attempting to fetch nginx config from blue team provider...")
            try:
                import sys
                import os
                # Add project root to path if not already there
                project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
                if project_root not in sys.path:
                    sys.path.insert(0, project_root)

                from blueteam.api.config_provider import get_provider
                provider = get_provider()
                config = provider.get_nginx_config()
                if config:
                    logger.info(f"✓ Successfully fetched nginx config from blue team provider (DEFINITIVE) - {len(config)} bytes")
                    return config
                else:
                    logger.warning("Blue team provider returned None")
            except ImportError as e:
                logger.warning(f"Blue team config provider not available: {e}")
            except Exception as e:
                logger.error(f"Error fetching from blue team provider: {e}")
                import traceback
                logger.error(traceback.format_exc())

        # Method 2: Fall back to HTTP probing
        if mode in ["probe", "both"]:
            return await self._fetch_via_http_probe(client)

        return None

    async def _fetch_via_http_probe(self, client: Any) -> str | None:
        """Fetch nginx config via HTTP endpoint probing.

        Returns:
            Config file contents or None if inaccessible
        """
        endpoints = self._get_config_endpoints("nginx")

        if not endpoints:
            # Default endpoints based on aggressiveness
            if self.aggressiveness == "low":
                endpoints = [
                    "/admin/nginx/config",
                    "/admin/config",
                ]
            elif self.aggressiveness == "medium":
                endpoints = [
                    "/admin/nginx/config",
                    "/admin/config",
                    "/nginx.conf",
                    "/.nginx.conf",
                ]
            else:  # high
                endpoints = [
                    "/admin/nginx/config",
                    "/admin/config",
                    "/nginx.conf",
                    "/.nginx.conf",
                    "/../etc/nginx/nginx.conf",
                    "/etc/nginx/nginx.conf",
                ]

        for endpoint in endpoints:
            try:
                status, body, headers = await client.get(endpoint, cookies={})
                if status == 200 and body:
                    # Check if it looks like nginx config
                    if "server {" in body or "location" in body or "fastcgi" in body:
                        logger.info(f"Successfully fetched nginx config from {endpoint}")
                        return body
            except Exception as exc:
                logger.debug(f"Failed to fetch nginx config from {endpoint}: {exc}")
                continue

        logger.info("Could not fetch nginx config from any known endpoint")
        return None
