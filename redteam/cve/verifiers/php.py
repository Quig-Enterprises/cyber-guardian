"""PHP CVE verifier."""

import logging
import re
from typing import Any

from .base import CVEVerifier, VerificationResult

logger = logging.getLogger(__name__)


class PHPCVEVerifier(CVEVerifier):
    """Verifies PHP CVEs by checking configuration and runtime environment."""

    # CVE ID → verification method mapping
    VERIFIABLE_CVES = {
        "CVE-2024-4577": "_verify_cve_2024_4577",
        "CVE-2016-10033": "_verify_cve_2016_10033",
    }

    def can_verify(self, cve_id: str) -> bool:
        """Return True if this verifier can verify the given CVE."""
        return cve_id in self.VERIFIABLE_CVES and self._is_enabled(cve_id)

    async def verify(self, client: Any, cve_id: str, software: str, version: str) -> VerificationResult:
        """Verify if CVE is actually exploitable based on PHP configuration."""
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

    async def _verify_cve_2024_4577(self, client: Any, version: str) -> VerificationResult:
        """Verify CVE-2024-4577: PHP Windows CGI argument injection.

        This CVE only affects PHP running in CGI mode on Windows.
        If not Windows or not CGI, the server is not vulnerable.
        """
        # Check server headers for Windows indicators
        try:
            status, body, headers = await client.get("/", cookies={})
            server_header = headers.get("Server", "") or headers.get("server", "")

            # Check if this is Windows
            is_windows = any(
                indicator in server_header.lower()
                for indicator in ["win32", "windows", "microsoft", "iis"]
            )

            if not is_windows:
                return VerificationResult(
                    cve_id="CVE-2024-4577",
                    verified_vulnerable=False,
                    verified_defended=True,
                    evidence="[VERIFIED DEFENDED] Not running on Windows (CVE-2024-4577 is Windows-only)",
                    config_source="server_header",
                    confidence="high",
                )

            # If Windows, check for CGI mode indicators
            phpinfo = await self._fetch_phpinfo(client)
            if phpinfo:
                if "cgi" in phpinfo.lower() and "sapi" in phpinfo.lower():
                    return VerificationResult(
                        cve_id="CVE-2024-4577",
                        verified_vulnerable=True,
                        verified_defended=False,
                        evidence="[VERIFIED VULNERABLE] PHP running in CGI mode on Windows",
                        config_source="phpinfo",
                        confidence="high",
                    )
                else:
                    return VerificationResult(
                        cve_id="CVE-2024-4577",
                        verified_vulnerable=False,
                        verified_defended=True,
                        evidence="[VERIFIED DEFENDED] PHP not running in CGI mode",
                        config_source="phpinfo",
                        confidence="high",
                    )

            # Can't verify without phpinfo
            return VerificationResult(
                cve_id="CVE-2024-4577",
                verified_vulnerable=False,
                verified_defended=False,
                evidence="Windows detected but cannot verify CGI mode without phpinfo access",
                config_source="server_header",
                confidence="low",
            )

        except Exception as exc:
            logger.error(f"Error verifying CVE-2024-4577: {exc}")
            return VerificationResult(
                cve_id="CVE-2024-4577",
                verified_vulnerable=False,
                verified_defended=False,
                evidence=f"Verification error: {exc}",
                config_source="none",
                confidence="none",
            )

    async def _verify_cve_2016_10033(self, client: Any, version: str) -> VerificationResult:
        """Verify CVE-2016-10033: PHPMailer RCE vulnerability.

        This CVE affects PHPMailer < 5.2.18. Need to check if PHPMailer is
        present and what version it is.
        """
        # Try to detect PHPMailer via composer.json
        try:
            status, body, headers = await client.get("/composer.json", cookies={})
            if status == 200 and "phpmailer" in body.lower():
                # Try to extract version
                version_match = re.search(r'"phpmailer/phpmailer":\s*"([^"]+)"', body, re.IGNORECASE)
                if version_match:
                    phpmailer_version = version_match.group(1)
                    return VerificationResult(
                        cve_id="CVE-2016-10033",
                        verified_vulnerable=True,
                        verified_defended=False,
                        evidence=f"[UNVERIFIED] PHPMailer detected (version constraint: {phpmailer_version}). "
                                "Manual verification needed for actual version.",
                        config_source="composer.json",
                        confidence="medium",
                    )
        except Exception:
            pass

        # Try vendor/composer/installed.json (more reliable)
        try:
            status, body, headers = await client.get("/vendor/composer/installed.json", cookies={})
            if status == 200 and "phpmailer" in body.lower():
                # Parse installed version
                version_match = re.search(
                    r'"name":\s*"phpmailer/phpmailer".*?"version":\s*"([^"]+)"',
                    body,
                    re.IGNORECASE | re.DOTALL
                )
                if version_match:
                    phpmailer_version = version_match.group(1)

                    # Check if vulnerable (< 5.2.18)
                    try:
                        ver_parts = phpmailer_version.lstrip('v').split('.')
                        major = int(ver_parts[0])
                        minor = int(ver_parts[1]) if len(ver_parts) > 1 else 0
                        patch = int(ver_parts[2]) if len(ver_parts) > 2 else 0

                        is_vulnerable = (major < 5) or (major == 5 and minor < 2) or (major == 5 and minor == 2 and patch < 18)

                        if is_vulnerable:
                            return VerificationResult(
                                cve_id="CVE-2016-10033",
                                verified_vulnerable=True,
                                verified_defended=False,
                                evidence=f"[VERIFIED VULNERABLE] PHPMailer {phpmailer_version} < 5.2.18",
                                config_source="vendor/composer/installed.json",
                                confidence="high",
                            )
                        else:
                            return VerificationResult(
                                cve_id="CVE-2016-10033",
                                verified_vulnerable=False,
                                verified_defended=True,
                                evidence=f"[VERIFIED DEFENDED] PHPMailer {phpmailer_version} >= 5.2.18 (patched)",
                                config_source="vendor/composer/installed.json",
                                confidence="high",
                            )
                    except (ValueError, IndexError):
                        pass
        except Exception:
            pass

        # PHPMailer not detected or version not accessible
        return VerificationResult(
            cve_id="CVE-2016-10033",
            verified_vulnerable=False,
            verified_defended=False,
            evidence="PHPMailer not detected or version not accessible",
            config_source="none",
            confidence="none",
        )

    async def _fetch_phpinfo(self, client: Any) -> str | None:
        """Attempt to fetch phpinfo() output.

        Returns:
            phpinfo HTML content or None if inaccessible
        """
        endpoints = self._get_config_endpoints("php")

        if not endpoints:
            # Default phpinfo endpoints
            endpoints = [
                "/phpinfo.php",
                "/?phpinfo=1",
                "/admin/phpinfo.php",
                "/info.php",
                "/test.php",
            ]

        for endpoint in endpoints:
            try:
                status, body, headers = await client.get(endpoint, cookies={})
                if status == 200 and "phpinfo()" in body:
                    logger.info(f"Successfully fetched phpinfo from {endpoint}")
                    return body
            except Exception as exc:
                logger.debug(f"Failed to fetch phpinfo from {endpoint}: {exc}")
                continue

        logger.info("Could not fetch phpinfo from any known endpoint")
        return None
