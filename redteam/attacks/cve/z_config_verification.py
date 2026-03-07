"""CVE configuration verification attack module.

This module performs "second-pass" verification of CVEs flagged by other
CVE attack modules. It checks actual configuration files to determine if
the vulnerable configuration pattern is present, reducing false positives.
"""

import logging
import time

from redteam.base import Attack, AttackResult, Severity, Status
from redteam.cve.verifiers import NginxCVEVerifier, PHPCVEVerifier

logger = logging.getLogger(__name__)


class ConfigVerificationAttack(Attack):
    """Verifies if flagged CVEs have vulnerable configurations."""

    name = "cve.config_verification"
    category = "cve"
    severity = Severity.HIGH
    description = "Verifies if flagged CVEs have vulnerable configurations"
    target_types = {"generic", "wordpress", "app"}

    def __init__(self):
        super().__init__()
        self._verifiers = []

    async def execute(self, client) -> list[AttackResult]:
        """Execute configuration verification for flagged CVEs.

        This attack reads CVE findings from shared state (populated by other
        CVE attacks) and attempts to verify if the vulnerable configuration
        is actually present.

        Returns:
            List of AttackResult with verification findings
        """
        results: list[AttackResult] = []
        start = time.monotonic()

        # Check if verification is enabled
        if not self._is_verification_enabled():
            results.append(self._make_result(
                variant="config_verification/disabled",
                status=Status.SKIPPED,
                evidence="CVE configuration verification is disabled in config",
                duration_ms=(time.monotonic() - start) * 1000,
            ))
            return results

        # Initialize verifiers
        self._verifiers = [
            NginxCVEVerifier(self._config),
            PHPCVEVerifier(self._config),
        ]

        # Get CVE findings from shared state
        if not hasattr(self, '_state'):
            results.append(self._make_result(
                variant="config_verification/no_state",
                status=Status.SKIPPED,
                evidence="No shared state available (no CVEs to verify)",
                details="Run other CVE attacks first to populate findings",
                duration_ms=(time.monotonic() - start) * 1000,
            ))
            return results

        cve_findings = self._state.get_cve_findings()

        if not cve_findings:
            results.append(self._make_result(
                variant="config_verification/no_findings",
                status=Status.DEFENDED,
                severity=Severity.INFO,
                evidence="No CVEs found by previous attacks",
                details="Configuration verification skipped (no CVEs to verify)",
                duration_ms=(time.monotonic() - start) * 1000,
            ))
            return results

        logger.info(f"Verifying {len(cve_findings)} CVE findings")

        # Group findings by CVE ID to avoid duplicate verification
        unique_cves = {}
        for software, version, finding in cve_findings:
            cve_id = finding.cve_id
            if cve_id not in unique_cves:
                unique_cves[cve_id] = (software, version, finding)

        # Verify each unique CVE
        verified_count = 0
        for cve_id, (software, version, finding) in unique_cves.items():
            verify_start = time.monotonic()

            # Find appropriate verifier
            verifier = self._find_verifier(cve_id)
            if not verifier:
                # No verifier available for this CVE
                results.append(self._make_result(
                    variant=f"config_verification/{software}/{cve_id}/no_verifier",
                    status=Status.PARTIAL,
                    severity=Severity.INFO,
                    evidence=f"[UNVERIFIED] {cve_id} - No configuration verifier available",
                    details=f"{software} {version}: {finding.description[:200]}",
                    duration_ms=(time.monotonic() - verify_start) * 1000,
                ))
                continue

            # Perform verification
            try:
                verification = await verifier.verify(client, cve_id, software, version)
                verified_count += 1

                # Convert verification result to AttackResult
                if verification.confidence == "none":
                    # Could not verify
                    status_val = Status.PARTIAL
                    sev = Severity.INFO
                elif verification.verified_vulnerable:
                    # Confirmed vulnerable
                    status_val = Status.VULNERABLE
                    sev = self._cvss_to_severity(finding.cvss_score)
                elif verification.verified_defended:
                    # Confirmed defended
                    status_val = Status.DEFENDED
                    sev = Severity.INFO
                else:
                    # Inconclusive
                    status_val = Status.PARTIAL
                    sev = Severity.LOW

                results.append(self._make_result(
                    variant=f"config_verification/{software}/{cve_id}",
                    status=status_val,
                    severity=sev,
                    evidence=f"{verification.evidence} (confidence: {verification.confidence})",
                    details=(
                        f"{software} {version}: {finding.description[:200]}\n"
                        f"Config source: {verification.config_source}\n"
                        f"Risk score: {finding.risk_score:.1f}"
                    ),
                    duration_ms=(time.monotonic() - verify_start) * 1000,
                ))

            except Exception as exc:
                logger.error(f"Error verifying {cve_id}: {exc}")
                results.append(self._make_result(
                    variant=f"config_verification/{software}/{cve_id}/error",
                    status=Status.ERROR,
                    evidence=f"Verification error: {exc}",
                    details=f"{software} {version}: {finding.description[:200]}",
                    duration_ms=(time.monotonic() - verify_start) * 1000,
                ))

        # Summary result
        if verified_count > 0:
            results.append(self._make_result(
                variant="config_verification/summary",
                status=Status.DEFENDED,
                severity=Severity.INFO,
                evidence=f"Verified {verified_count} of {len(unique_cves)} unique CVEs",
                details=f"Configuration verification completed for {verified_count} CVEs",
                duration_ms=(time.monotonic() - start) * 1000,
            ))

        return results

    def _is_verification_enabled(self) -> bool:
        """Check if CVE verification is enabled in config."""
        return self._config.get("cve", {}).get("verification", {}).get("enabled", True)

    def _find_verifier(self, cve_id: str):
        """Find a verifier that can verify the given CVE.

        Args:
            cve_id: CVE identifier

        Returns:
            CVEVerifier instance or None
        """
        for verifier in self._verifiers:
            if verifier.can_verify(cve_id):
                return verifier
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
