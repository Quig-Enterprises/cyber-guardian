"""Base classes for CVE configuration verifiers."""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any


@dataclass
class VerificationResult:
    """Result of CVE configuration verification.

    Attributes:
        cve_id: CVE identifier (e.g., "CVE-2019-11043")
        verified_vulnerable: True if config IS vulnerable
        verified_defended: True if config has mitigations
        evidence: What was found in config
        config_source: Where config was checked
        confidence: "high"|"medium"|"low"|"none"
    """
    cve_id: str
    verified_vulnerable: bool
    verified_defended: bool
    evidence: str
    config_source: str
    confidence: str  # "high"|"medium"|"low"|"none"

    @property
    def attempted(self) -> bool:
        """Returns True if verification was attempted."""
        return self.confidence != "none"


class CVEVerifier(ABC):
    """Base class for CVE configuration verifiers."""

    def __init__(self, config: dict):
        """Initialize verifier with configuration.

        Args:
            config: Scanner configuration dictionary
        """
        self.config = config
        self.aggressiveness = config.get("cve", {}).get("verification", {}).get("aggressiveness", "low")

    @abstractmethod
    async def verify(self, client: Any, cve_id: str, software: str, version: str) -> VerificationResult:
        """Verify if CVE is actually exploitable based on configuration.

        Args:
            client: RedTeamClient or WordPressClient instance
            cve_id: CVE identifier to verify
            software: Software name (e.g., "nginx")
            version: Version string (e.g., "1.24.0")

        Returns:
            VerificationResult with findings
        """
        ...

    @abstractmethod
    def can_verify(self, cve_id: str) -> bool:
        """Return True if this verifier can verify the given CVE.

        Args:
            cve_id: CVE identifier

        Returns:
            True if verifier has a verification method for this CVE
        """
        ...

    def _is_enabled(self, cve_id: str) -> bool:
        """Check if verification is enabled for specific CVE in config.

        Args:
            cve_id: CVE identifier

        Returns:
            True if verification is enabled
        """
        specific_cves = self.config.get("cve", {}).get("verification", {}).get("specific_cves", {})
        return specific_cves.get(cve_id, True)  # Default: enabled

    def _get_config_endpoints(self, software: str) -> list[str]:
        """Get config endpoint URLs to probe for the given software.

        Args:
            software: Software name (e.g., "nginx", "php")

        Returns:
            List of URL paths to try
        """
        verification_config = self.config.get("cve", {}).get("verification", {})
        endpoints = verification_config.get("config_endpoints", {})
        return endpoints.get(software, [])
