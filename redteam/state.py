"""Shared state for cross-attack communication during scans."""

from dataclasses import dataclass
from threading import Lock
from typing import Any


@dataclass
class CVEFinding:
    """Represents a CVE found by a CVE attack module."""
    software: str
    version: str
    cve_id: str
    cvss_score: float | None
    risk_score: float
    description: str
    fixed_version: str | None
    exploit_refs: list[Any]
    in_kev: bool


class ScanState:
    """Thread-safe shared state for attack results.

    Allows attacks to register findings that can be verified by later attacks.
    """

    def __init__(self):
        self._lock = Lock()
        self._cve_findings: list[tuple[str, str, CVEFinding]] = []
        self._software_detected: dict[str, str] = {}  # {software: version}

    def store_cve_finding(self, software: str, version: str, cve_record: Any) -> None:
        """Called by CVE attack modules to register findings.

        Args:
            software: Software name (e.g., "nginx", "php")
            version: Version string (e.g., "1.24.0")
            cve_record: CVERecord object from CVE engine
        """
        with self._lock:
            finding = CVEFinding(
                software=software,
                version=version,
                cve_id=cve_record.cve_id,
                cvss_score=cve_record.cvss_v31_score,
                risk_score=cve_record.risk_score,
                description=cve_record.description,
                fixed_version=cve_record.fixed_version,
                exploit_refs=cve_record.exploit_refs,
                in_kev=cve_record.in_kev,
            )
            self._cve_findings.append((software, version, finding))

    def get_cve_findings(self) -> list[tuple[str, str, CVEFinding]]:
        """Returns all CVE findings for verification.

        Returns:
            List of (software, version, CVEFinding) tuples
        """
        with self._lock:
            return self._cve_findings.copy()

    def store_software_version(self, software: str, version: str) -> None:
        """Register detected software for later verification.

        Args:
            software: Software name
            version: Version string
        """
        with self._lock:
            self._software_detected[software] = version

    def get_software_version(self, software: str) -> str | None:
        """Get version of detected software.

        Args:
            software: Software name

        Returns:
            Version string or None if not detected
        """
        with self._lock:
            return self._software_detected.get(software)

    def get_all_software(self) -> dict[str, str]:
        """Get all detected software and versions.

        Returns:
            Dictionary of {software: version}
        """
        with self._lock:
            return self._software_detected.copy()
