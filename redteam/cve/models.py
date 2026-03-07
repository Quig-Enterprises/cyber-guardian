"""Data models for the CVE lookup engine."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class ExploitMaturity(str, Enum):
    POC = "poc"
    FUNCTIONAL = "functional"
    WEAPONIZED = "weaponized"
    NONE = "none"


@dataclass
class ExploitRef:
    """Reference to a known exploit for a CVE."""

    source: str  # "exploitdb", "github", "metasploit", "vulners"
    url: str
    description: str = ""


@dataclass
class CVERecord:
    """A single CVE vulnerability record with merged data from all sources."""

    cve_id: str
    description: str = ""
    cvss_v31_score: Optional[float] = None
    cvss_v31_vector: str = ""
    cvss_v40_score: Optional[float] = None
    severity: str = "unknown"  # critical/high/medium/low/unknown
    published: str = ""
    modified: str = ""
    cpe_matches: list[str] = field(default_factory=list)
    affected_versions: str = ""  # "< 3.2.1"
    fixed_version: str = ""
    in_kev: bool = False
    kev_due_date: str = ""
    exploit_maturity: ExploitMaturity = ExploitMaturity.NONE
    exploit_refs: list[ExploitRef] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    wp_vuln_type: str = ""
    wp_fixed_in: str = ""

    @property
    def risk_score(self) -> float:
        """Calculate risk score: CVSS + exploit bonus + KEV bonus, capped at 10.0."""
        base = self.cvss_v31_score or self.cvss_v40_score or 5.0
        exploit_bonus = {
            ExploitMaturity.WEAPONIZED: 2.0,
            ExploitMaturity.FUNCTIONAL: 1.5,
            ExploitMaturity.POC: 0.5,
            ExploitMaturity.NONE: 0.0,
        }.get(self.exploit_maturity, 0.0)
        kev_bonus = 2.0 if self.in_kev else 0.0
        return min(10.0, base + exploit_bonus + kev_bonus)


@dataclass
class CVEQuery:
    """Query parameters for CVE lookup."""

    software: str
    version: str = ""
    ecosystem: str = ""  # "wordpress-plugin", "wordpress-core", "npm", "pypi", "generic"
    cpe: str = ""
    vendor: str = ""
    max_results: int = 50
    min_cvss: float = 0.0
    include_rejected: bool = False
