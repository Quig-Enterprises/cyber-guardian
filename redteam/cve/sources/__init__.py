"""CVE data source adapters."""

from redteam.cve.sources.base import AsyncCVESource, SourceResult
from redteam.cve.sources.kev import KEVSource
from redteam.cve.sources.exploitdb import ExploitDBSource
from redteam.cve.sources.cvelistv5 import CVEListV5Source
from redteam.cve.sources.nvd import NVDSource
from redteam.cve.sources.wpvulndb import WPVulnerabilitySource
from redteam.cve.sources.osv import OSVSource
from redteam.cve.sources.wpscan import WPScanSource
from redteam.cve.sources.vulners_source import VulnersSource
from redteam.cve.sources.github_advisory import GitHubAdvisorySource
from redteam.cve.sources.deps_dev import DepsDevSource

ALL_SOURCES: list[type[AsyncCVESource]] = [
    # Local sources (always available if synced)
    CVEListV5Source,
    KEVSource,
    ExploitDBSource,
    # Remote sources (free, no auth)
    WPVulnerabilitySource,
    OSVSource,
    DepsDevSource,
    # Remote sources (require API key)
    NVDSource,
    WPScanSource,
    VulnersSource,
    GitHubAdvisorySource,
]

__all__ = [
    "AsyncCVESource",
    "SourceResult",
    "KEVSource",
    "ExploitDBSource",
    "CVEListV5Source",
    "NVDSource",
    "WPVulnerabilitySource",
    "OSVSource",
    "WPScanSource",
    "VulnersSource",
    "GitHubAdvisorySource",
    "DepsDevSource",
    "ALL_SOURCES",
]
