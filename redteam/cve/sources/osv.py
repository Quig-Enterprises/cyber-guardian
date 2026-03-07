"""OSV.dev source adapter (no auth required)."""

import logging
import time
from typing import Optional

import aiohttp

from redteam.cve.models import CVEQuery, CVERecord, ExploitMaturity
from redteam.cve.sources.base import AsyncCVESource, SourceResult

logger = logging.getLogger(__name__)

OSV_API_URL = "https://api.osv.dev/v1/query"

# Mapping from our ecosystem names to OSV ecosystem values
ECOSYSTEM_MAP = {
    "npm": "npm",
    "pypi": "PyPI",
    "go": "Go",
    "cargo": "crates.io",
    "crates": "crates.io",
    "rust": "crates.io",
    "maven": "Maven",
    "java": "Maven",
    "nuget": "NuGet",
    "rubygems": "RubyGems",
    "ruby": "RubyGems",
    "packagist": "Packagist",
    "php": "Packagist",
    "composer": "Packagist",
    "hex": "Hex",
    "pub": "Pub",
    "swift": "SwiftURL",
    "cocoapods": "CocoaPods",
    "linux": "Linux",
    "debian": "Debian",
    "alpine": "Alpine",
}

# Ecosystems that are NOT supported by OSV
UNSUPPORTED_ECOSYSTEMS = {
    "wordpress-plugin",
    "wordpress-theme",
    "wordpress-core",
    "generic",
}


class OSVSource(AsyncCVESource):
    """OSV.dev — open-source vulnerability database.

    Supports batch queries for many open-source ecosystems including
    npm, PyPI, Go, crates.io, Maven, NuGet, RubyGems, Packagist, etc.

    Does NOT support WordPress-specific ecosystems.
    """

    name = "osv"
    requires_auth = False

    def __init__(self, config: dict, rate_limiter=None, cache=None):
        super().__init__(config, rate_limiter, cache)
        self._session: Optional[aiohttp.ClientSession] = None

    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create an aiohttp session."""
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=30)
            )
        return self._session

    def _resolve_ecosystem(self, eco: str) -> Optional[str]:
        """Map our ecosystem name to OSV ecosystem name."""
        if not eco:
            return None
        lower = eco.lower()
        if lower in UNSUPPORTED_ECOSYSTEMS:
            return None
        return ECOSYSTEM_MAP.get(lower)

    def _extract_cve_ids(self, vuln: dict) -> list[str]:
        """Extract CVE IDs from aliases."""
        cve_ids = []
        # The main id might be a CVE
        vuln_id = vuln.get("id", "")
        if vuln_id.startswith("CVE-"):
            cve_ids.append(vuln_id)
        # Check aliases
        for alias in vuln.get("aliases", []):
            if alias.startswith("CVE-") and alias not in cve_ids:
                cve_ids.append(alias)
        return cve_ids

    def _extract_severity(self, vuln: dict) -> tuple[Optional[float], str, str]:
        """Extract CVSS score, severity, and vector from OSV severity data.

        Returns: (score, severity_label, vector_string)
        """
        score = None
        vector = ""
        severity_list = vuln.get("severity", [])
        if isinstance(severity_list, list):
            for sev in severity_list:
                sev_type = sev.get("type", "")
                sev_score = sev.get("score", "")
                if sev_type == "CVSS_V3" and sev_score:
                    vector = sev_score
                    # Parse score from vector if possible
                    # OSV sometimes provides the vector string in score field
                    break

        # Try database_specific for score
        db_specific = vuln.get("database_specific", {})
        if isinstance(db_specific, dict):
            cvss_score = db_specific.get("cvss", {})
            if isinstance(cvss_score, dict):
                s = cvss_score.get("score")
                if s is not None:
                    try:
                        score = float(s)
                    except (ValueError, TypeError):
                        pass
            # GitHub Advisory format
            ghsa_severity = db_specific.get("severity")
            if ghsa_severity and score is None:
                score = {
                    "CRITICAL": 9.5,
                    "HIGH": 7.5,
                    "MODERATE": 5.5,
                    "LOW": 2.5,
                }.get(str(ghsa_severity).upper())

        severity_label = "unknown"
        if score is not None:
            if score >= 9.0:
                severity_label = "critical"
            elif score >= 7.0:
                severity_label = "high"
            elif score >= 4.0:
                severity_label = "medium"
            elif score > 0.0:
                severity_label = "low"
            else:
                severity_label = "none"

        return score, severity_label, vector

    def _extract_affected_info(self, vuln: dict) -> tuple[str, str]:
        """Extract affected version range and fixed version from OSV data.

        Returns: (affected_versions, fixed_version)
        """
        affected_list = vuln.get("affected", [])
        if not isinstance(affected_list, list) or not affected_list:
            return "", ""

        for affected in affected_list:
            ranges = affected.get("ranges", [])
            if not isinstance(ranges, list):
                continue
            for r in ranges:
                events = r.get("events", [])
                if not isinstance(events, list):
                    continue
                introduced = ""
                fixed = ""
                for event in events:
                    if "introduced" in event:
                        introduced = str(event["introduced"])
                    if "fixed" in event:
                        fixed = str(event["fixed"])
                if introduced or fixed:
                    parts = []
                    if introduced and introduced != "0":
                        parts.append(f">= {introduced}")
                    if fixed:
                        parts.append(f"< {fixed}")
                    return (", ".join(parts) if parts else ""), fixed

        return "", ""

    def _extract_references(self, vuln: dict) -> list[str]:
        """Extract reference URLs from OSV vulnerability."""
        refs = []
        for ref in vuln.get("references", []):
            if isinstance(ref, dict) and "url" in ref:
                refs.append(ref["url"])
        return refs

    def _map_to_record(self, vuln: dict) -> list[CVERecord]:
        """Convert an OSV vulnerability to CVERecord(s)."""
        cve_ids = self._extract_cve_ids(vuln)
        if not cve_ids:
            # Use OSV ID as fallback
            osv_id = vuln.get("id", "UNKNOWN")
            cve_ids = [osv_id]

        cvss_score, severity, vector = self._extract_severity(vuln)
        affected_versions, fixed_version = self._extract_affected_info(vuln)
        description = vuln.get("summary", "") or vuln.get("details", "")
        published = vuln.get("published", "")
        modified = vuln.get("modified", "")
        references = self._extract_references(vuln)

        records = []
        for cve_id in cve_ids:
            records.append(CVERecord(
                cve_id=cve_id,
                description=description,
                cvss_v31_score=cvss_score,
                cvss_v31_vector=vector,
                severity=severity,
                published=published,
                modified=modified,
                affected_versions=affected_versions,
                fixed_version=fixed_version,
                references=references,
                sources=["osv"],
            ))
        return records

    async def query(self, q: CVEQuery) -> SourceResult:
        """Query OSV.dev for vulnerabilities matching the query."""
        start = time.monotonic()

        # Check if ecosystem is supported
        osv_ecosystem = self._resolve_ecosystem(q.ecosystem)
        if q.ecosystem and osv_ecosystem is None:
            # Unsupported ecosystem (e.g., WordPress)
            return SourceResult(
                source_name=self.name,
                records=[],
                query_time_ms=(time.monotonic() - start) * 1000,
            )

        cache_key = f"osv:{q.software}:{q.version}:{q.ecosystem}"

        # Check cache
        if self._cache:
            cached = await self._cache.get(cache_key)
            if cached is not None:
                return SourceResult(
                    source_name=self.name,
                    records=cached,
                    cached=True,
                    query_time_ms=(time.monotonic() - start) * 1000,
                )

        # Rate limit
        if self._rate_limiter:
            await self._rate_limiter.acquire()

        try:
            # Build query payload
            payload: dict = {
                "package": {
                    "name": q.software,
                },
            }
            if osv_ecosystem:
                payload["package"]["ecosystem"] = osv_ecosystem
            if q.version:
                payload["version"] = q.version

            session = await self._get_session()
            async with session.post(
                OSV_API_URL,
                json=payload,
                headers={"Content-Type": "application/json"},
            ) as resp:
                resp.raise_for_status()
                data = await resp.json()

            vulns = data.get("vulns", [])
            if not isinstance(vulns, list):
                vulns = []

            records = []
            for vuln in vulns:
                mapped = self._map_to_record(vuln)
                records.extend(mapped)
                if len(records) >= q.max_results:
                    records = records[: q.max_results]
                    break

            # Apply min_cvss filter
            if q.min_cvss > 0:
                records = [
                    r for r in records
                    if (r.cvss_v31_score or 0.0) >= q.min_cvss
                ]

            # Store in cache
            if self._cache:
                await self._cache.set(cache_key, records)

            return SourceResult(
                source_name=self.name,
                records=records,
                query_time_ms=(time.monotonic() - start) * 1000,
            )

        except Exception as e:
            logger.warning("OSV query failed: %s", e)
            return SourceResult(
                source_name=self.name,
                error=str(e),
                query_time_ms=(time.monotonic() - start) * 1000,
            )

    async def health_check(self) -> bool:
        """Check OSV.dev API availability."""
        try:
            session = await self._get_session()
            async with session.post(
                OSV_API_URL,
                json={"package": {"name": "requests", "ecosystem": "PyPI"}},
                timeout=aiohttp.ClientTimeout(total=10),
            ) as resp:
                return resp.status == 200
        except Exception:
            return False
