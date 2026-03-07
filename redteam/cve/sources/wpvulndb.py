"""WPVulnerability.net source adapter (no auth required)."""

import logging
import time
from typing import Optional

import aiohttp

from redteam.cve.models import CVEQuery, CVERecord, ExploitMaturity
from redteam.cve.sources.base import AsyncCVESource, SourceResult

logger = logging.getLogger(__name__)

BASE_URL = "https://www.wpvulnerability.net"


class WPVulnerabilitySource(AsyncCVESource):
    """WPVulnerability.net — free WordPress vulnerability database.

    Provides vulnerability data for WordPress core, plugins, and themes
    without requiring authentication.

    Endpoints:
        - Plugin: GET /plugin/{slug}/
        - Theme:  GET /theme/{slug}/
        - Core:   GET /core/{version}/
    """

    name = "wpvulnerability"
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

    def _build_url(self, q: CVEQuery) -> Optional[str]:
        """Determine the correct API endpoint based on ecosystem."""
        eco = q.ecosystem.lower() if q.ecosystem else ""
        if eco == "wordpress-plugin" or (not eco and q.software):
            return f"{BASE_URL}/plugin/{q.software}/"
        elif eco == "wordpress-theme":
            return f"{BASE_URL}/theme/{q.software}/"
        elif eco == "wordpress-core":
            version = q.version or q.software
            return f"{BASE_URL}/core/{version}/"
        return None

    def _extract_cve_ids(self, vuln: dict) -> list[str]:
        """Extract CVE IDs from a vulnerability's source array."""
        cve_ids = []
        sources = vuln.get("source", [])
        if isinstance(sources, list):
            for src in sources:
                if isinstance(src, dict) and src.get("type") == "CVE":
                    name = src.get("name", "")
                    if name.startswith("CVE-"):
                        cve_ids.append(name)
        return cve_ids

    def _extract_cvss(self, vuln: dict) -> Optional[float]:
        """Extract CVSS score from vulnerability impact data."""
        try:
            impact = vuln.get("impact", {})
            if isinstance(impact, dict):
                cvss = impact.get("cvss", {})
                if isinstance(cvss, dict):
                    score = cvss.get("score")
                    if score is not None:
                        return float(score)
        except (ValueError, TypeError):
            pass
        return None

    def _extract_affected_versions(self, vuln: dict) -> str:
        """Extract affected version range from operator field."""
        operator = vuln.get("operator", {})
        if isinstance(operator, dict):
            parts = []
            min_op = operator.get("min_operator", "")
            min_ver = operator.get("min_operand", "")
            max_op = operator.get("max_operator", "")
            max_ver = operator.get("max_operand", "")
            if min_op and min_ver:
                parts.append(f"{min_op} {min_ver}")
            if max_op and max_ver:
                parts.append(f"{max_op} {max_ver}")
            if parts:
                return ", ".join(parts)
        return ""

    def _severity_from_score(self, score: Optional[float]) -> str:
        """Map CVSS score to severity string."""
        if score is None:
            return "unknown"
        if score >= 9.0:
            return "critical"
        if score >= 7.0:
            return "high"
        if score >= 4.0:
            return "medium"
        if score > 0.0:
            return "low"
        return "none"

    def _map_vuln_to_records(self, vuln: dict) -> list[CVERecord]:
        """Convert a single WPVulnerability entry to CVERecord(s)."""
        cve_ids = self._extract_cve_ids(vuln)
        if not cve_ids:
            # Generate a placeholder ID from the vulnerability name
            name = vuln.get("name", "unknown")
            cve_ids = [f"WPVULN-{hash(name) & 0xFFFFFFFF:08x}"]

        cvss_score = self._extract_cvss(vuln)
        severity = self._severity_from_score(cvss_score)
        affected = self._extract_affected_versions(vuln)
        vuln_type = vuln.get("type", "")
        fixed_in = ""
        operator = vuln.get("operator", {})
        if isinstance(operator, dict):
            max_operand = operator.get("max_operand", "")
            max_op = operator.get("max_operator", "")
            if max_op == "<" and max_operand:
                fixed_in = max_operand

        records = []
        for cve_id in cve_ids:
            records.append(CVERecord(
                cve_id=cve_id,
                description=vuln.get("name", ""),
                cvss_v31_score=cvss_score,
                severity=severity,
                published=vuln.get("date", ""),
                affected_versions=affected,
                fixed_version=fixed_in,
                wp_vuln_type=vuln_type,
                wp_fixed_in=fixed_in,
                sources=["wpvulnerability"],
            ))
        return records

    async def query(self, q: CVEQuery) -> SourceResult:
        """Query WPVulnerability.net for WordPress CVEs."""
        start = time.monotonic()

        # Only relevant for WordPress ecosystems
        eco = q.ecosystem.lower() if q.ecosystem else ""
        if eco and not eco.startswith("wordpress"):
            return SourceResult(
                source_name=self.name,
                records=[],
                query_time_ms=(time.monotonic() - start) * 1000,
            )

        cache_key = f"wpvulndb:{q.software}:{q.version}:{q.ecosystem}"

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

        url = self._build_url(q)
        if not url:
            return SourceResult(
                source_name=self.name,
                records=[],
                query_time_ms=(time.monotonic() - start) * 1000,
            )

        # Rate limit
        if self._rate_limiter:
            await self._rate_limiter.acquire()

        try:
            session = await self._get_session()
            async with session.get(url) as resp:
                if resp.status == 404:
                    logger.debug("WPVulnerability: no data for %s", q.software)
                    return SourceResult(
                        source_name=self.name,
                        records=[],
                        query_time_ms=(time.monotonic() - start) * 1000,
                    )
                resp.raise_for_status()
                data = await resp.json()

            # Parse response structure
            output = data.get("data", {}).get("output", {})
            vulns = output.get("vulnerability", [])
            if not isinstance(vulns, list):
                vulns = []

            records = []
            for vuln in vulns:
                mapped = self._map_vuln_to_records(vuln)
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
            logger.warning("WPVulnerability query failed: %s", e)
            return SourceResult(
                source_name=self.name,
                error=str(e),
                query_time_ms=(time.monotonic() - start) * 1000,
            )

    async def health_check(self) -> bool:
        """Check WPVulnerability.net availability."""
        try:
            session = await self._get_session()
            async with session.get(
                f"{BASE_URL}/plugin/wordpress-seo/",
                timeout=aiohttp.ClientTimeout(total=10),
            ) as resp:
                return resp.status == 200
        except Exception:
            return False
