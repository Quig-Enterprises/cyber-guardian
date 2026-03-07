"""deps.dev API source adapter (no auth required)."""

import logging
import time
from typing import Optional
from urllib.parse import quote

import aiohttp

from redteam.cve.models import CVEQuery, CVERecord, ExploitMaturity
from redteam.cve.sources.base import AsyncCVESource, SourceResult

logger = logging.getLogger(__name__)

DEPS_DEV_API_BASE = "https://api.deps.dev/v3"

# Mapping from our ecosystem names to deps.dev system values
SYSTEM_MAP = {
    "npm": "npm",
    "pypi": "pypi",
    "go": "go",
    "cargo": "cargo",
    "rust": "cargo",
    "crates": "cargo",
    "maven": "maven",
    "java": "maven",
    "nuget": "nuget",
}

# Ecosystems NOT supported by deps.dev
UNSUPPORTED_SYSTEMS = {
    "wordpress-plugin",
    "wordpress-theme",
    "wordpress-core",
    "generic",
    "rubygems",
    "ruby",
    "packagist",
    "php",
    "composer",
}


class DepsDevSource(AsyncCVESource):
    """deps.dev — package supply-chain advisory database.

    Provides advisory data for packages across npm, PyPI, Go, Cargo,
    Maven, and NuGet ecosystems.  No authentication required.

    Endpoints:
        - Version info:    GET /systems/{system}/packages/{name}/versions/{version}
        - Advisory detail: GET /advisories/{id}
    """

    name = "deps_dev"
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

    def _resolve_system(self, eco: str) -> Optional[str]:
        """Map our ecosystem name to deps.dev system name."""
        if not eco:
            return None
        lower = eco.lower()
        if lower in UNSUPPORTED_SYSTEMS:
            return None
        return SYSTEM_MAP.get(lower)

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

    async def _fetch_advisory_detail(
        self, advisory_id: str, session: aiohttp.ClientSession
    ) -> Optional[dict]:
        """Fetch detailed advisory data by ID."""
        url = f"{DEPS_DEV_API_BASE}/advisories/{quote(advisory_id, safe='')}"
        try:
            async with session.get(url) as resp:
                if resp.status == 200:
                    return await resp.json()
                logger.debug(
                    "deps.dev advisory fetch failed for %s: HTTP %d",
                    advisory_id, resp.status,
                )
                return None
        except Exception as e:
            logger.debug("deps.dev advisory fetch error for %s: %s", advisory_id, e)
            return None

    def _map_advisory_to_record(
        self, advisory_key: dict, detail: Optional[dict]
    ) -> Optional[CVERecord]:
        """Convert a deps.dev advisory to a CVERecord."""
        advisory_id = ""
        if isinstance(advisory_key, dict):
            advisory_id = advisory_key.get("id", "")
        elif isinstance(advisory_key, str):
            advisory_id = advisory_key

        if not advisory_id:
            return None

        # Determine if this is a CVE or GHSA
        cve_id = advisory_id
        if not advisory_id.startswith("CVE-") and not advisory_id.startswith("GHSA-"):
            cve_id = advisory_id  # Keep whatever ID we have

        # Extract data from detail response
        description = ""
        cvss_score = None
        cvss_vector = ""
        severity = "unknown"
        references = []
        affected_versions = ""

        if detail and isinstance(detail, dict):
            # URL from detail
            url = detail.get("url", "")
            if url:
                references.append(url)

            # Try to get aliases (might contain CVE ID)
            aliases = detail.get("aliases", [])
            if isinstance(aliases, list):
                for alias in aliases:
                    if alias.startswith("CVE-") and not cve_id.startswith("CVE-"):
                        cve_id = alias
                        break

            # Title/summary as description
            description = detail.get("title", "") or detail.get("summary", "")

            # CVSS from detail
            cvss_data = detail.get("cvss3Score")
            if cvss_data is not None:
                try:
                    cvss_score = float(cvss_data)
                except (ValueError, TypeError):
                    pass

            cvss_vector = detail.get("cvss3Vector", "") or ""

            # Severity
            severity_val = detail.get("severity", "")
            if severity_val:
                severity = severity_val.lower()
            elif cvss_score is not None:
                severity = self._severity_from_score(cvss_score)

        advisory_url = f"https://deps.dev/advisory/{quote(advisory_id, safe='')}"
        if advisory_url not in references:
            references.append(advisory_url)

        return CVERecord(
            cve_id=cve_id,
            description=description,
            cvss_v31_score=cvss_score,
            cvss_v31_vector=cvss_vector,
            severity=severity,
            affected_versions=affected_versions,
            references=references,
            sources=["deps_dev"],
        )

    async def query(self, q: CVEQuery) -> SourceResult:
        """Query deps.dev for package vulnerabilities."""
        start = time.monotonic()

        # Check if ecosystem is supported
        system = self._resolve_system(q.ecosystem)
        if q.ecosystem and system is None:
            return SourceResult(
                source_name=self.name,
                records=[],
                query_time_ms=(time.monotonic() - start) * 1000,
            )

        # deps.dev requires both a system and a version
        if not system:
            return SourceResult(
                source_name=self.name,
                records=[],
                query_time_ms=(time.monotonic() - start) * 1000,
            )

        if not q.version:
            logger.debug("deps.dev requires a version for package lookup")
            return SourceResult(
                source_name=self.name,
                records=[],
                query_time_ms=(time.monotonic() - start) * 1000,
            )

        cache_key = f"deps_dev:{system}:{q.software}:{q.version}"

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
            session = await self._get_session()

            # Step 1: Get version info with advisories
            pkg_name_encoded = quote(q.software, safe="")
            version_encoded = quote(q.version, safe="")
            version_url = (
                f"{DEPS_DEV_API_BASE}/systems/{system}"
                f"/packages/{pkg_name_encoded}"
                f"/versions/{version_encoded}"
            )

            async with session.get(version_url) as resp:
                if resp.status == 404:
                    logger.debug(
                        "deps.dev: package %s@%s not found in %s",
                        q.software, q.version, system,
                    )
                    return SourceResult(
                        source_name=self.name,
                        records=[],
                        query_time_ms=(time.monotonic() - start) * 1000,
                    )
                resp.raise_for_status()
                version_data = await resp.json()

            # Step 2: Extract advisory keys
            advisories = version_data.get("advisoryKeys", [])
            if not isinstance(advisories, list):
                advisories = []

            # Step 3: Fetch detail for each advisory
            records = []
            for advisory_key in advisories:
                if len(records) >= q.max_results:
                    break

                advisory_id = ""
                if isinstance(advisory_key, dict):
                    advisory_id = advisory_key.get("id", "")
                elif isinstance(advisory_key, str):
                    advisory_id = advisory_key

                if not advisory_id:
                    continue

                # Fetch advisory detail
                detail = await self._fetch_advisory_detail(advisory_id, session)
                record = self._map_advisory_to_record(advisory_key, detail)
                if record is not None:
                    score = record.cvss_v31_score or 0.0
                    if score >= q.min_cvss:
                        records.append(record)

            # Store in cache
            if self._cache:
                await self._cache.set(cache_key, records)

            return SourceResult(
                source_name=self.name,
                records=records,
                query_time_ms=(time.monotonic() - start) * 1000,
            )

        except Exception as e:
            logger.warning("deps.dev query failed: %s", e)
            return SourceResult(
                source_name=self.name,
                error=str(e),
                query_time_ms=(time.monotonic() - start) * 1000,
            )

    async def health_check(self) -> bool:
        """Check deps.dev API availability."""
        try:
            session = await self._get_session()
            async with session.get(
                f"{DEPS_DEV_API_BASE}/systems/npm/packages/express/versions/4.18.2",
                timeout=aiohttp.ClientTimeout(total=10),
            ) as resp:
                return resp.status == 200
        except Exception:
            return False
