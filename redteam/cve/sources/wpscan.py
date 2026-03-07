"""WPScan API v3 source adapter (requires auth token)."""

import logging
import time
from typing import Optional

import aiohttp

from redteam.cve.models import CVEQuery, CVERecord, ExploitMaturity, ExploitRef
from redteam.cve.sources.base import AsyncCVESource, SourceResult

logger = logging.getLogger(__name__)

WPSCAN_API_BASE = "https://wpscan.com/api/v3"


class WPScanSource(AsyncCVESource):
    """WPScan API v3 — WordPress vulnerability database.

    Requires an API token (free tier: 25 requests/day).

    Endpoints:
        - Plugin: GET /plugins/{slug}
        - Theme:  GET /themes/{slug}
        - Core:   GET /wordpresses/{version_slug}
          (version without dots, e.g., "641" for 6.4.1)
    """

    name = "wpscan"
    requires_auth = True

    def __init__(self, config: dict, rate_limiter=None, cache=None):
        super().__init__(config, rate_limiter, cache)
        self._api_key: Optional[str] = self._resolve_api_key()
        self._session: Optional[aiohttp.ClientSession] = None

    def _resolve_api_key(self) -> Optional[str]:
        """Extract WPScan API token from config."""
        try:
            key = self._config.get("cve", {}).get("api_keys", {}).get("wpscan", "")
            return key if key and not key.startswith("$") else None
        except (AttributeError, TypeError):
            return None

    def is_configured(self) -> bool:
        """WPScan requires an API key."""
        return self._api_key is not None

    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create an aiohttp session with auth headers."""
        if self._session is None or self._session.closed:
            headers = {}
            if self._api_key:
                headers["Authorization"] = f"Token token={self._api_key}"
            self._session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=30),
                headers=headers,
            )
        return self._session

    def _build_url(self, q: CVEQuery) -> Optional[str]:
        """Determine the correct API endpoint based on ecosystem."""
        eco = q.ecosystem.lower() if q.ecosystem else ""
        if eco == "wordpress-plugin":
            return f"{WPSCAN_API_BASE}/plugins/{q.software}"
        elif eco == "wordpress-theme":
            return f"{WPSCAN_API_BASE}/themes/{q.software}"
        elif eco == "wordpress-core":
            # Convert version like "6.4.1" to "641"
            version_slug = q.version.replace(".", "") if q.version else ""
            if not version_slug:
                version_slug = q.software.replace(".", "")
            return f"{WPSCAN_API_BASE}/wordpresses/{version_slug}"
        return None

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
        """Convert a single WPScan vulnerability entry to CVERecord(s)."""
        # Extract CVE IDs from references
        cve_ids = []
        references = vuln.get("references", {})
        if isinstance(references, dict):
            cve_list = references.get("cve", [])
            if isinstance(cve_list, list):
                for cve_num in cve_list:
                    cve_ids.append(f"CVE-{cve_num}")

        if not cve_ids:
            # Use title hash as fallback
            title = vuln.get("title", "unknown")
            cve_ids = [f"WPSCAN-{hash(title) & 0xFFFFFFFF:08x}"]

        # Extract CVSS score
        cvss_score = None
        cvss_data = vuln.get("cvss", {})
        if isinstance(cvss_data, dict):
            score_val = cvss_data.get("score")
            if score_val is not None:
                try:
                    cvss_score = float(score_val)
                except (ValueError, TypeError):
                    pass

        # Extract exploit references
        exploit_refs = []
        ref_urls = []
        if isinstance(references, dict):
            for ref_type, ref_list in references.items():
                if ref_type == "cve":
                    continue
                if isinstance(ref_list, list):
                    for ref_item in ref_list:
                        url = str(ref_item) if not isinstance(ref_item, dict) else ref_item.get("url", "")
                        if url:
                            ref_urls.append(url)
                            if "exploit" in url.lower() or ref_type in ("exploitdb", "metasploit"):
                                exploit_refs.append(ExploitRef(
                                    source=f"wpscan-{ref_type}",
                                    url=url,
                                    description=f"{ref_type} reference",
                                ))

        severity = self._severity_from_score(cvss_score)
        vuln_type = vuln.get("vuln_type", "")
        fixed_in = vuln.get("fixed_in", "")
        if fixed_in is None:
            fixed_in = ""
        else:
            fixed_in = str(fixed_in)

        records = []
        for cve_id in cve_ids:
            records.append(CVERecord(
                cve_id=cve_id,
                description=vuln.get("title", ""),
                cvss_v31_score=cvss_score,
                severity=severity,
                published=vuln.get("created_at", ""),
                modified=vuln.get("updated_at", ""),
                fixed_version=fixed_in,
                wp_vuln_type=vuln_type,
                wp_fixed_in=fixed_in,
                exploit_refs=exploit_refs,
                references=ref_urls,
                sources=["wpscan"],
            ))
        return records

    async def query(self, q: CVEQuery) -> SourceResult:
        """Query WPScan API for WordPress CVEs."""
        start = time.monotonic()

        # Only relevant for WordPress ecosystems
        eco = q.ecosystem.lower() if q.ecosystem else ""
        if eco and not eco.startswith("wordpress"):
            return SourceResult(
                source_name=self.name,
                records=[],
                query_time_ms=(time.monotonic() - start) * 1000,
            )

        if not self.is_configured():
            return SourceResult(
                source_name=self.name,
                error="WPScan API key not configured",
                query_time_ms=(time.monotonic() - start) * 1000,
            )

        cache_key = f"wpscan:{q.software}:{q.version}:{q.ecosystem}"

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
                    logger.debug("WPScan: no data for %s", q.software)
                    return SourceResult(
                        source_name=self.name,
                        records=[],
                        query_time_ms=(time.monotonic() - start) * 1000,
                    )
                if resp.status == 403:
                    logger.warning("WPScan: API key invalid or rate limited")
                    return SourceResult(
                        source_name=self.name,
                        error="WPScan API key invalid or rate limit exceeded",
                        query_time_ms=(time.monotonic() - start) * 1000,
                    )
                resp.raise_for_status()
                data = await resp.json()

            # Response structure: {slug: {vulnerabilities: [...]}}
            # or for core: {version: {vulnerabilities: [...]}}
            records = []
            for slug_key, slug_data in data.items():
                if not isinstance(slug_data, dict):
                    continue
                vulns = slug_data.get("vulnerabilities", [])
                if not isinstance(vulns, list):
                    continue
                for vuln in vulns:
                    mapped = self._map_vuln_to_records(vuln)
                    records.extend(mapped)
                    if len(records) >= q.max_results:
                        break
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
            logger.warning("WPScan query failed: %s", e)
            return SourceResult(
                source_name=self.name,
                error=str(e),
                query_time_ms=(time.monotonic() - start) * 1000,
            )

    async def health_check(self) -> bool:
        """Check WPScan API availability."""
        if not self.is_configured():
            return False
        try:
            session = await self._get_session()
            async with session.get(
                f"{WPSCAN_API_BASE}/plugins/wordpress-seo",
                timeout=aiohttp.ClientTimeout(total=10),
            ) as resp:
                return resp.status in (200, 403)  # 403 = key issue, but API is up
        except Exception:
            return False
