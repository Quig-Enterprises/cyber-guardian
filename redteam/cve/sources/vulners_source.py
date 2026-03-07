"""Vulners free API source adapter (requires API key)."""

import logging
import time
from typing import Optional

import aiohttp

from redteam.cve.models import CVEQuery, CVERecord, ExploitMaturity, ExploitRef
from redteam.cve.sources.base import AsyncCVESource, SourceResult

logger = logging.getLogger(__name__)

VULNERS_API_BASE = "https://vulners.com/api/v3"


class VulnersSource(AsyncCVESource):
    """Vulners free API — vulnerability enrichment source.

    Uses raw aiohttp (NOT the vulners pip package) to query the Vulners
    API for exploit references and software vulnerability lookups.

    Free tier endpoints (no credits consumed):
        - ID lookup:  GET /search/id/?id={CVE-ID}&references=true&apiKey={key}
        - Software:   POST /burp/softwareapi/ with software name+version

    Primarily used for enrichment: given a CVE ID, fetch exploit
    references (Metasploit, ExploitDB, GitHub, etc.).
    """

    name = "vulners"
    requires_auth = True

    def __init__(self, config: dict, rate_limiter=None, cache=None):
        super().__init__(config, rate_limiter, cache)
        self._api_key: Optional[str] = self._resolve_api_key()
        self._session: Optional[aiohttp.ClientSession] = None

    def _resolve_api_key(self) -> Optional[str]:
        """Extract Vulners API key from config."""
        try:
            key = self._config.get("cve", {}).get("api_keys", {}).get("vulners", "")
            return key if key and not key.startswith("$") else None
        except (AttributeError, TypeError):
            return None

    def is_configured(self) -> bool:
        """Vulners requires an API key."""
        return self._api_key is not None

    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create an aiohttp session."""
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=30)
            )
        return self._session

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

    def _classify_exploit_source(self, bulletin_type: str) -> str:
        """Classify Vulners bulletin type into exploit source category."""
        type_lower = bulletin_type.lower()
        if "exploit" in type_lower or "exploitdb" in type_lower:
            return "exploitdb"
        if "metasploit" in type_lower:
            return "metasploit"
        if "github" in type_lower:
            return "github"
        if "packetstorm" in type_lower:
            return "packetstorm"
        if "zdi" in type_lower:
            return "zdi"
        return f"vulners-{bulletin_type}"

    def _extract_exploit_maturity(self, exploit_refs: list[ExploitRef]) -> ExploitMaturity:
        """Determine exploit maturity from references."""
        if not exploit_refs:
            return ExploitMaturity.NONE
        sources = {ref.source for ref in exploit_refs}
        if "metasploit" in sources:
            return ExploitMaturity.FUNCTIONAL
        if "exploitdb" in sources or "github" in sources:
            return ExploitMaturity.POC
        return ExploitMaturity.POC

    async def _lookup_by_id(self, cve_id: str) -> Optional[CVERecord]:
        """Look up a single CVE by ID and extract exploit references."""
        session = await self._get_session()
        url = (
            f"{VULNERS_API_BASE}/search/id/"
            f"?id={cve_id}&references=true&apiKey={self._api_key}"
        )

        async with session.get(url) as resp:
            if resp.status != 200:
                return None
            data = await resp.json()

        result = data.get("data", {})
        if result.get("result") != "OK":
            return None

        documents = result.get("documents", {})
        cve_doc = documents.get(cve_id, {})
        if not cve_doc:
            return None

        # Extract CVSS score
        cvss_score = None
        try:
            cvss = cve_doc.get("cvss", {})
            if isinstance(cvss, dict):
                score_val = cvss.get("score")
                if score_val is not None:
                    cvss_score = float(score_val)
        except (ValueError, TypeError):
            pass

        # Extract exploit references from related documents
        exploit_refs = []
        ref_urls = []
        references = result.get("references", {})
        if isinstance(references, dict):
            for ref_id, ref_doc in references.items():
                if not isinstance(ref_doc, dict):
                    continue
                bulletin_type = ref_doc.get("type", "")
                href = ref_doc.get("href", "")
                title = ref_doc.get("title", "")
                if href:
                    ref_urls.append(href)
                    # Classify exploits
                    exploit_types = {"exploit", "metasploit", "packetstorm",
                                     "zdi", "githubexploit", "exploitdb",
                                     "exploitpack", "seebug"}
                    if bulletin_type.lower() in exploit_types:
                        exploit_refs.append(ExploitRef(
                            source=self._classify_exploit_source(bulletin_type),
                            url=href,
                            description=title,
                        ))

        maturity = self._extract_exploit_maturity(exploit_refs)
        description = cve_doc.get("description", "")
        published = cve_doc.get("published", "")
        modified = cve_doc.get("modified", "")

        return CVERecord(
            cve_id=cve_id,
            description=description,
            cvss_v31_score=cvss_score,
            severity=self._severity_from_score(cvss_score),
            published=published,
            modified=modified,
            exploit_maturity=maturity,
            exploit_refs=exploit_refs,
            references=ref_urls,
            sources=["vulners"],
        )

    async def _lookup_by_software(
        self, software: str, version: str
    ) -> list[CVERecord]:
        """Look up vulnerabilities by software name and version."""
        session = await self._get_session()
        url = f"{VULNERS_API_BASE}/burp/softwareapi/"
        payload = {
            "software": software,
            "version": version,
            "type": "software",
            "apiKey": self._api_key,
        }

        async with session.post(url, json=payload) as resp:
            if resp.status != 200:
                return []
            data = await resp.json()

        result = data.get("data", {})
        if result.get("result") != "OK":
            return []

        records = []
        search_data = result.get("search", [])
        if not isinstance(search_data, list):
            return []

        for item in search_data:
            if not isinstance(item, dict):
                continue
            source_data = item.get("_source", {})
            if not isinstance(source_data, dict):
                continue

            bulletin_id = source_data.get("id", "")
            bulletin_type = source_data.get("type", "")

            # Only collect CVE-type entries
            if not bulletin_id.startswith("CVE-"):
                continue

            cvss_score = None
            try:
                cvss = source_data.get("cvss", {})
                if isinstance(cvss, dict):
                    score_val = cvss.get("score")
                    if score_val is not None:
                        cvss_score = float(score_val)
            except (ValueError, TypeError):
                pass

            href = source_data.get("href", "")
            description = source_data.get("description", "")

            records.append(CVERecord(
                cve_id=bulletin_id,
                description=description,
                cvss_v31_score=cvss_score,
                severity=self._severity_from_score(cvss_score),
                published=source_data.get("published", ""),
                modified=source_data.get("modified", ""),
                references=[href] if href else [],
                sources=["vulners"],
            ))

        return records

    async def query(self, q: CVEQuery) -> SourceResult:
        """Query Vulners API for CVE data and exploit references."""
        start = time.monotonic()

        if not self.is_configured():
            return SourceResult(
                source_name=self.name,
                error="Vulners API key not configured",
                query_time_ms=(time.monotonic() - start) * 1000,
            )

        cache_key = f"vulners:{q.software}:{q.version}"

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
            records = []

            # If we have a version, use the software lookup endpoint
            if q.version:
                records = await self._lookup_by_software(q.software, q.version)
            else:
                # Try ID lookup if software looks like a CVE ID
                if q.software.upper().startswith("CVE-"):
                    record = await self._lookup_by_id(q.software.upper())
                    if record:
                        records = [record]

            # Truncate and filter
            records = records[: q.max_results]
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
            logger.warning("Vulners query failed: %s", e)
            return SourceResult(
                source_name=self.name,
                error=str(e),
                query_time_ms=(time.monotonic() - start) * 1000,
            )

    async def health_check(self) -> bool:
        """Check Vulners API availability."""
        if not self.is_configured():
            return False
        try:
            session = await self._get_session()
            url = (
                f"{VULNERS_API_BASE}/search/id/"
                f"?id=CVE-2021-44228&references=false&apiKey={self._api_key}"
            )
            async with session.get(
                url, timeout=aiohttp.ClientTimeout(total=10)
            ) as resp:
                return resp.status == 200
        except Exception:
            return False
