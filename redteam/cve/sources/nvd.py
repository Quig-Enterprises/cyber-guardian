"""NVD API v2.0 source adapter using nvdlib."""

import asyncio
import logging
import time
from typing import Optional

from redteam.cve.models import CVEQuery, CVERecord, ExploitMaturity
from redteam.cve.sources.base import AsyncCVESource, SourceResult

logger = logging.getLogger(__name__)


class NVDSource(AsyncCVESource):
    """NVD (National Vulnerability Database) API v2.0 source.

    Uses nvdlib for synchronous queries, wrapped in asyncio.to_thread()
    for non-blocking operation.  Works without an API key but is rate-limited
    to ~5 req/30s; with a key the limit is ~50 req/30s.
    """

    name = "nvd"
    requires_auth = True  # works without key, just slower

    def __init__(self, config: dict, rate_limiter=None, cache=None):
        super().__init__(config, rate_limiter, cache)
        self._api_key: Optional[str] = self._resolve_api_key()

    def _resolve_api_key(self) -> Optional[str]:
        """Extract NVD API key from config."""
        try:
            key = self._config.get("cve", {}).get("api_keys", {}).get("nvd", "")
            return key if key and not key.startswith("$") else None
        except (AttributeError, TypeError):
            return None

    def is_configured(self) -> bool:
        """NVD works without a key (slower), so always configured."""
        return True

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

    def _extract_cvss_v31(self, cve_item) -> tuple[Optional[float], str]:
        """Extract CVSS v3.1 score and vector from an nvdlib CVE object."""
        score = None
        vector = ""
        try:
            if hasattr(cve_item, "v31score"):
                score = float(cve_item.v31score)
            if hasattr(cve_item, "v31vector"):
                vector = str(cve_item.v31vector)
            # Fallback to v30 if v31 not available
            if score is None and hasattr(cve_item, "v30score"):
                score = float(cve_item.v30score)
            if not vector and hasattr(cve_item, "v30vector"):
                vector = str(cve_item.v30vector)
        except (ValueError, TypeError):
            pass
        return score, vector

    def _extract_description(self, cve_item) -> str:
        """Extract English description from nvdlib CVE object."""
        try:
            if hasattr(cve_item, "descriptions"):
                for desc in cve_item.descriptions:
                    if hasattr(desc, "lang") and desc.lang == "en":
                        return str(desc.value)
                # Fallback to first description
                if cve_item.descriptions:
                    return str(cve_item.descriptions[0].value)
        except (AttributeError, IndexError, TypeError):
            pass
        return ""

    def _extract_references(self, cve_item) -> list[str]:
        """Extract reference URLs from nvdlib CVE object."""
        refs = []
        try:
            if hasattr(cve_item, "references"):
                for ref in cve_item.references:
                    if hasattr(ref, "url"):
                        refs.append(str(ref.url))
        except (AttributeError, TypeError):
            pass
        return refs

    def _extract_cpes(self, cve_item) -> list[str]:
        """Extract CPE match strings from nvdlib CVE object."""
        cpes = []
        try:
            if hasattr(cve_item, "cpe"):
                for cpe_entry in cve_item.cpe:
                    if hasattr(cpe_entry, "criteria"):
                        cpes.append(str(cpe_entry.criteria))
        except (AttributeError, TypeError):
            pass
        return cpes

    def _version_matches(self, cve_item, version: str) -> bool:
        """Check if a CVE affects the specified version.

        When no version is specified, all CVEs match.  When a version is
        specified, we check the CPE configurations for version ranges.
        """
        if not version:
            return True
        try:
            if hasattr(cve_item, "cpe"):
                for cpe_entry in cve_item.cpe:
                    # If vulnerable flag is set, check version ranges
                    vulnerable = getattr(cpe_entry, "vulnerable", True)
                    if not vulnerable:
                        continue
                    vs = getattr(cpe_entry, "versionStartIncluding", "")
                    ve = getattr(cpe_entry, "versionEndIncluding", "")
                    vee = getattr(cpe_entry, "versionEndExcluding", "")
                    # If no version constraints, match all
                    if not vs and not ve and not vee:
                        return True
                    # Simple string comparison (sufficient for most cases)
                    if vee and version >= (vs or "") and version < vee:
                        return True
                    if ve and version >= (vs or "") and version <= ve:
                        return True
                    if vs and not ve and not vee and version >= vs:
                        return True
                # If CPE entries exist but none matched
                return False
        except (AttributeError, TypeError):
            pass
        return True

    def _map_to_record(self, cve_item) -> CVERecord:
        """Convert nvdlib CVE object to CVERecord."""
        cve_id = str(cve_item.id) if hasattr(cve_item, "id") else ""
        cvss_score, cvss_vector = self._extract_cvss_v31(cve_item)
        published = ""
        modified = ""
        if hasattr(cve_item, "published"):
            published = str(cve_item.published)
        if hasattr(cve_item, "lastModified"):
            modified = str(cve_item.lastModified)

        return CVERecord(
            cve_id=cve_id,
            description=self._extract_description(cve_item),
            cvss_v31_score=cvss_score,
            cvss_v31_vector=cvss_vector,
            severity=self._severity_from_score(cvss_score),
            published=published,
            modified=modified,
            cpe_matches=self._extract_cpes(cve_item),
            references=self._extract_references(cve_item),
            sources=["nvd"],
        )

    async def query(self, q: CVEQuery) -> SourceResult:
        """Query NVD API for CVEs matching the query."""
        start = time.monotonic()
        cache_key = f"nvd:{q.software}:{q.version}:{q.cpe}"

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
            import nvdlib

            kwargs = {}
            if self._api_key:
                kwargs["key"] = self._api_key

            if q.cpe:
                kwargs["cpeName"] = q.cpe
            else:
                kwargs["keywordSearch"] = q.software

            # nvdlib is synchronous — wrap in thread
            cve_results = await asyncio.to_thread(
                nvdlib.searchCVE, **kwargs
            )

            records = []
            for cve_item in cve_results:
                if not self._version_matches(cve_item, q.version):
                    continue
                record = self._map_to_record(cve_item)
                if record.cve_id:
                    # Apply min_cvss filter
                    score = record.cvss_v31_score or 0.0
                    if score >= q.min_cvss:
                        records.append(record)
                if len(records) >= q.max_results:
                    break

            # Store in cache
            if self._cache:
                await self._cache.set(cache_key, records)

            return SourceResult(
                source_name=self.name,
                records=records,
                query_time_ms=(time.monotonic() - start) * 1000,
            )

        except ImportError:
            logger.error("nvdlib is not installed; NVD source unavailable")
            return SourceResult(
                source_name=self.name,
                error="nvdlib not installed",
                query_time_ms=(time.monotonic() - start) * 1000,
            )
        except Exception as e:
            logger.warning("NVD query failed: %s", e)
            return SourceResult(
                source_name=self.name,
                error=str(e),
                query_time_ms=(time.monotonic() - start) * 1000,
            )

    async def health_check(self) -> bool:
        """Check NVD API availability."""
        try:
            import nvdlib  # noqa: F401
            return True
        except ImportError:
            return False
