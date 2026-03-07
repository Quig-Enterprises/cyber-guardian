"""CVE Engine — orchestrator that queries all sources, merges, deduplicates, and ranks."""

import asyncio
import logging
from typing import Optional

from redteam.cve.models import CVERecord, CVEQuery, ExploitMaturity
from redteam.cve.cache import CVECache
from redteam.cve.rate_limiter import RateLimiter
from redteam.cve.sources.base import AsyncCVESource, SourceResult

logger = logging.getLogger(__name__)


class CVEEngine:
    """Orchestrator for cross-source CVE lookups.

    Initializes all configured sources with rate limiters and cache on first
    use, then queries local sources first, remote sources in parallel, merges
    results by CVE ID, enriches with KEV/ExploitDB data, and ranks by
    risk_score descending.
    """

    def __init__(self, config: dict, session=None):
        self._config = config
        self._session = session
        self._sources: list[AsyncCVESource] = []
        self._cache: Optional[CVECache] = None
        self._initialized = False

    async def initialize(self) -> None:
        """Initialize all configured sources, rate limiters, and cache. Idempotent."""
        if self._initialized:
            return

        cve_config = self._config.get("cve", {})
        data_dir = cve_config.get("data_dir", "data/cve")
        aws_mode = self._config.get("execution", {}).get("mode") == "aws"

        # Create cache
        cache_cfg = cve_config.get("cache", {})
        self._cache = CVECache(data_dir=data_dir, config=cache_cfg)

        # Create rate limiters per source
        rate_limiters = {
            "nvd": RateLimiter("nvd", 50, 30, aws_mode),
            "wpscan": RateLimiter("wpscan", 25, 86400, aws_mode),
            "github": RateLimiter("github", 5000, 3600, aws_mode),
            "default": RateLimiter("default", 10, 1, aws_mode),
        }

        source_toggles = cve_config.get("sources", {})
        api_keys = cve_config.get("api_keys", {})

        # --- Local sources (always try) ---
        self._try_add_source("redteam.cve.sources.kev", "KEVSource",
                             self._config, None, self._cache)

        self._try_add_source("redteam.cve.sources.exploitdb", "ExploitDBSource",
                             self._config, None, self._cache)

        if source_toggles.get("cvelistv5", True):
            self._try_add_source("redteam.cve.sources.cvelistv5", "CVEListV5Source",
                                 self._config, None, self._cache)

        # --- Remote sources (check toggles) ---
        if source_toggles.get("nvd", True):
            self._try_add_source("redteam.cve.sources.nvd", "NVDSource",
                                 self._config, rate_limiters.get("nvd"), self._cache)

        if source_toggles.get("wpvulnerability", True):
            self._try_add_source("redteam.cve.sources.wpvulndb", "WPVulnerabilitySource",
                                 self._config, rate_limiters.get("default"), self._cache)

        if source_toggles.get("osv", True):
            self._try_add_source("redteam.cve.sources.osv", "OSVSource",
                                 self._config, rate_limiters.get("default"), self._cache)

        if source_toggles.get("wpscan", True):
            self._try_add_source("redteam.cve.sources.wpscan", "WPScanSource",
                                 self._config, rate_limiters.get("wpscan"), self._cache)

        if source_toggles.get("vulners", True):
            self._try_add_source("redteam.cve.sources.vulners_source", "VulnersSource",
                                 self._config, rate_limiters.get("default"), self._cache)

        if source_toggles.get("github_advisory", True):
            self._try_add_source("redteam.cve.sources.github_advisory", "GitHubAdvisorySource",
                                 self._config, rate_limiters.get("github"), self._cache)

        if source_toggles.get("deps_dev", True):
            self._try_add_source("redteam.cve.sources.deps_dev", "DepsDevSource",
                                 self._config, rate_limiters.get("default"), self._cache)

        # Filter out sources that aren't configured (missing API keys, etc.)
        configured = []
        for src in self._sources:
            if src.is_configured():
                configured.append(src)
                logger.debug("Source enabled: %s", src.name)
            else:
                logger.debug("Source skipped (not configured): %s", src.name)
        self._sources = configured

        logger.info("CVE engine initialized with %d sources", len(self._sources))
        self._initialized = True

    def _try_add_source(self, module_path: str, class_name: str,
                        config: dict, rate_limiter, cache) -> None:
        """Try to import and instantiate a source. Log and skip on failure."""
        try:
            import importlib
            mod = importlib.import_module(module_path)
            cls = getattr(mod, class_name)
            instance = cls(config, rate_limiter=rate_limiter, cache=cache)
            self._sources.append(instance)
        except ImportError as exc:
            logger.warning("Could not import %s.%s: %s", module_path, class_name, exc)
        except Exception as exc:
            logger.warning("Could not instantiate %s.%s: %s", module_path, class_name, exc)

    # ------------------------------------------------------------------
    # Primary lookup
    # ------------------------------------------------------------------

    async def lookup(self, query: CVEQuery) -> list[CVERecord]:
        """Query all sources, merge, deduplicate, rank by risk_score."""
        await self.initialize()

        # 1. Check merged-result cache
        cache_key = f"merged:{query.software}:{query.version}:{query.ecosystem}"
        if self._cache:
            cached = await self._cache.get(cache_key)
            if cached is not None:
                logger.debug("Cache hit for %s", cache_key)
                return cached

        # 2. Query local sources first (fast, no network)
        local_results: list[SourceResult] = []
        for src in self._sources:
            if src.is_local:
                try:
                    result = await src.query(query)
                    local_results.append(result)
                    logger.debug("Local source %s returned %d records",
                                 src.name, len(result.records))
                except Exception as exc:
                    logger.warning("Local source %s failed: %s", src.name, exc)

        # 3. Query remote sources IN PARALLEL
        remote_tasks = []
        remote_names = []
        for src in self._sources:
            if not src.is_local:
                remote_tasks.append(src.query(query))
                remote_names.append(src.name)

        remote_results: list[SourceResult] = []
        if remote_tasks:
            raw_results = await asyncio.gather(*remote_tasks, return_exceptions=True)
            for name, result in zip(remote_names, raw_results):
                if isinstance(result, SourceResult):
                    remote_results.append(result)
                    logger.debug("Remote source %s returned %d records",
                                 name, len(result.records))
                elif isinstance(result, Exception):
                    logger.warning("Remote source %s raised: %s", name, result)

        # 4. Merge all results
        all_results = local_results + remote_results
        merged = self._merge_records(all_results)

        # 5. Enrich with KEV status
        kev_source = self._find_source("kev")
        if kev_source and hasattr(kev_source, "is_in_kev"):
            for record in merged:
                if not record.in_kev and kev_source.is_in_kev(record.cve_id):
                    record.in_kev = True
                    kev_entry = kev_source.get_kev_entry(record.cve_id)
                    if kev_entry:
                        record.kev_due_date = kev_entry.get("dueDate", "")
                    if "kev" not in record.sources:
                        record.sources.append("kev")

        # 6. Enrich with exploit data
        exploitdb_source = self._find_source("exploitdb")
        if exploitdb_source and hasattr(exploitdb_source, "has_exploit"):
            for record in merged:
                if exploitdb_source.has_exploit(record.cve_id):
                    refs = exploitdb_source.get_exploits(record.cve_id)
                    existing_urls = {e.url for e in record.exploit_refs}
                    for ref in refs:
                        if ref.url not in existing_urls:
                            record.exploit_refs.append(ref)
                            existing_urls.add(ref.url)
                    # Upgrade maturity if we found public exploits
                    if record.exploit_maturity == ExploitMaturity.NONE:
                        record.exploit_maturity = ExploitMaturity.POC
                    if "exploitdb" not in record.sources:
                        record.sources.append("exploitdb")

        # 7. Apply min_cvss filter
        if query.min_cvss > 0:
            merged = [r for r in merged if r.risk_score >= query.min_cvss]

        # 8. Rank and limit
        ranked = self._rank_records(merged)
        result = ranked[:query.max_results]

        # 9. Cache merged result
        if self._cache and result:
            await self._cache.set(cache_key, result)

        return result

    def _find_source(self, name: str):
        """Find a source by name."""
        for src in self._sources:
            if src.name == name:
                return src
        return None

    # ------------------------------------------------------------------
    # Merge logic
    # ------------------------------------------------------------------

    def _merge_records(self, results: list[SourceResult]) -> list[CVERecord]:
        """Merge records from multiple sources by CVE ID."""
        by_cve: dict[str, CVERecord] = {}

        for result in results:
            if result.error:
                continue
            for record in result.records:
                if not record.cve_id:
                    continue
                if record.cve_id in by_cve:
                    existing = by_cve[record.cve_id]
                    # Prefer higher CVSS score
                    if (record.cvss_v31_score or 0) > (existing.cvss_v31_score or 0):
                        existing.cvss_v31_score = record.cvss_v31_score
                        existing.cvss_v31_vector = record.cvss_v31_vector
                    # Prefer longer description
                    if len(record.description) > len(existing.description):
                        existing.description = record.description
                    # Merge sources
                    for src in record.sources:
                        if src not in existing.sources:
                            existing.sources.append(src)
                    # Merge exploit refs
                    existing_urls = {e.url for e in existing.exploit_refs}
                    for ref in record.exploit_refs:
                        if ref.url not in existing_urls:
                            existing.exploit_refs.append(ref)
                            existing_urls.add(ref.url)
                    # Merge references
                    existing_ref_set = set(existing.references)
                    for ref_url in record.references:
                        if ref_url not in existing_ref_set:
                            existing.references.append(ref_url)
                            existing_ref_set.add(ref_url)
                    # KEV status (union)
                    existing.in_kev = existing.in_kev or record.in_kev
                    if record.kev_due_date and not existing.kev_due_date:
                        existing.kev_due_date = record.kev_due_date
                    # WP fields
                    if record.wp_vuln_type and not existing.wp_vuln_type:
                        existing.wp_vuln_type = record.wp_vuln_type
                    if record.wp_fixed_in and not existing.wp_fixed_in:
                        existing.wp_fixed_in = record.wp_fixed_in
                    if record.fixed_version and not existing.fixed_version:
                        existing.fixed_version = record.fixed_version
                    # Affected versions — prefer longer / more specific
                    if len(record.affected_versions) > len(existing.affected_versions):
                        existing.affected_versions = record.affected_versions
                    # Exploit maturity (take highest)
                    maturity_order = [
                        ExploitMaturity.NONE,
                        ExploitMaturity.POC,
                        ExploitMaturity.FUNCTIONAL,
                        ExploitMaturity.WEAPONIZED,
                    ]
                    try:
                        if maturity_order.index(record.exploit_maturity) > \
                                maturity_order.index(existing.exploit_maturity):
                            existing.exploit_maturity = record.exploit_maturity
                    except ValueError:
                        pass
                    # Severity — take the more severe
                    sev_order = ["unknown", "none", "low", "medium", "high", "critical"]
                    try:
                        if sev_order.index(record.severity) > sev_order.index(existing.severity):
                            existing.severity = record.severity
                    except ValueError:
                        pass
                else:
                    by_cve[record.cve_id] = record

        return list(by_cve.values())

    def _rank_records(self, records: list[CVERecord]) -> list[CVERecord]:
        """Sort records by risk_score descending."""
        return sorted(records, key=lambda r: r.risk_score, reverse=True)

    # ------------------------------------------------------------------
    # Convenience methods
    # ------------------------------------------------------------------

    async def lookup_wordpress_plugin(self, slug: str, version: str) -> list[CVERecord]:
        """Lookup CVEs for a WordPress plugin."""
        query = CVEQuery(
            software=slug,
            version=version,
            ecosystem="wordpress-plugin",
        )
        return await self.lookup(query)

    async def lookup_wordpress_core(self, version: str) -> list[CVERecord]:
        """Lookup CVEs for WordPress core."""
        query = CVEQuery(
            software="wordpress",
            version=version,
            ecosystem="wordpress-core",
            vendor="wordpress",
        )
        return await self.lookup(query)

    async def lookup_wordpress_theme(self, slug: str, version: str) -> list[CVERecord]:
        """Lookup CVEs for a WordPress theme."""
        query = CVEQuery(
            software=slug,
            version=version,
            ecosystem="wordpress-theme",
        )
        return await self.lookup(query)

    async def lookup_server(self, server_name: str, version: str) -> list[CVERecord]:
        """Lookup CVEs for a server component (nginx, apache, PHP)."""
        query = CVEQuery(
            software=server_name,
            version=version,
            ecosystem="generic",
        )
        return await self.lookup(query)
