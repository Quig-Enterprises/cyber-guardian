"""GitHub Advisory Database REST API source adapter (requires auth)."""

import logging
import time
from typing import Optional

import aiohttp

from redteam.cve.models import CVEQuery, CVERecord, ExploitMaturity
from redteam.cve.sources.base import AsyncCVESource, SourceResult

logger = logging.getLogger(__name__)

GITHUB_API_BASE = "https://api.github.com"

# Mapping from our ecosystem names to GitHub Advisory ecosystem values
ECOSYSTEM_MAP = {
    "npm": "npm",
    "pypi": "pip",
    "go": "go",
    "cargo": "rust",
    "rust": "rust",
    "crates": "rust",
    "maven": "maven",
    "java": "maven",
    "nuget": "nuget",
    "rubygems": "rubygems",
    "ruby": "rubygems",
    "packagist": "composer",
    "php": "composer",
    "composer": "composer",
    "hex": "erlang",
    "pub": "pub",
    "swift": "swift",
    "actions": "actions",
}

# Ecosystems NOT supported by GitHub Advisory API
UNSUPPORTED_ECOSYSTEMS = {
    "wordpress-plugin",
    "wordpress-theme",
    "wordpress-core",
    "generic",
}


class GitHubAdvisorySource(AsyncCVESource):
    """GitHub Advisory Database — security advisories via REST API.

    Requires a GitHub personal access token (PAT).  Free tier allows
    5,000 requests per hour.

    Supports ecosystems: npm, pip, go, rust, maven, nuget, rubygems,
    composer, erlang, pub, swift, actions.

    Does NOT support WordPress-specific ecosystems.
    """

    name = "github_advisory"
    requires_auth = True

    def __init__(self, config: dict, rate_limiter=None, cache=None):
        super().__init__(config, rate_limiter, cache)
        self._token: Optional[str] = self._resolve_token()
        self._session: Optional[aiohttp.ClientSession] = None

    def _resolve_token(self) -> Optional[str]:
        """Extract GitHub token from config."""
        try:
            token = self._config.get("cve", {}).get("api_keys", {}).get("github", "")
            return token if token and not token.startswith("$") else None
        except (AttributeError, TypeError):
            return None

    def is_configured(self) -> bool:
        """GitHub Advisory requires a PAT."""
        return self._token is not None

    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create an aiohttp session with auth headers."""
        if self._session is None or self._session.closed:
            headers = {
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            }
            if self._token:
                headers["Authorization"] = f"Bearer {self._token}"
            self._session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=30),
                headers=headers,
            )
        return self._session

    def _resolve_ecosystem(self, eco: str) -> Optional[str]:
        """Map our ecosystem name to GitHub Advisory ecosystem name."""
        if not eco:
            return None
        lower = eco.lower()
        if lower in UNSUPPORTED_ECOSYSTEMS:
            return None
        return ECOSYSTEM_MAP.get(lower)

    def _severity_from_label(self, label: str) -> tuple[Optional[float], str]:
        """Convert GitHub severity label to score and our severity string.

        Returns: (estimated_score, severity_label)
        """
        mapping = {
            "critical": (9.5, "critical"),
            "high": (7.5, "high"),
            "moderate": (5.5, "medium"),
            "medium": (5.5, "medium"),
            "low": (2.5, "low"),
        }
        return mapping.get(label.lower(), (None, "unknown"))

    def _extract_affected_info(self, advisory: dict) -> tuple[str, str, str]:
        """Extract affected package, version range, and fixed version.

        Returns: (package_name, affected_versions, fixed_version)
        """
        vulns = advisory.get("vulnerabilities", [])
        if not isinstance(vulns, list) or not vulns:
            return "", "", ""

        for vuln in vulns:
            if not isinstance(vuln, dict):
                continue
            package = vuln.get("package", {})
            pkg_name = package.get("name", "") if isinstance(package, dict) else ""
            version_range = vuln.get("vulnerable_version_range", "")
            first_patched = vuln.get("first_patched_version", "")
            if isinstance(first_patched, dict):
                first_patched = first_patched.get("identifier", "")
            return pkg_name, str(version_range), str(first_patched)

        return "", "", ""

    def _extract_references(self, advisory: dict) -> list[str]:
        """Extract reference URLs from advisory."""
        refs = []
        html_url = advisory.get("html_url", "")
        if html_url:
            refs.append(html_url)
        for ref in advisory.get("references", []):
            if isinstance(ref, str) and ref not in refs:
                refs.append(ref)
        return refs

    def _map_to_record(self, advisory: dict) -> Optional[CVERecord]:
        """Convert a GitHub advisory to a CVERecord."""
        cve_id = advisory.get("cve_id", "")
        ghsa_id = advisory.get("ghsa_id", "")

        # Must have at least one identifier
        if not cve_id and not ghsa_id:
            return None

        # Prefer CVE ID, fall back to GHSA
        primary_id = cve_id if cve_id else ghsa_id

        # Extract CVSS score
        cvss_score = None
        cvss_data = advisory.get("cvss", {})
        if isinstance(cvss_data, dict):
            score_val = cvss_data.get("score")
            if score_val is not None:
                try:
                    cvss_score = float(score_val)
                except (ValueError, TypeError):
                    pass

        cvss_vector = ""
        if isinstance(cvss_data, dict):
            cvss_vector = cvss_data.get("vector_string", "") or ""

        # Get severity
        severity_label = advisory.get("severity", "unknown")
        if cvss_score is not None:
            if cvss_score >= 9.0:
                severity = "critical"
            elif cvss_score >= 7.0:
                severity = "high"
            elif cvss_score >= 4.0:
                severity = "medium"
            elif cvss_score > 0.0:
                severity = "low"
            else:
                severity = "none"
        else:
            est_score, severity = self._severity_from_label(severity_label)
            if cvss_score is None:
                cvss_score = est_score

        pkg_name, affected_versions, fixed_version = self._extract_affected_info(advisory)
        references = self._extract_references(advisory)

        return CVERecord(
            cve_id=primary_id,
            description=advisory.get("summary", ""),
            cvss_v31_score=cvss_score,
            cvss_v31_vector=cvss_vector,
            severity=severity,
            published=advisory.get("published_at", ""),
            modified=advisory.get("updated_at", ""),
            affected_versions=affected_versions,
            fixed_version=fixed_version,
            references=references,
            sources=["github_advisory"],
        )

    async def query(self, q: CVEQuery) -> SourceResult:
        """Query GitHub Advisory Database for vulnerabilities."""
        start = time.monotonic()

        # Check if ecosystem is supported
        gh_ecosystem = self._resolve_ecosystem(q.ecosystem)
        if q.ecosystem and gh_ecosystem is None:
            return SourceResult(
                source_name=self.name,
                records=[],
                query_time_ms=(time.monotonic() - start) * 1000,
            )

        if not self.is_configured():
            return SourceResult(
                source_name=self.name,
                error="GitHub token not configured",
                query_time_ms=(time.monotonic() - start) * 1000,
            )

        cache_key = f"github_advisory:{q.software}:{q.version}:{q.ecosystem}"

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
            # Build query parameters
            params: dict = {
                "per_page": str(min(q.max_results, 100)),
                "affects": q.software,
            }
            if gh_ecosystem:
                params["ecosystem"] = gh_ecosystem

            session = await self._get_session()
            async with session.get(
                f"{GITHUB_API_BASE}/advisories",
                params=params,
            ) as resp:
                if resp.status == 401:
                    logger.warning("GitHub Advisory: authentication failed")
                    return SourceResult(
                        source_name=self.name,
                        error="GitHub token invalid",
                        query_time_ms=(time.monotonic() - start) * 1000,
                    )
                if resp.status == 403:
                    logger.warning("GitHub Advisory: rate limit exceeded")
                    return SourceResult(
                        source_name=self.name,
                        error="GitHub API rate limit exceeded",
                        query_time_ms=(time.monotonic() - start) * 1000,
                    )
                resp.raise_for_status()
                advisories = await resp.json()

            if not isinstance(advisories, list):
                advisories = []

            records = []
            for advisory in advisories:
                record = self._map_to_record(advisory)
                if record is not None:
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

        except Exception as e:
            logger.warning("GitHub Advisory query failed: %s", e)
            return SourceResult(
                source_name=self.name,
                error=str(e),
                query_time_ms=(time.monotonic() - start) * 1000,
            )

    async def health_check(self) -> bool:
        """Check GitHub Advisory API availability."""
        if not self.is_configured():
            return False
        try:
            session = await self._get_session()
            async with session.get(
                f"{GITHUB_API_BASE}/advisories",
                params={"per_page": "1"},
                timeout=aiohttp.ClientTimeout(total=10),
            ) as resp:
                return resp.status == 200
        except Exception:
            return False
