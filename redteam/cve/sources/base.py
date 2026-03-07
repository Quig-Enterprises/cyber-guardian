"""Abstract base class for all CVE data source adapters."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional

from redteam.cve.models import CVERecord, CVEQuery


@dataclass
class SourceResult:
    """Result container from a single source query."""

    source_name: str
    records: list[CVERecord] = field(default_factory=list)
    error: Optional[str] = None
    cached: bool = False
    query_time_ms: float = 0.0


class AsyncCVESource(ABC):
    """Abstract base for async CVE data source adapters.

    Each source implements query() to search for CVEs matching a CVEQuery.
    Sources may be local (file-based) or remote (API-based).
    """

    name: str = "unnamed"
    requires_auth: bool = False
    is_local: bool = False

    def __init__(self, config: dict, rate_limiter=None, cache=None):
        self._config = config
        self._rate_limiter = rate_limiter
        self._cache = cache

    @abstractmethod
    async def query(self, q: CVEQuery) -> SourceResult:
        """Query this source for CVEs matching the given query."""
        ...

    async def health_check(self) -> bool:
        """Check if this source is available and functional."""
        return True

    def is_configured(self) -> bool:
        """Check if this source has all required configuration (e.g. API keys)."""
        return True
