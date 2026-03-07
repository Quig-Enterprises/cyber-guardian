"""CISA Known Exploited Vulnerabilities (KEV) catalog reader."""

import json
import logging
import time
from pathlib import Path
from typing import Optional

from redteam.cve.models import CVERecord, CVEQuery, ExploitMaturity
from redteam.cve.sources.base import AsyncCVESource, SourceResult

logger = logging.getLogger(__name__)


class KEVSource(AsyncCVESource):
    """Local CISA KEV JSON reader.

    Loads the KEV catalog from {data_dir}/kev.json on first query and
    caches in memory as a dict mapping CVE ID to KEV entry. Provides
    both enrichment (marking CVEs as in-KEV) and standalone search
    (finding KEV entries by product/vendor keyword).
    """

    name = "kev"
    requires_auth = False
    is_local = True

    def __init__(self, config: dict, rate_limiter=None, cache=None):
        super().__init__(config, rate_limiter, cache)
        cve_cfg = config.get("cve", {})
        self._data_dir = Path(cve_cfg.get("data_dir", "data/cve"))
        self._kev_path = self._data_dir / "kev.json"
        self._kev_data: Optional[dict[str, dict]] = None
        self._loaded = False

    def _load(self) -> None:
        """Load KEV JSON into memory on first use."""
        if self._loaded:
            return
        self._loaded = True
        if not self._kev_path.exists():
            logger.warning("KEV data file not found: %s", self._kev_path)
            self._kev_data = {}
            return
        try:
            raw = json.loads(self._kev_path.read_text(encoding="utf-8"))
            vulnerabilities = raw.get("vulnerabilities", [])
            self._kev_data = {}
            for entry in vulnerabilities:
                cve_id = entry.get("cveID", "")
                if cve_id:
                    self._kev_data[cve_id] = entry
            logger.info("KEV catalog loaded: %d entries", len(self._kev_data))
        except (json.JSONDecodeError, OSError) as exc:
            logger.error("Failed to load KEV data: %s", exc)
            self._kev_data = {}

    def is_in_kev(self, cve_id: str) -> bool:
        """Check if a CVE ID is in the KEV catalog."""
        self._load()
        return cve_id in (self._kev_data or {})

    def get_kev_entry(self, cve_id: str) -> dict:
        """Get the full KEV entry for a CVE ID, or empty dict."""
        self._load()
        return (self._kev_data or {}).get(cve_id, {})

    async def query(self, q: CVEQuery) -> SourceResult:
        """Search KEV by product/vendor keyword match.

        For standalone use, searches vendorProject and product fields.
        """
        start = time.monotonic()
        self._load()

        if not self._kev_data:
            return SourceResult(
                source_name=self.name,
                error="KEV data not loaded",
                query_time_ms=0.0,
            )

        records: list[CVERecord] = []
        search_terms = [q.software.lower()]
        if q.vendor:
            search_terms.append(q.vendor.lower())

        for cve_id, entry in self._kev_data.items():
            vendor_project = entry.get("vendorProject", "").lower()
            product = entry.get("product", "").lower()

            matched = False
            for term in search_terms:
                if term in vendor_project or term in product:
                    matched = True
                    break

            if not matched:
                continue

            record = CVERecord(
                cve_id=cve_id,
                description=entry.get("shortDescription", ""),
                severity=_kev_to_severity(entry),
                published=entry.get("dateAdded", ""),
                in_kev=True,
                kev_due_date=entry.get("dueDate", ""),
                exploit_maturity=ExploitMaturity.FUNCTIONAL,
                sources=[self.name],
                references=[
                    entry.get("notes", ""),
                ] if entry.get("notes") else [],
            )
            records.append(record)

            if len(records) >= q.max_results:
                break

        elapsed_ms = (time.monotonic() - start) * 1000
        return SourceResult(
            source_name=self.name,
            records=records,
            query_time_ms=elapsed_ms,
        )

    async def health_check(self) -> bool:
        """KEV is healthy if the data file exists."""
        return self._kev_path.exists()

    def is_configured(self) -> bool:
        return True


def _kev_to_severity(entry: dict) -> str:
    """Derive severity from KEV entry (KEV items are always high+ risk)."""
    # KEV entries are actively exploited, so at minimum high severity
    known_ransomware = entry.get("knownRansomwareCampaignUse", "Unknown")
    if known_ransomware == "Known":
        return "critical"
    return "high"
