"""SQLite-indexed cvelistV5 local reader."""

import logging
import re
import sqlite3
import time
from pathlib import Path
from typing import Optional

from redteam.cve.models import CVERecord, CVEQuery, ExploitMaturity
from redteam.cve.sources.base import AsyncCVESource, SourceResult

logger = logging.getLogger(__name__)


class CVEListV5Source(AsyncCVESource):
    """Local cvelistV5 reader backed by a SQLite index.

    The SQLite database is built by CVESyncManager._build_sqlite_index()
    from the cvelistV5 JSON repository. This source queries that index
    for fast product+version lookups across 250K+ CVEs.

    Tables:
        cves: cve_id TEXT PK, published TEXT, modified TEXT, state TEXT,
              description TEXT, cvss_v31 REAL, vendor TEXT, product TEXT,
              version_start TEXT, version_end TEXT, json_path TEXT
        products: vendor TEXT, product TEXT, cve_id TEXT
                  (indexed on vendor, product)
    """

    name = "cvelistv5"
    requires_auth = False
    is_local = True

    def __init__(self, config: dict, rate_limiter=None, cache=None):
        super().__init__(config, rate_limiter, cache)
        cve_cfg = config.get("cve", {})
        self._data_dir = Path(cve_cfg.get("data_dir", "data/cve"))
        self._db_path = self._data_dir / "index.sqlite"
        self._conn: Optional[sqlite3.Connection] = None

    def _get_conn(self) -> Optional[sqlite3.Connection]:
        """Get or create a SQLite connection."""
        if self._conn is not None:
            return self._conn
        if not self._db_path.exists():
            logger.warning("cvelistV5 index not found: %s", self._db_path)
            return None
        try:
            self._conn = sqlite3.connect(
                str(self._db_path), check_same_thread=False
            )
            self._conn.row_factory = sqlite3.Row
            return self._conn
        except sqlite3.Error as exc:
            logger.error("Failed to open cvelistV5 index: %s", exc)
            return None

    async def query(self, q: CVEQuery) -> SourceResult:
        """Search CVEs by vendor+product or keyword in description."""
        start = time.monotonic()
        conn = self._get_conn()
        if conn is None:
            return SourceResult(
                source_name=self.name,
                error="cvelistV5 SQLite index not available",
                query_time_ms=0.0,
            )

        try:
            records = self._search(conn, q)
        except sqlite3.Error as exc:
            elapsed_ms = (time.monotonic() - start) * 1000
            return SourceResult(
                source_name=self.name,
                error=f"SQLite query error: {exc}",
                query_time_ms=elapsed_ms,
            )

        elapsed_ms = (time.monotonic() - start) * 1000
        return SourceResult(
            source_name=self.name,
            records=records,
            query_time_ms=elapsed_ms,
        )

    def _search(self, conn: sqlite3.Connection, q: CVEQuery) -> list[CVERecord]:
        """Execute the actual SQLite search."""
        records: list[CVERecord] = []
        cursor = conn.cursor()

        # Strategy 1: Search by vendor + product via the products table
        if q.vendor or q.software:
            cve_ids = self._search_by_product(cursor, q)
        else:
            cve_ids = []

        # Strategy 2: If no product matches, fall back to keyword in description
        if not cve_ids:
            cve_ids = self._search_by_keyword(cursor, q)

        if not cve_ids:
            return records

        # Fetch full CVE rows
        placeholders = ",".join("?" for _ in cve_ids)
        sql = f"SELECT * FROM cves WHERE cve_id IN ({placeholders})"
        if not q.include_rejected:
            sql += " AND (state IS NULL OR state != 'REJECTED')"
        sql += " ORDER BY cvss_v31 DESC NULLS LAST"
        sql += f" LIMIT {q.max_results}"

        cursor.execute(sql, cve_ids)
        for row in cursor.fetchall():
            cvss = row["cvss_v31"]
            if q.min_cvss > 0 and (cvss is None or cvss < q.min_cvss):
                continue

            # Version matching
            if q.version and not self._version_matches(
                q.version, row["version_start"], row["version_end"]
            ):
                continue

            severity = _cvss_to_severity(cvss)
            record = CVERecord(
                cve_id=row["cve_id"],
                description=row["description"] or "",
                cvss_v31_score=cvss,
                severity=severity,
                published=row["published"] or "",
                modified=row["modified"] or "",
                affected_versions=self._format_version_range(
                    row["version_start"], row["version_end"]
                ),
                sources=[self.name],
            )
            records.append(record)

        return records

    def _search_by_product(
        self, cursor: sqlite3.Cursor, q: CVEQuery
    ) -> list[str]:
        """Search the products table for matching vendor/product."""
        conditions = []
        params: list[str] = []

        if q.vendor:
            conditions.append("LOWER(vendor) LIKE ?")
            params.append(f"%{q.vendor.lower()}%")

        if q.software:
            conditions.append("LOWER(product) LIKE ?")
            params.append(f"%{q.software.lower()}%")

        if not conditions:
            return []

        where = " AND ".join(conditions)
        sql = f"SELECT DISTINCT cve_id FROM products WHERE {where} LIMIT {q.max_results * 2}"
        cursor.execute(sql, params)
        return [row[0] for row in cursor.fetchall()]

    def _search_by_keyword(
        self, cursor: sqlite3.Cursor, q: CVEQuery
    ) -> list[str]:
        """Fall back to keyword search in the description field."""
        if not q.software:
            return []
        sql = (
            "SELECT cve_id FROM cves WHERE LOWER(description) LIKE ?"
            " LIMIT ?"
        )
        cursor.execute(sql, (f"%{q.software.lower()}%", q.max_results * 2))
        return [row[0] for row in cursor.fetchall()]

    @staticmethod
    def _version_matches(
        query_version: str,
        version_start: Optional[str],
        version_end: Optional[str],
    ) -> bool:
        """Check if query_version falls within [version_start, version_end].

        Uses simple tuple-based version comparison. Returns True if no
        version constraints are set.
        """
        if not version_start and not version_end:
            return True

        try:
            qv = _parse_version(query_version)
        except ValueError:
            return True  # Can't parse, include it

        if version_start:
            try:
                sv = _parse_version(version_start)
                if qv < sv:
                    return False
            except ValueError:
                pass

        if version_end:
            try:
                ev = _parse_version(version_end)
                if qv > ev:
                    return False
            except ValueError:
                pass

        return True

    @staticmethod
    def _format_version_range(
        version_start: Optional[str], version_end: Optional[str]
    ) -> str:
        """Format version range as a human-readable string."""
        if version_start and version_end:
            return f">= {version_start}, <= {version_end}"
        elif version_end:
            return f"<= {version_end}"
        elif version_start:
            return f">= {version_start}"
        return ""

    async def health_check(self) -> bool:
        """Check if the SQLite index exists."""
        return self._db_path.exists()

    def is_configured(self) -> bool:
        return True

    def close(self) -> None:
        """Close the SQLite connection."""
        if self._conn:
            self._conn.close()
            self._conn = None


def _parse_version(version_str: str) -> tuple:
    """Parse a version string into a comparable tuple of integers."""
    # Strip common prefixes
    version_str = version_str.lstrip("vV")
    # Extract numeric parts
    parts = re.split(r"[.\-_]", version_str)
    result = []
    for part in parts:
        match = re.match(r"(\d+)", part)
        if match:
            result.append(int(match.group(1)))
        else:
            break
    if not result:
        raise ValueError(f"Cannot parse version: {version_str}")
    return tuple(result)


def _cvss_to_severity(score: Optional[float]) -> str:
    """Convert a CVSS v3.1 score to a severity string."""
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
    return "unknown"
