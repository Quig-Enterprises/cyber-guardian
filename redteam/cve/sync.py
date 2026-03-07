"""CVE data source synchronization manager."""

import asyncio
import json
import logging
import os
import sqlite3
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# Source URLs
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EXPLOITDB_CSV_URL = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
CVELISTV5_REPO_URL = "https://github.com/CVEProject/cvelistV5.git"

# Default max ages in hours
DEFAULT_KEV_MAX_AGE_HOURS = 168       # 1 week
DEFAULT_EXPLOITDB_MAX_AGE_HOURS = 168  # 1 week
DEFAULT_CVELISTV5_MAX_AGE_HOURS = 24   # 1 day

# SQLite batch size for index building
BATCH_SIZE = 1000


class CVESyncManager:
    """Manages local CVE data source synchronization."""

    def __init__(self, config: dict, data_dir: str = None):
        self._config = config
        cve_config = config.get("cve", {})
        self._data_dir = Path(data_dir or cve_config.get("data_dir", "data/cve"))
        self._sync_config = cve_config.get("sync", {})
        self._metadata_path = self._data_dir / "sync_metadata.json"

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def sync_all(self, force: bool = False) -> None:
        """Sync all local data sources."""
        self._data_dir.mkdir(parents=True, exist_ok=True)
        await self.sync_kev(force)
        await self.sync_exploitdb(force)
        await self.sync_cvelistv5(force)

    async def sync_kev(self, force: bool = False) -> None:
        """Download CISA KEV JSON catalog."""
        max_age = self._sync_config.get("kev_max_age_hours", DEFAULT_KEV_MAX_AGE_HOURS)
        if not force and not self._is_stale("kev", max_age):
            logger.info("KEV data is fresh (max_age=%dh), skipping", max_age)
            return

        dest = self._data_dir / "kev.json"
        logger.info("Downloading KEV catalog from %s", KEV_URL)
        try:
            await self._download_file(KEV_URL, dest)
            self._mark_synced("kev")
            logger.info("KEV catalog saved to %s", dest)
        except Exception as exc:
            logger.error("Failed to download KEV catalog: %s", exc)

    async def sync_exploitdb(self, force: bool = False) -> None:
        """Download ExploitDB files_exploits.csv."""
        max_age = self._sync_config.get(
            "exploitdb_max_age_hours", DEFAULT_EXPLOITDB_MAX_AGE_HOURS
        )
        if not force and not self._is_stale("exploitdb", max_age):
            logger.info("ExploitDB data is fresh (max_age=%dh), skipping", max_age)
            return

        dest = self._data_dir / "files_exploits.csv"
        logger.info("Downloading ExploitDB CSV from %s", EXPLOITDB_CSV_URL)
        try:
            await self._download_file(EXPLOITDB_CSV_URL, dest)
            self._mark_synced("exploitdb")
            logger.info("ExploitDB CSV saved to %s", dest)
        except Exception as exc:
            logger.error("Failed to download ExploitDB CSV: %s", exc)

    async def sync_cvelistv5(self, force: bool = False) -> None:
        """Clone or pull CVEProject/cvelistV5 and rebuild SQLite index."""
        max_age = self._sync_config.get(
            "cvelistv5_max_age_hours", DEFAULT_CVELISTV5_MAX_AGE_HOURS
        )
        if not force and not self._is_stale("cvelistv5", max_age):
            logger.info("cvelistV5 data is fresh (max_age=%dh), skipping", max_age)
            return

        repo_dir = self._data_dir / "cvelistV5"
        try:
            if repo_dir.exists():
                logger.info("Pulling cvelistV5 updates in %s", repo_dir)
                await self._run_git("pull", cwd=str(repo_dir))
            else:
                logger.info("Cloning cvelistV5 repo to %s", repo_dir)
                await self._run_git(
                    "clone", "--depth", "1", CVELISTV5_REPO_URL, str(repo_dir)
                )
        except Exception as exc:
            logger.error("git operation failed for cvelistV5: %s", exc)
            if not repo_dir.exists():
                return  # Nothing to index

        logger.info("Building SQLite index from cvelistV5 JSON files")
        try:
            await asyncio.get_event_loop().run_in_executor(
                None, self._build_sqlite_index
            )
            self._mark_synced("cvelistv5")
            logger.info("cvelistV5 SQLite index built successfully")
        except Exception as exc:
            logger.error("Failed to build cvelistV5 SQLite index: %s", exc)

    def check_freshness(self) -> dict:
        """Return freshness status of each data source."""
        metadata = self._load_metadata()
        result = {}
        sources = {
            "kev": self._sync_config.get("kev_max_age_hours", DEFAULT_KEV_MAX_AGE_HOURS),
            "exploitdb": self._sync_config.get(
                "exploitdb_max_age_hours", DEFAULT_EXPLOITDB_MAX_AGE_HOURS
            ),
            "cvelistv5": self._sync_config.get(
                "cvelistv5_max_age_hours", DEFAULT_CVELISTV5_MAX_AGE_HOURS
            ),
        }
        for source, max_age in sources.items():
            last_sync = metadata.get(source, {}).get("last_sync")
            is_stale = self._is_stale(source, max_age)
            result[source] = {
                "last_sync": last_sync,
                "max_age_hours": max_age,
                "stale": is_stale,
            }
        return result

    # ------------------------------------------------------------------
    # SQLite index builder
    # ------------------------------------------------------------------

    def _build_sqlite_index(self) -> None:
        """Parse cvelistV5 JSON files and build SQLite index.

        Table schema mirrors what CVEListV5Source expects:
            cves(cve_id TEXT PK, published TEXT, modified TEXT, state TEXT,
                 description TEXT, cvss_v31 REAL, vendor TEXT, product TEXT,
                 version_start TEXT, version_end TEXT, json_path TEXT)
            products(vendor TEXT, product TEXT, cve_id TEXT)  -- indexed
        """
        repo_dir = self._data_dir / "cvelistV5"
        cves_dir = repo_dir / "cves"
        if not cves_dir.exists():
            logger.error("cvelistV5 cves/ directory not found: %s", cves_dir)
            return

        db_path = self._data_dir / "index.sqlite"
        tmp_path = db_path.with_suffix(".sqlite.tmp")

        conn = sqlite3.connect(str(tmp_path))
        try:
            self._create_schema(conn)
            total = self._index_cve_files(conn, cves_dir)
            conn.commit()
        finally:
            conn.close()

        # Atomic replace
        tmp_path.replace(db_path)
        logger.info("SQLite index built: %d CVE records at %s", total, db_path)

    @staticmethod
    def _create_schema(conn: sqlite3.Connection) -> None:
        """Create the cves and products tables."""
        conn.executescript("""
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = NORMAL;

            CREATE TABLE IF NOT EXISTS cves (
                cve_id       TEXT PRIMARY KEY,
                published    TEXT,
                modified     TEXT,
                state        TEXT,
                description  TEXT,
                cvss_v31     REAL,
                vendor       TEXT,
                product      TEXT,
                version_start TEXT,
                version_end  TEXT,
                json_path    TEXT
            );

            CREATE TABLE IF NOT EXISTS products (
                vendor   TEXT,
                product  TEXT,
                cve_id   TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_products_vendor_product
                ON products (vendor, product);
        """)

    def _index_cve_files(self, conn: sqlite3.Connection, cves_dir: Path) -> int:
        """Walk the cves/ directory and batch-insert CVE records."""
        cve_batch: list[tuple] = []
        product_batch: list[tuple] = []
        total = 0

        for json_file in cves_dir.rglob("CVE-*.json"):
            try:
                data = json.loads(json_file.read_bytes())
            except (json.JSONDecodeError, OSError) as exc:
                logger.debug("Skipping %s: %s", json_file, exc)
                continue

            parsed = _parse_cve_json(data, str(json_file))
            if parsed is None:
                continue

            cve_row, product_rows = parsed
            cve_batch.append(cve_row)
            product_batch.extend(product_rows)
            total += 1

            if len(cve_batch) >= BATCH_SIZE:
                _flush_batches(conn, cve_batch, product_batch)
                cve_batch.clear()
                product_batch.clear()

        # Flush remainder
        if cve_batch:
            _flush_batches(conn, cve_batch, product_batch)

        return total

    # ------------------------------------------------------------------
    # HTTP download helper
    # ------------------------------------------------------------------

    @staticmethod
    async def _download_file(url: str, dest: Path) -> None:
        """Download url to dest atomically using aiohttp.

        Writes to a temp file first, then renames to avoid leaving a
        partial file on failure.
        """
        try:
            import aiohttp
        except ImportError as exc:
            raise RuntimeError("aiohttp is required for downloads") from exc

        dest.parent.mkdir(parents=True, exist_ok=True)
        tmp_fd, tmp_path = tempfile.mkstemp(dir=dest.parent, prefix=".dl_")
        try:
            os.close(tmp_fd)
            timeout = aiohttp.ClientTimeout(total=300)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(url) as resp:
                    resp.raise_for_status()
                    with open(tmp_path, "wb") as f:
                        async for chunk in resp.content.iter_chunked(65536):
                            f.write(chunk)
            os.replace(tmp_path, dest)
        except Exception:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise

    # ------------------------------------------------------------------
    # Git helper
    # ------------------------------------------------------------------

    @staticmethod
    async def _run_git(*args: str, cwd: Optional[str] = None) -> None:
        """Run a git command asynchronously, raising on non-zero exit."""
        cmd = ["git"] + list(args)
        logger.debug("Running: %s (cwd=%s)", " ".join(cmd), cwd)
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            cwd=cwd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        if proc.returncode != 0:
            err_text = stderr.decode(errors="replace").strip()
            raise RuntimeError(
                f"git {args[0]} failed (exit {proc.returncode}): {err_text}"
            )
        if stdout:
            logger.debug("git stdout: %s", stdout.decode(errors="replace").strip())

    # ------------------------------------------------------------------
    # Metadata persistence
    # ------------------------------------------------------------------

    def _load_metadata(self) -> dict:
        """Load sync metadata from JSON file."""
        if not self._metadata_path.exists():
            return {}
        try:
            return json.loads(self._metadata_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("Could not read sync metadata: %s", exc)
            return {}

    def _save_metadata(self, metadata: dict) -> None:
        """Save sync metadata to JSON file."""
        try:
            self._metadata_path.write_text(
                json.dumps(metadata, indent=2), encoding="utf-8"
            )
        except OSError as exc:
            logger.error("Could not write sync metadata: %s", exc)

    def _mark_synced(self, source_name: str) -> None:
        """Record a successful sync timestamp for source_name."""
        metadata = self._load_metadata()
        metadata.setdefault(source_name, {})["last_sync"] = _utcnow_iso()
        self._save_metadata(metadata)

    def _is_stale(self, source_name: str, max_age_hours: int) -> bool:
        """Return True if source_name needs a refresh.

        A source is considered stale when:
        - It has never been synced, OR
        - Its last sync was more than max_age_hours ago.
        """
        metadata = self._load_metadata()
        last_sync_str = metadata.get(source_name, {}).get("last_sync")
        if not last_sync_str:
            return True
        try:
            last_sync = datetime.fromisoformat(last_sync_str)
            if last_sync.tzinfo is None:
                last_sync = last_sync.replace(tzinfo=timezone.utc)
            now = datetime.now(tz=timezone.utc)
            elapsed_hours = (now - last_sync).total_seconds() / 3600
            return elapsed_hours >= max_age_hours
        except (ValueError, TypeError) as exc:
            logger.warning("Could not parse last_sync for %s: %s", source_name, exc)
            return True


# ------------------------------------------------------------------
# Module-level helpers (pure functions, no self)
# ------------------------------------------------------------------

def _utcnow_iso() -> str:
    """Return current UTC time as an ISO 8601 string."""
    return datetime.now(tz=timezone.utc).isoformat()


def _parse_cve_json(
    data: dict, json_path: str
) -> Optional[tuple[tuple, list[tuple]]]:
    """Extract CVE fields from a CVE JSON 5.0 document.

    Returns (cve_row_tuple, [product_row_tuples]) or None on parse failure.
    """
    try:
        meta = data.get("cveMetadata", {})
        cve_id = meta.get("cveId", "")
        if not cve_id:
            return None

        published = meta.get("datePublished", "")
        modified = meta.get("dateUpdated", "")
        state = meta.get("state", "")

        cna = data.get("containers", {}).get("cna", {})

        # English description
        description = ""
        for desc in cna.get("descriptions", []):
            if desc.get("lang", "").lower().startswith("en"):
                description = desc.get("value", "")
                break
        if not description:
            descs = cna.get("descriptions", [])
            if descs:
                description = descs[0].get("value", "")

        # CVSS v3.1 base score
        cvss_v31: Optional[float] = None
        for metric in cna.get("metrics", []):
            cvss_data = metric.get("cvssV3_1", {})
            score = cvss_data.get("baseScore")
            if score is not None:
                try:
                    cvss_v31 = float(score)
                    break
                except (TypeError, ValueError):
                    pass

        # Affected products and version ranges
        affected = cna.get("affected", [])
        vendor = ""
        product = ""
        version_start = ""
        version_end = ""
        product_rows: list[tuple] = []

        for aff in affected:
            v = (aff.get("vendor") or "").strip()
            p = (aff.get("product") or "").strip()
            if not vendor and v:
                vendor = v
            if not product and p:
                product = p

            # Collect version range from first affected entry with versions
            versions = aff.get("versions", [])
            if versions and not version_start and not version_end:
                first = versions[0]
                version_start = (first.get("version") or "").strip()
                version_end = (
                    first.get("versionEndIncluding")
                    or first.get("lessThanOrEqual")
                    or first.get("lessThan")
                    or ""
                ).strip()

            # Products table row
            if v and p:
                product_rows.append((v, p, cve_id))

        cve_row = (
            cve_id,
            published,
            modified,
            state,
            description,
            cvss_v31,
            vendor,
            product,
            version_start,
            version_end,
            json_path,
        )
        return cve_row, product_rows

    except Exception as exc:
        logger.debug("Failed to parse CVE JSON %s: %s", json_path, exc)
        return None


def _flush_batches(
    conn: sqlite3.Connection,
    cve_batch: list[tuple],
    product_batch: list[tuple],
) -> None:
    """Batch-insert CVE and product rows into the SQLite database."""
    conn.executemany(
        """
        INSERT OR REPLACE INTO cves
            (cve_id, published, modified, state, description,
             cvss_v31, vendor, product, version_start, version_end, json_path)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        cve_batch,
    )
    if product_batch:
        conn.executemany(
            "INSERT INTO products (vendor, product, cve_id) VALUES (?, ?, ?)",
            product_batch,
        )
