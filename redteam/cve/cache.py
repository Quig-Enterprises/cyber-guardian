"""Two-tier async cache: in-memory LRU + disk JSON files."""

import asyncio
import hashlib
import json
import logging
import time
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)


class CVECacheEncoder(json.JSONEncoder):
    """Custom JSON encoder for CVERecord dataclasses and enums."""

    def default(self, obj):
        if is_dataclass(obj):
            # Convert dataclass to dict, handling nested objects
            result = {}
            for key, value in asdict(obj).items():
                if hasattr(value, 'value'):  # Enum
                    result[key] = value.value if hasattr(value.value, '__str__') else str(value)
                else:
                    result[key] = value
            result['__dataclass__'] = obj.__class__.__name__
            return result
        elif hasattr(obj, 'value'):  # Enum
            return obj.value
        return super().default(obj)


def cve_cache_decoder(dct):
    """JSON decoder hook to reconstruct CVERecord and ExploitRef objects."""
    if '__dataclass__' in dct:
        from redteam.cve.models import CVERecord, ExploitRef, ExploitMaturity

        classname = dct.pop('__dataclass__')

        if classname == 'CVERecord':
            # Reconstruct ExploitMaturity enum
            if 'exploit_maturity' in dct and isinstance(dct['exploit_maturity'], str):
                dct['exploit_maturity'] = ExploitMaturity(dct['exploit_maturity'])

            # Reconstruct ExploitRef objects
            if 'exploit_refs' in dct and isinstance(dct['exploit_refs'], list):
                dct['exploit_refs'] = [
                    ExploitRef(**ref) if isinstance(ref, dict) else ref
                    for ref in dct['exploit_refs']
                ]

            return CVERecord(**dct)
        elif classname == 'ExploitRef':
            return ExploitRef(**dct)

    return dct


class CVECache:
    """Two-tier cache with memory (LRU) and disk (JSON) layers.

    Memory tier: dict with TTL, max_entries with LRU eviction.
    Disk tier: JSON files in data_dir/cache/, TTL-based expiry.

    Args:
        data_dir: Base directory for disk cache files.
        config: Configuration dict (from config.cve.cache).
    """

    def __init__(self, data_dir: str = "data/cve", config: Optional[dict] = None):
        cfg = config or {}
        self._max_entries = cfg.get("memory_max_entries", 500)
        self._memory_ttl = cfg.get("memory_ttl_seconds", 1800)  # 30 min
        self._disk_ttl = cfg.get("disk_ttl_seconds", 86400)  # 24 hours
        self._cache_dir = Path(data_dir) / "cache"
        self._memory: dict[str, dict[str, Any]] = {}  # key -> {"value": ..., "ts": ...}
        self._access_order: list[str] = []  # LRU tracking
        self._disk_lock = asyncio.Lock()

    @staticmethod
    def make_key(source_name: str, query_params: str) -> str:
        """Build a cache key from source name and query parameters."""
        query_hash = hashlib.sha256(query_params.encode("utf-8")).hexdigest()[:16]
        return f"{source_name}:{query_hash}"

    async def get(self, key: str) -> Optional[Any]:
        """Retrieve a value from cache. Checks memory first, then disk."""
        # Check memory
        entry = self._memory.get(key)
        if entry is not None:
            if time.time() - entry["ts"] < self._memory_ttl:
                # Move to end of access order (most recently used)
                if key in self._access_order:
                    self._access_order.remove(key)
                self._access_order.append(key)
                return entry["value"]
            else:
                # Expired
                del self._memory[key]
                if key in self._access_order:
                    self._access_order.remove(key)

        # Check disk
        disk_path = self._disk_path(key)
        if disk_path.exists():
            try:
                async with self._disk_lock:
                    data = json.loads(
                        disk_path.read_text(encoding="utf-8"),
                        object_hook=cve_cache_decoder
                    )
                if time.time() - data.get("ts", 0) < self._disk_ttl:
                    value = data["value"]
                    # Promote to memory
                    self._memory_put(key, value)
                    return value
                else:
                    # Expired disk entry
                    async with self._disk_lock:
                        disk_path.unlink(missing_ok=True)
            except (json.JSONDecodeError, KeyError, OSError) as exc:
                logger.debug("Disk cache read error for %s: %s", key, exc)

        return None

    async def set(self, key: str, value: Any) -> None:
        """Store a value in both memory and disk cache."""
        self._memory_put(key, value)

        # Write to disk
        disk_path = self._disk_path(key)
        try:
            async with self._disk_lock:
                disk_path.parent.mkdir(parents=True, exist_ok=True)
                data = {"value": value, "ts": time.time()}
                disk_path.write_text(
                    json.dumps(data, cls=CVECacheEncoder), encoding="utf-8"
                )
        except OSError as exc:
            logger.debug("Disk cache write error for %s: %s", key, exc)

    async def clear(self) -> None:
        """Clear both memory and disk caches."""
        self._memory.clear()
        self._access_order.clear()
        async with self._disk_lock:
            if self._cache_dir.exists():
                for f in self._cache_dir.glob("*.json"):
                    try:
                        f.unlink()
                    except OSError:
                        pass

    def _memory_put(self, key: str, value: Any) -> None:
        """Insert into memory cache with LRU eviction."""
        if key in self._memory:
            if key in self._access_order:
                self._access_order.remove(key)
        elif len(self._memory) >= self._max_entries:
            # Evict least recently used
            if self._access_order:
                evict_key = self._access_order.pop(0)
                self._memory.pop(evict_key, None)
        self._memory[key] = {"value": value, "ts": time.time()}
        self._access_order.append(key)

    def _disk_path(self, key: str) -> Path:
        """Get the disk file path for a cache key."""
        # Sanitize key for filesystem
        safe_key = key.replace(":", "_").replace("/", "_")
        return self._cache_dir / f"{safe_key}.json"
