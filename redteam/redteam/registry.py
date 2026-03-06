"""Attack module auto-discovery and registration."""

import importlib
import inspect
import pkgutil
import logging
from typing import Optional

from .base import Attack

logger = logging.getLogger(__name__)


class AttackRegistry:
    """Discovers and manages attack modules."""

    def __init__(self):
        self._attacks: dict[str, Attack] = {}

    def discover(self, package_path: str = "redteam.attacks") -> int:
        """Auto-discover attack modules. Returns count of attacks found."""
        count = 0
        package = importlib.import_module(package_path)

        for category_info in pkgutil.iter_modules(package.__path__):
            if not category_info.ispkg:
                continue
            category_name = category_info.name
            category_package = importlib.import_module(f"{package_path}.{category_name}")

            for module_info in pkgutil.iter_modules(category_package.__path__):
                if module_info.name.startswith("_"):
                    continue
                try:
                    module = importlib.import_module(
                        f"{package_path}.{category_name}.{module_info.name}"
                    )
                    for name, obj in inspect.getmembers(module, inspect.isclass):
                        if (
                            issubclass(obj, Attack)
                            and obj is not Attack
                            and not inspect.isabstract(obj)
                        ):
                            instance = obj()
                            key = f"{category_name}.{module_info.name}"
                            self._attacks[key] = instance
                            count += 1
                            logger.debug(f"Registered attack: {key} ({instance.name})")
                except Exception as e:
                    logger.error(
                        f"Failed to load {package_path}.{category_name}.{module_info.name}: {e}"
                    )
        return count

    def get_all(self) -> list[Attack]:
        """Return all registered attacks."""
        return list(self._attacks.values())

    def get_by_category(self, category: str) -> list[Attack]:
        """Return all attacks in a given category."""
        return [a for k, a in self._attacks.items() if k.startswith(f"{category}.")]

    def get_by_name(self, name: str) -> Optional[Attack]:
        """Return a specific attack by its registry key (e.g., 'ai.jailbreak')."""
        return self._attacks.get(name)

    def list_attacks(self) -> list[dict]:
        """List all registered attacks with metadata."""
        return [
            {
                "key": k,
                "name": a.name,
                "category": a.category,
                "severity": a.severity.value,
                "description": a.description,
            }
            for k, a in sorted(self._attacks.items())
        ]
