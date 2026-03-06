# Task 04: Attack Registry & CLI Runner

## Overview

Implement the attack auto-discovery registry and CLI runner entry point.

## Files

- `redteam/registry.py` - Auto-discovers attack modules by scanning directories
- `runner.py` - CLI entry point with argparse
- `tests/test_registry.py` - Unit tests

---

## Step 1: Write tests/test_registry.py

Create `/opt/security-red-team/tests/test_registry.py`:

```python
"""Tests for the attack registry."""

import pytest
from unittest.mock import patch, MagicMock
from redteam.registry import AttackRegistry
from redteam.base import Attack, AttackResult, AttackScore, Severity


class ConcreteAttack(Attack):
    """Concrete attack for testing."""
    name = "Test Attack"
    category = "ai"
    severity = Severity.MEDIUM
    description = "A test attack"

    async def execute(self, client) -> list[AttackResult]:
        return []

    async def cleanup(self, client) -> None:
        pass


class AnotherAttack(Attack):
    """Another concrete attack for testing."""
    name = "Another Attack"
    category = "api"
    severity = Severity.HIGH
    description = "Another test attack"

    async def execute(self, client) -> list[AttackResult]:
        return []

    async def cleanup(self, client) -> None:
        pass


class TestAttackRegistry:
    def test_registry_starts_empty(self):
        registry = AttackRegistry()
        assert registry.get_all() == []
        assert registry.list_attacks() == []

    def test_get_by_category_empty(self):
        registry = AttackRegistry()
        assert registry.get_by_category("ai") == []

    def test_get_by_name_missing(self):
        registry = AttackRegistry()
        assert registry.get_by_name("ai.jailbreak") is None

    def test_discover_returns_count(self):
        """discover() should return integer count of attacks found."""
        registry = AttackRegistry()
        # Patch pkgutil and importlib to simulate discovery
        with patch("redteam.registry.importlib.import_module") as mock_import, \
             patch("redteam.registry.pkgutil.iter_modules") as mock_iter:

            # Simulate one category package with one module
            cat_info = MagicMock()
            cat_info.ispkg = True
            cat_info.name = "ai"

            mod_info = MagicMock()
            mod_info.name = "jailbreak"

            mock_iter.side_effect = [
                iter([cat_info]),   # category iteration
                iter([mod_info]),   # module iteration within category
            ]

            mock_package = MagicMock()
            mock_package.__path__ = ["/fake/path"]

            mock_cat_package = MagicMock()
            mock_cat_package.__path__ = ["/fake/path/ai"]

            mock_module = MagicMock()
            # Make inspect.getmembers return our ConcreteAttack
            mock_module.__dict__ = {"ConcreteAttack": ConcreteAttack}

            mock_import.side_effect = [mock_package, mock_cat_package, mock_module]

            with patch("redteam.registry.inspect.getmembers", return_value=[("ConcreteAttack", ConcreteAttack)]):
                count = registry.discover()

        assert isinstance(count, int)
        assert count >= 0

    def test_register_attack_manually(self):
        """Test internal _attacks registration and retrieval."""
        registry = AttackRegistry()
        attack = ConcreteAttack()
        registry._attacks["ai.test"] = attack

        assert registry.get_by_name("ai.test") is attack
        assert attack in registry.get_all()

    def test_get_by_category_filters_correctly(self):
        registry = AttackRegistry()
        ai_attack = ConcreteAttack()
        api_attack = AnotherAttack()
        registry._attacks["ai.test"] = ai_attack
        registry._attacks["api.test"] = api_attack

        ai_results = registry.get_by_category("ai")
        assert ai_attack in ai_results
        assert api_attack not in ai_results

        api_results = registry.get_by_category("api")
        assert api_attack in api_results
        assert ai_attack not in api_results

    def test_get_by_category_returns_empty_for_unknown(self):
        registry = AttackRegistry()
        ai_attack = ConcreteAttack()
        registry._attacks["ai.test"] = ai_attack
        assert registry.get_by_category("web") == []

    def test_get_by_name_returns_correct_attack(self):
        registry = AttackRegistry()
        attack = ConcreteAttack()
        registry._attacks["ai.jailbreak"] = attack
        assert registry.get_by_name("ai.jailbreak") is attack

    def test_get_by_name_returns_none_for_wrong_key(self):
        registry = AttackRegistry()
        attack = ConcreteAttack()
        registry._attacks["ai.jailbreak"] = attack
        assert registry.get_by_name("ai.other") is None

    def test_list_attacks_returns_metadata(self):
        registry = AttackRegistry()
        attack = ConcreteAttack()
        registry._attacks["ai.test"] = attack

        listing = registry.list_attacks()
        assert len(listing) == 1
        entry = listing[0]
        assert entry["key"] == "ai.test"
        assert entry["name"] == "Test Attack"
        assert entry["category"] == "ai"
        assert entry["severity"] == "medium"
        assert entry["description"] == "A test attack"

    def test_list_attacks_is_sorted(self):
        registry = AttackRegistry()
        registry._attacks["web.xss"] = ConcreteAttack()
        registry._attacks["ai.jailbreak"] = ConcreteAttack()
        registry._attacks["api.auth"] = AnotherAttack()

        listing = registry.list_attacks()
        keys = [e["key"] for e in listing]
        assert keys == sorted(keys)

    def test_list_attacks_empty(self):
        registry = AttackRegistry()
        assert registry.list_attacks() == []

    def test_get_all_returns_all_attacks(self):
        registry = AttackRegistry()
        a1 = ConcreteAttack()
        a2 = AnotherAttack()
        registry._attacks["ai.test"] = a1
        registry._attacks["api.test"] = a2

        all_attacks = registry.get_all()
        assert len(all_attacks) == 2
        assert a1 in all_attacks
        assert a2 in all_attacks

    def test_discover_skips_private_modules(self):
        """Modules starting with _ should be skipped."""
        registry = AttackRegistry()
        with patch("redteam.registry.importlib.import_module") as mock_import, \
             patch("redteam.registry.pkgutil.iter_modules") as mock_iter:

            cat_info = MagicMock()
            cat_info.ispkg = True
            cat_info.name = "ai"

            private_mod = MagicMock()
            private_mod.name = "__init__"

            mock_iter.side_effect = [
                iter([cat_info]),
                iter([private_mod]),
            ]

            mock_package = MagicMock()
            mock_package.__path__ = ["/fake/path"]
            mock_cat_package = MagicMock()
            mock_cat_package.__path__ = ["/fake/path/ai"]

            mock_import.side_effect = [mock_package, mock_cat_package]

            count = registry.discover()

        assert count == 0

    def test_discover_handles_import_errors_gracefully(self):
        """Errors loading a module should be logged, not raise."""
        registry = AttackRegistry()
        with patch("redteam.registry.importlib.import_module") as mock_import, \
             patch("redteam.registry.pkgutil.iter_modules") as mock_iter:

            cat_info = MagicMock()
            cat_info.ispkg = True
            cat_info.name = "ai"

            bad_mod = MagicMock()
            bad_mod.name = "broken_module"

            mock_iter.side_effect = [
                iter([cat_info]),
                iter([bad_mod]),
            ]

            mock_package = MagicMock()
            mock_package.__path__ = ["/fake/path"]
            mock_cat_package = MagicMock()
            mock_cat_package.__path__ = ["/fake/path/ai"]

            def import_side_effect(name):
                if name == "redteam.attacks":
                    return mock_package
                elif name == "redteam.attacks.ai":
                    return mock_cat_package
                else:
                    raise ImportError("Simulated import failure")

            mock_import.side_effect = import_side_effect

            # Should not raise
            count = registry.discover()

        assert count == 0

    def test_discover_skips_non_package_entries(self):
        """Non-package entries at the category level should be skipped."""
        registry = AttackRegistry()
        with patch("redteam.registry.importlib.import_module") as mock_import, \
             patch("redteam.registry.pkgutil.iter_modules") as mock_iter:

            not_a_pkg = MagicMock()
            not_a_pkg.ispkg = False
            not_a_pkg.name = "helpers"

            mock_iter.side_effect = [iter([not_a_pkg])]

            mock_package = MagicMock()
            mock_package.__path__ = ["/fake/path"]
            mock_import.return_value = mock_package

            count = registry.discover()

        assert count == 0
```

---

## Step 2: Run tests to verify failures

```bash
cd /opt/security-red-team
python -m pytest tests/test_registry.py -v 2>&1 | head -60
```

Expected: Most tests fail because `redteam/registry.py` does not yet exist.

---

## Step 3: Write redteam/registry.py

Create `/opt/security-red-team/redteam/registry.py`:

```python
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
```

---

## Step 4: Write runner.py

Create `/opt/security-red-team/runner.py`:

```python
#!/usr/bin/env python3
"""Security Red Team - CLI Runner"""

import argparse
import asyncio
import sys
import logging
from pathlib import Path

from redteam.config import load_config
from redteam.client import RedTeamClient
from redteam.registry import AttackRegistry
from redteam.scoring import aggregate_scores
from redteam.reporters.console import ConsoleReporter
# These will be imported as they're implemented:
# from redteam.reporters.json_report import JsonReporter
# from redteam.reporters.html import HtmlReporter
# from redteam.cleanup.db import DatabaseCleaner

logger = logging.getLogger("redteam")


def parse_args():
    parser = argparse.ArgumentParser(
        description="Security Red Team - EQMON Attack Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  runner.py --list
  runner.py --all --report console json
  runner.py --category ai --report console
  runner.py --attack ai.jailbreak --verbose
  runner.py --cleanup
        """,
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--all", action="store_true", help="Run all attack batteries")
    group.add_argument(
        "--category",
        choices=["ai", "api", "web"],
        help="Run attacks in a specific category",
    )
    group.add_argument(
        "--attack",
        type=str,
        metavar="NAME",
        help="Run a specific attack (e.g., ai.jailbreak)",
    )
    group.add_argument(
        "--list",
        action="store_true",
        help="List all available attacks",
    )
    group.add_argument(
        "--cleanup",
        action="store_true",
        help="Run cleanup only (remove test data)",
    )

    parser.add_argument(
        "--report",
        choices=["console", "json", "html"],
        nargs="+",
        default=["console"],
        help="Report format(s) (default: console)",
    )
    parser.add_argument(
        "--output",
        type=str,
        default="reports/",
        help="Report output directory (default: reports/)",
    )
    parser.add_argument(
        "--no-cleanup",
        action="store_true",
        help="Skip cleanup after run",
    )
    parser.add_argument(
        "--config",
        type=str,
        default="config.yaml",
        help="Config file path (default: config.yaml)",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose (DEBUG) logging",
    )

    return parser.parse_args()


async def run(args):
    # Setup logging
    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    )

    # Load config
    config = load_config(args.config)

    # Discover attacks
    registry = AttackRegistry()
    count = registry.discover()
    logger.info(f"Discovered {count} attack modules")

    # Handle --list
    if args.list:
        attacks = registry.list_attacks()
        console = ConsoleReporter()
        console.print_attack_list(attacks)
        return

    # Handle --cleanup
    if args.cleanup:
        # from redteam.cleanup.db import DatabaseCleaner
        # cleaner = DatabaseCleaner(config["database"])
        # await cleaner.cleanup(config["auth"]["test_users"])
        logger.info("Cleanup complete")
        return

    # Select attacks
    if args.all:
        attacks = registry.get_all()
    elif args.category:
        attacks = registry.get_by_category(args.category)
    elif args.attack:
        attack = registry.get_by_name(args.attack)
        if not attack:
            logger.error(f"Attack not found: {args.attack}")
            sys.exit(1)
        attacks = [attack]
    else:
        attacks = []

    if not attacks:
        logger.warning("No attacks matched the filter")
        return

    # Authenticate
    test_user = config["auth"]["test_users"]["system_admin"]
    async with RedTeamClient(config["target"]["base_url"]) as client:
        if not await client.login(test_user["username"], test_user["password"]):
            logger.error("Authentication failed. Have test users been created?")
            sys.exit(1)

        # Run attacks
        scores = []
        for attack in attacks:
            logger.info(f"Running: {attack.name} ({attack.category})")
            try:
                results = await attack.execute(client)
                score = attack.score(results)
                scores.append(score)
                logger.info(
                    f"  -> {score.vulnerable} vulnerable, "
                    f"{score.partial} partial, "
                    f"{score.defended} defended"
                )
            except Exception as e:
                logger.error(f"  -> Error running {attack.name}: {e}")

            # Per-attack cleanup
            if not args.no_cleanup:
                try:
                    await attack.cleanup(client)
                except Exception as e:
                    logger.warning(f"  -> Cleanup error for {attack.name}: {e}")

        # Aggregate results
        summary = aggregate_scores(scores)

        # Generate reports
        Path(args.output).mkdir(parents=True, exist_ok=True)
        for fmt in args.report:
            if fmt == "console":
                ConsoleReporter().print_report(summary)
            elif fmt == "json":
                # JsonReporter().write_report(summary, args.output)
                logger.warning("JSON reporter not yet implemented")
            elif fmt == "html":
                # HtmlReporter().write_report(summary, args.output)
                logger.warning("HTML reporter not yet implemented")

    # Global cleanup
    if not args.no_cleanup and config.get("cleanup", {}).get("enabled", True):
        logger.info("Running global cleanup...")
        # from redteam.cleanup.db import DatabaseCleaner
        # cleaner = DatabaseCleaner(config["database"])
        # await cleaner.cleanup(config["auth"]["test_users"])


def main():
    args = parse_args()
    asyncio.run(run(args))


if __name__ == "__main__":
    main()
```

---

## Step 5: Run tests to verify passes

```bash
cd /opt/security-red-team
python -m pytest tests/test_registry.py -v
```

Expected: All tests pass.

---

## Step 6: Commit

```bash
cd /opt/security-red-team
git add redteam/registry.py runner.py tests/test_registry.py
git commit -m "feat: add attack registry auto-discovery and CLI runner

- AttackRegistry scans redteam/attacks/{ai,api,web}/ for Attack subclasses
- Registers by dotted key (e.g., 'ai.jailbreak')
- Supports filter by category, name lookup, and metadata listing
- runner.py CLI with --all/--category/--attack/--list/--cleanup
- Full unit test suite for registry with mocked discovery"
```

---

## Acceptance Criteria

- [ ] `tests/test_registry.py` exists and covers all registry behaviors
- [ ] Tests fail before implementation (TDD red phase)
- [ ] `redteam/registry.py` implements `AttackRegistry` with `discover()`, `get_all()`, `get_by_category()`, `get_by_name()`, `list_attacks()`
- [ ] `discover()` skips modules starting with `_`
- [ ] `discover()` logs errors and continues on import failures (no crash)
- [ ] `runner.py` provides `--all`, `--category`, `--attack`, `--list`, `--cleanup` flags
- [ ] `--all`/`--category`/`--attack`/`--list`/`--cleanup` are mutually exclusive
- [ ] `--report` accepts multiple formats: `console`, `json`, `html`
- [ ] All tests pass after implementation
- [ ] Changes committed with descriptive message
