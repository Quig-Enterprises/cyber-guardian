"""Tests for the attack registry."""

import pytest
from unittest.mock import patch, MagicMock
from redteam.registry import AttackRegistry
from redteam.base import Attack, AttackResult, Score as AttackScore, Severity


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
        """discover() should return integer count of registered attacks."""
        registry = AttackRegistry()
        count = registry.discover()
        assert isinstance(count, int)
        assert count == 117

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
