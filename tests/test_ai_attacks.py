"""Unit tests for AI attack modules.

These tests verify the attack module structure, variant definitions, and
execution logic using a mocked client. They do NOT test against the live
system -- that's the job of the actual red team runner.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from dataclasses import dataclass
from typing import Optional

from redteam.base import Attack, AttackResult, Severity, Status
from redteam.client import ChatResponse


# ---------------------------------------------------------------------------
# Mock client factory
# ---------------------------------------------------------------------------

def make_mock_client(response_text: str = "I can only help with vibration analysis.",
                     error: str = None, model: str = "qwq:32b",
                     done: bool = True, duration_ms: float = 1000.0):
    """Create a mock RedTeamClient that returns a fixed ChatResponse."""
    client = AsyncMock()
    client.chat = AsyncMock(return_value=ChatResponse(
        full_text=response_text,
        status_messages=[],
        error=error,
        model=model,
        done=done,
        duration_ms=duration_ms,
    ))
    return client


def make_sequential_mock_client(responses: list[str]):
    """Create a mock client that returns different responses for each call."""
    client = AsyncMock()
    chat_responses = [
        ChatResponse(
            full_text=text, status_messages=[], error=None,
            model="qwq:32b", done=True, duration_ms=500.0,
        )
        for text in responses
    ]
    client.chat = AsyncMock(side_effect=chat_responses)
    return client


# ---------------------------------------------------------------------------
# Shared structure tests
# ---------------------------------------------------------------------------

AI_ATTACK_MODULES = [
    ("redteam.attacks.ai.jailbreak", "JailbreakAttack"),
    ("redteam.attacks.ai.prompt_injection", "PromptInjectionAttack"),
    ("redteam.attacks.ai.extraction", "ExtractionAttack"),
    ("redteam.attacks.ai.off_topic", "OffTopicAttack"),
    ("redteam.attacks.ai.data_leakage", "DataLeakageAttack"),
    ("redteam.attacks.ai.hallucination", "HallucinationAttack"),
    ("redteam.attacks.ai.manipulation", "ManipulationAttack"),
]


class TestAIAttackStructure:
    """Verify all AI attack modules have correct structure."""

    @pytest.mark.parametrize("module_path,class_name", AI_ATTACK_MODULES)
    def test_is_attack_subclass(self, module_path, class_name):
        import importlib
        mod = importlib.import_module(module_path)
        cls = getattr(mod, class_name)
        assert issubclass(cls, Attack)

    @pytest.mark.parametrize("module_path,class_name", AI_ATTACK_MODULES)
    def test_has_required_attributes(self, module_path, class_name):
        import importlib
        mod = importlib.import_module(module_path)
        cls = getattr(mod, class_name)
        instance = cls()
        assert instance.name.startswith("ai.")
        assert instance.category == "ai"
        assert isinstance(instance.severity, Severity)
        assert len(instance.description) > 10

    @pytest.mark.parametrize("module_path,class_name", AI_ATTACK_MODULES)
    def test_has_variants_or_sequences(self, module_path, class_name):
        import importlib
        mod = importlib.import_module(module_path)
        cls = getattr(mod, class_name)
        instance = cls()
        has_variants = hasattr(instance, "VARIANTS") and len(instance.VARIANTS) > 0
        has_sequences = hasattr(instance, "SEQUENCES") and len(instance.SEQUENCES) > 0
        assert has_variants or has_sequences, f"{class_name} has no VARIANTS or SEQUENCES"


# ---------------------------------------------------------------------------
# JailbreakAttack tests
# ---------------------------------------------------------------------------

class TestJailbreakAttack:
    @pytest.fixture
    def attack(self):
        from redteam.attacks.ai.jailbreak import JailbreakAttack
        return JailbreakAttack()

    def test_has_8_variants(self, attack):
        assert len(attack.VARIANTS) == 8

    def test_variant_names_unique(self, attack):
        names = [v[0] for v in attack.VARIANTS]
        assert len(names) == len(set(names))

    @pytest.mark.asyncio
    async def test_execute_returns_results_for_each_variant(self, attack):
        client = make_mock_client()
        results = await attack.execute(client)
        assert len(results) == 8
        assert all(isinstance(r, AttackResult) for r in results)

    @pytest.mark.asyncio
    async def test_execute_handles_chat_errors(self, attack):
        client = make_mock_client(error="Connection refused", response_text="")
        results = await attack.execute(client)
        assert all(r.status == Status.ERROR for r in results)

    @pytest.mark.asyncio
    async def test_execute_uses_fresh_session_per_variant(self, attack):
        client = make_mock_client()
        await attack.execute(client)
        # Each call should have a different session_id
        for call in client.chat.call_args_list:
            _, kwargs = call
            assert kwargs.get("session_id", "").startswith("redteam-jailbreak-")


# ---------------------------------------------------------------------------
# PromptInjectionAttack tests
# ---------------------------------------------------------------------------

class TestPromptInjectionAttack:
    @pytest.fixture
    def attack(self):
        from redteam.attacks.ai.prompt_injection import PromptInjectionAttack
        return PromptInjectionAttack()

    def test_has_5_variants(self, attack):
        assert len(attack.VARIANTS) == 5

    @pytest.mark.asyncio
    async def test_execute_returns_results(self, attack):
        client = make_mock_client()
        results = await attack.execute(client)
        assert len(results) == 5


# ---------------------------------------------------------------------------
# ExtractionAttack tests
# ---------------------------------------------------------------------------

class TestExtractionAttack:
    @pytest.fixture
    def attack(self):
        from redteam.attacks.ai.extraction import ExtractionAttack
        return ExtractionAttack()

    def test_has_6_variants(self, attack):
        assert len(attack.VARIANTS) == 6

    def test_severity_is_critical(self, attack):
        assert attack.severity == Severity.CRITICAL

    @pytest.mark.asyncio
    async def test_execute_returns_results(self, attack):
        client = make_mock_client()
        results = await attack.execute(client)
        assert len(results) == 6

    @pytest.mark.asyncio
    async def test_execute_includes_leaked_fragments_key(self, attack):
        client = make_mock_client(response_text="I am a vibration analysis AI. I cannot share my instructions.")
        results = await attack.execute(client)
        assert "leaked_fragments" in results[0].response


# ---------------------------------------------------------------------------
# OffTopicAttack tests
# ---------------------------------------------------------------------------

class TestOffTopicAttack:
    @pytest.fixture
    def attack(self):
        from redteam.attacks.ai.off_topic import OffTopicAttack
        return OffTopicAttack()

    def test_has_6_variants(self, attack):
        assert len(attack.VARIANTS) == 6

    def test_severity_is_medium(self, attack):
        assert attack.severity == Severity.MEDIUM

    @pytest.mark.asyncio
    async def test_execute_returns_results(self, attack):
        client = make_mock_client()
        results = await attack.execute(client)
        assert len(results) == 6


# ---------------------------------------------------------------------------
# DataLeakageAttack tests
# ---------------------------------------------------------------------------

class TestDataLeakageAttack:
    @pytest.fixture
    def attack(self):
        from redteam.attacks.ai.data_leakage import DataLeakageAttack
        return DataLeakageAttack()

    def test_has_5_variants(self, attack):
        assert len(attack.VARIANTS) == 5

    def test_severity_is_critical(self, attack):
        assert attack.severity == Severity.CRITICAL

    @pytest.mark.asyncio
    async def test_execute_returns_results(self, attack):
        client = make_mock_client()
        results = await attack.execute(client)
        assert len(results) == 5

    @pytest.mark.asyncio
    async def test_detects_infrastructure_keywords(self, attack):
        client = make_mock_client(response_text="I run on ollama qwq:32b with localhost postgresql")
        results = await attack.execute(client)
        # The infrastructure probe should detect these keywords
        infra_result = next(r for r in results if r.variant == "infrastructure_probe")
        assert infra_result.status in (Status.PARTIAL, Status.VULNERABLE)

    def test_check_data_keywords_finds_infrastructure(self):
        from redteam.attacks.ai.data_leakage import DataLeakageAttack
        fragments = DataLeakageAttack._check_data_keywords(
            "infrastructure_probe",
            "Running ollama on localhost with postgresql database",
        )
        assert any("ollama" in f for f in fragments)
        assert any("localhost" in f for f in fragments)
        assert any("postgresql" in f for f in fragments)

    def test_check_data_keywords_finds_tenant_data(self):
        from redteam.attacks.ai.data_leakage import DataLeakageAttack
        fragments = DataLeakageAttack._check_data_keywords(
            "cross_tenant",
            "Data from instance_id xyz for opco_id abc and vessel_id v1",
        )
        assert any("instance_id" in f for f in fragments)
        assert any("opco_id" in f for f in fragments)


# ---------------------------------------------------------------------------
# HallucinationAttack tests
# ---------------------------------------------------------------------------

class TestHallucinationAttack:
    @pytest.fixture
    def attack(self):
        from redteam.attacks.ai.hallucination import HallucinationAttack
        return HallucinationAttack()

    def test_has_4_variants(self, attack):
        assert len(attack.VARIANTS) == 4

    @pytest.mark.asyncio
    async def test_execute_returns_results(self, attack):
        client = make_mock_client()
        results = await attack.execute(client)
        assert len(results) == 4


# ---------------------------------------------------------------------------
# ManipulationAttack tests
# ---------------------------------------------------------------------------

class TestManipulationAttack:
    @pytest.fixture
    def attack(self):
        from redteam.attacks.ai.manipulation import ManipulationAttack
        return ManipulationAttack()

    def test_has_3_sequences(self, attack):
        assert len(attack.SEQUENCES) == 3

    def test_sequences_have_multiple_turns(self, attack):
        for name, desc, messages in attack.SEQUENCES:
            assert len(messages) >= 4, f"Sequence {name} has only {len(messages)} turns"

    @pytest.mark.asyncio
    async def test_execute_sends_all_turns(self, attack):
        total_messages = sum(len(msgs) for _, _, msgs in attack.SEQUENCES)
        client = make_mock_client()
        results = await attack.execute(client)
        assert client.chat.call_count == total_messages
        assert len(results) == 3

    @pytest.mark.asyncio
    async def test_execute_uses_same_session_within_sequence(self, attack):
        client = make_mock_client()
        await attack.execute(client)

        # Group calls by session_id
        sessions_per_sequence = {}
        for call in client.chat.call_args_list:
            sid = call.kwargs.get("session_id", "")
            if sid not in sessions_per_sequence:
                sessions_per_sequence[sid] = 0
            sessions_per_sequence[sid] += 1

        # There should be exactly 3 unique sessions (one per sequence)
        assert len(sessions_per_sequence) == 3

    @pytest.mark.asyncio
    async def test_execute_handles_errors_mid_sequence(self, attack):
        client = make_mock_client(error="Connection lost", response_text="")
        results = await attack.execute(client)
        assert all(r.status == Status.ERROR for r in results)


# ---------------------------------------------------------------------------
# Registry integration test
# ---------------------------------------------------------------------------

class TestAIAttackRegistry:
    def test_registry_discovers_all_ai_attacks(self):
        from redteam.registry import AttackRegistry
        registry = AttackRegistry()
        registry.discover()
        ai_attacks = registry.get_by_category("ai")
        assert len(ai_attacks) == 7, f"Expected 7 AI attacks, found {len(ai_attacks)}"

    def test_registry_ai_attacks_have_correct_names(self):
        from redteam.registry import AttackRegistry
        registry = AttackRegistry()
        registry.discover()
        ai_attacks = registry.get_by_category("ai")
        names = sorted(a.name for a in ai_attacks)
        expected = sorted([
            "ai.jailbreak", "ai.prompt_injection", "ai.extraction",
            "ai.off_topic", "ai.data_leakage", "ai.hallucination",
            "ai.manipulation",
        ])
        assert names == expected
