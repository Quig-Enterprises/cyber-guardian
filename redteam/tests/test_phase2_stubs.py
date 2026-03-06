"""Tests for Phase 2 AI-powered attack classes.

Verify that:
1. Classes can be instantiated
2. Class metadata (name, category, severity) is set correctly
3. AiPoweredAttack extends Attack base class and has Ollama model config
4. AdaptiveJailbreakAttack and CreativeExtractionAttack have correct structure
5. AiJudgeEvaluator can be instantiated with default and custom params
"""

import pytest
import asyncio
from redteam.base import Attack, Severity
from redteam.attacks.ai_powered.base import AiPoweredAttack
from redteam.attacks.ai_powered.adaptive_jailbreak import AdaptiveJailbreakAttack
from redteam.attacks.ai_powered.creative_extraction import CreativeExtractionAttack
from redteam.evaluators.ai_judge import AiJudgeEvaluator


# ---------------------------------------------------------------------------
# AiPoweredAttack base class
# ---------------------------------------------------------------------------

class TestAiPoweredAttackBase:
    def test_extends_attack(self):
        assert issubclass(AiPoweredAttack, Attack)

    def test_has_attacker_model(self):
        assert hasattr(AiPoweredAttack, "attacker_model")
        assert AiPoweredAttack.attacker_model == "qwen2.5:32b"

    def test_has_judge_model(self):
        assert hasattr(AiPoweredAttack, "judge_model")
        assert AiPoweredAttack.judge_model == "llama3.2:latest"

    def test_has_max_attempts(self):
        assert hasattr(AiPoweredAttack, "max_attempts")
        assert AiPoweredAttack.max_attempts > 0

    def test_default_severity(self):
        assert AiPoweredAttack.severity == Severity.HIGH

    def test_has_generate_prompt(self):
        assert hasattr(AiPoweredAttack, "generate_prompt")
        assert asyncio.iscoroutinefunction(AiPoweredAttack.generate_prompt)

    def test_has_evaluate_with_ai(self):
        assert hasattr(AiPoweredAttack, "evaluate_with_ai")
        assert asyncio.iscoroutinefunction(AiPoweredAttack.evaluate_with_ai)

    def test_has_call_ollama(self):
        assert hasattr(AiPoweredAttack, "_call_ollama")
        assert asyncio.iscoroutinefunction(AiPoweredAttack._call_ollama)


# ---------------------------------------------------------------------------
# AdaptiveJailbreakAttack
# ---------------------------------------------------------------------------

class TestAdaptiveJailbreakAttack:
    def test_extends_ai_powered_attack(self):
        assert issubclass(AdaptiveJailbreakAttack, AiPoweredAttack)

    def test_name(self):
        attack = AdaptiveJailbreakAttack()
        assert attack.name == "ai_powered.adaptive_jailbreak"

    def test_category(self):
        attack = AdaptiveJailbreakAttack()
        assert attack.category == "ai"

    def test_severity(self):
        attack = AdaptiveJailbreakAttack()
        assert attack.severity == Severity.CRITICAL

    def test_has_description(self):
        attack = AdaptiveJailbreakAttack()
        assert len(attack.description) > 0

    def test_has_attack_goals(self):
        attack = AdaptiveJailbreakAttack()
        assert hasattr(attack, "attack_goals")
        assert len(attack.attack_goals) == 5

    def test_execute_is_implemented(self):
        attack = AdaptiveJailbreakAttack()
        assert asyncio.iscoroutinefunction(attack.execute)


# ---------------------------------------------------------------------------
# CreativeExtractionAttack
# ---------------------------------------------------------------------------

class TestCreativeExtractionAttack:
    def test_extends_ai_powered_attack(self):
        assert issubclass(CreativeExtractionAttack, AiPoweredAttack)

    def test_name(self):
        attack = CreativeExtractionAttack()
        assert attack.name == "ai_powered.creative_extraction"

    def test_category(self):
        attack = CreativeExtractionAttack()
        assert attack.category == "ai"

    def test_severity(self):
        attack = CreativeExtractionAttack()
        assert attack.severity == Severity.CRITICAL

    def test_has_description(self):
        attack = CreativeExtractionAttack()
        assert len(attack.description) > 0

    def test_has_target_fragments(self):
        attack = CreativeExtractionAttack()
        assert hasattr(attack, "target_fragments")
        assert len(attack.target_fragments) == 7

    def test_execute_is_implemented(self):
        attack = CreativeExtractionAttack()
        assert asyncio.iscoroutinefunction(attack.execute)


# ---------------------------------------------------------------------------
# AiJudgeEvaluator stub (still Phase 2 stub - uses Anthropic API)
# ---------------------------------------------------------------------------

class TestAiJudgeEvaluator:
    def test_instantiation_defaults(self):
        judge = AiJudgeEvaluator()
        assert "claude" in judge.model.lower()
        assert judge.api_key_env == "ANTHROPIC_API_KEY"

    def test_instantiation_custom(self):
        judge = AiJudgeEvaluator(model="claude-opus-4-20250514", api_key_env="MY_KEY")
        assert judge.model == "claude-opus-4-20250514"
        assert judge.api_key_env == "MY_KEY"

    @pytest.mark.asyncio
    async def test_judge_jailbreak_raises(self):
        judge = AiJudgeEvaluator()
        with pytest.raises(NotImplementedError, match="Phase 2"):
            await judge.judge_jailbreak("prompt", "response")

    @pytest.mark.asyncio
    async def test_judge_extraction_raises(self):
        judge = AiJudgeEvaluator()
        with pytest.raises(NotImplementedError, match="Phase 2"):
            await judge.judge_extraction("response", ["fragment"])

    @pytest.mark.asyncio
    async def test_judge_off_topic_raises(self):
        judge = AiJudgeEvaluator()
        with pytest.raises(NotImplementedError, match="Phase 2"):
            await judge.judge_off_topic("cooking", "response")

    @pytest.mark.asyncio
    async def test_judge_persona_break_raises(self):
        judge = AiJudgeEvaluator()
        with pytest.raises(NotImplementedError, match="Phase 2"):
            await judge.judge_persona_break(
                "vibration analysis expert", "I can help with anything!"
            )
