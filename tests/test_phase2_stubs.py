"""Tests for Phase 2 stub classes.

Verify that:
1. Stub classes can be instantiated
2. Stub methods raise NotImplementedError with helpful messages
3. Class metadata (name, category, severity) is set correctly
4. AiPoweredAttack extends Attack base class
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
        assert "claude" in AiPoweredAttack.attacker_model.lower()

    def test_has_judge_model(self):
        assert hasattr(AiPoweredAttack, "judge_model")
        assert "claude" in AiPoweredAttack.judge_model.lower()

    def test_has_max_attempts(self):
        assert hasattr(AiPoweredAttack, "max_attempts")
        assert AiPoweredAttack.max_attempts > 0

    def test_default_severity(self):
        assert AiPoweredAttack.severity == Severity.HIGH

    @pytest.mark.asyncio
    async def test_generate_prompt_raises(self):
        class ConcreteAiAttack(AiPoweredAttack):
            name = "test"
            async def execute(self, client):
                return []

        attack = ConcreteAiAttack()
        with pytest.raises(NotImplementedError, match="Phase 2"):
            await attack.generate_prompt({"target_description": "test"})

    @pytest.mark.asyncio
    async def test_evaluate_with_ai_raises(self):
        class ConcreteAiAttack(AiPoweredAttack):
            name = "test"
            async def execute(self, client):
                return []

        attack = ConcreteAiAttack()
        with pytest.raises(NotImplementedError, match="Phase 2"):
            await attack.evaluate_with_ai("prompt", "response", "goal")


# ---------------------------------------------------------------------------
# AdaptiveJailbreakAttack stub
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

    @pytest.mark.asyncio
    async def test_execute_raises(self):
        attack = AdaptiveJailbreakAttack()
        with pytest.raises(NotImplementedError, match="Phase 2"):
            await attack.execute(None)


# ---------------------------------------------------------------------------
# CreativeExtractionAttack stub
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

    @pytest.mark.asyncio
    async def test_execute_raises(self):
        attack = CreativeExtractionAttack()
        with pytest.raises(NotImplementedError, match="Phase 2"):
            await attack.execute(None)


# ---------------------------------------------------------------------------
# AiJudgeEvaluator stub
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
