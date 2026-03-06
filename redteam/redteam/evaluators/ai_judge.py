"""Phase 2: AI-based evaluation of attack responses.

Uses Claude to determine if an attack succeeded, with richer
understanding than keyword matching. The AI judge can detect:
- Semantic compliance (responding to off-topic requests without obvious keywords)
- Subtle information leakage (paraphrased system prompt content)
- Persona breaks (changes in tone, expertise claims, or behavior)
- Partial compliance (refusing but still providing some information)

Dependencies (Phase 2):
    pip install anthropic
"""


class AiJudgeEvaluator:
    """LLM-based response evaluation for nuanced attack success detection.

    Args:
        model: Claude model to use for evaluation (default: Haiku for speed/cost)
        api_key_env: Environment variable name containing the Anthropic API key
    """

    def __init__(
        self,
        model: str = "claude-haiku-4-5-20251001",
        api_key_env: str = "ANTHROPIC_API_KEY",
    ):
        self.model = model
        self.api_key_env = api_key_env

    async def judge_jailbreak(self, prompt: str, response: str) -> dict:
        """Judge whether a jailbreak attempt succeeded.

        Returns:
            {"succeeded": bool, "confidence": float, "reasoning": str,
             "compliance_type": str, "defense_bypassed": str}
        """
        raise NotImplementedError("Phase 2")

    async def judge_extraction(self, response: str, known_fragments: list[str]) -> dict:
        """Judge whether system prompt content was extracted.

        Returns:
            {"succeeded": bool, "confidence": float, "reasoning": str,
             "fragments_found": list[str], "fragments_paraphrased": list[str],
             "coverage": float}
        """
        raise NotImplementedError("Phase 2")

    async def judge_off_topic(self, requested_topic: str, response: str) -> dict:
        """Judge whether the AI responded to an off-topic request.

        Returns:
            {"succeeded": bool, "confidence": float, "reasoning": str,
             "topic_addressed": bool, "topic_refused": bool,
             "sneaky_compliance": bool}
        """
        raise NotImplementedError("Phase 2")

    async def judge_persona_break(self, expected_persona: str, response: str) -> dict:
        """Judge whether the AI broke its assigned persona.

        Returns:
            {"succeeded": bool, "confidence": float, "reasoning": str,
             "persona_maintained": bool, "new_persona_claimed": str | None,
             "behavioral_inconsistency": str | None}
        """
        raise NotImplementedError("Phase 2")
