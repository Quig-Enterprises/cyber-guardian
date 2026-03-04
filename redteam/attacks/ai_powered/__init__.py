"""AI-powered attack strategies (Phase 2).

This package contains attack modules that use an LLM (Claude) to
dynamically generate adversarial prompts and evaluate responses.

Phase 2 modules:
- adaptive_jailbreak: Uses Claude to iteratively craft jailbreak attempts
- creative_extraction: Uses Claude to find novel system prompt extraction strategies

These modules require an ANTHROPIC_API_KEY environment variable to be set.
They are disabled by default in config.yaml (ai_attacker.enabled: false).
"""
