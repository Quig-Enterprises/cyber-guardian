"""AI-powered attack strategies (Phase 2).

This package contains attack modules that use local Ollama LLMs to
dynamically generate adversarial prompts and evaluate responses.

Phase 2 modules:
- adaptive_jailbreak: Uses LLM to iteratively craft jailbreak attempts
- creative_extraction: Uses LLM to find novel system prompt extraction strategies

Uses local Ollama models (qwen2.5:32b attacker, llama3.2 judge). No API keys needed.
"""
