#!/usr/bin/env python3
"""
Static model data — costs, limits, endpoints, defaults.

Pure data, no logic. Updated during development from provider
documentation. Changes at a different rate than code — when
providers update pricing or release new models, edit this file.
"""

# Provider API endpoints (Anthropic uses native SDK, no base_url needed)
PROVIDER_ENDPOINTS = {
    "openai":    "https://api.openai.com/v1",
    "gemini":    "https://generativelanguage.googleapis.com/v1beta/openai",
    "mistral":   "https://api.mistral.ai/v1",
    "ollama":    "http://localhost:11434/v1",
}

# Default model per provider (used when user specifies provider without model)
# Defaults to the most capable model — quality over cost for security analysis
PROVIDER_DEFAULT_MODELS = {
    "anthropic": "claude-opus-4-6",
    "openai":    "gpt-5.2-thinking",
    "gemini":    "gemini-2.5-pro",
    "mistral":   "mistral-large-latest",
}

# Per-1K-token costs (USD), split input/output
MODEL_COSTS = {
    "claude-opus-4-6":       {"input": 0.015, "output": 0.075},
    "claude-sonnet-4-6":     {"input": 0.003, "output": 0.015},
    "claude-haiku-4-5":      {"input": 0.0008, "output": 0.004},
    "gpt-5.2":               {"input": 0.006, "output": 0.030},
    "gpt-5.2-thinking":      {"input": 0.012, "output": 0.060},
    "gemini-2.5-pro":        {"input": 0.002, "output": 0.010},
    "gemini-2.5-flash":      {"input": 0.0002, "output": 0.001},
}

# Per-model context window and max output token limits
MODEL_LIMITS = {
    "claude-opus-4-6":       {"max_context": 1000000, "max_output": 32000},
    "claude-sonnet-4-6":     {"max_context": 1000000, "max_output": 64000},
    "claude-haiku-4-5":      {"max_context": 200000,  "max_output": 8192},
    "gpt-5.2":               {"max_context": 128000,  "max_output": 16384},
    "gpt-5.2-thinking":      {"max_context": 128000,  "max_output": 16384},
    "gemini-2.5-pro":        {"max_context": 1000000, "max_output": 8192},
    "gemini-2.5-flash":      {"max_context": 1000000, "max_output": 8192},
}

# Provider -> env var mapping for API key lookup
PROVIDER_ENV_KEYS = {
    "anthropic": "ANTHROPIC_API_KEY",
    "openai": "OPENAI_API_KEY",
    "gemini": "GEMINI_API_KEY",
    "mistral": "MISTRAL_API_KEY",
}
