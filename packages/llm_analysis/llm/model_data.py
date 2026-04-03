#!/usr/bin/env python3
"""
Static model data — costs, limits, endpoints, defaults.

Pure data, no logic. Updated during development from provider
documentation. Changes at a different rate than code — when
providers update pricing or release new models, edit this file.

Last verified: 2026-04-01.
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
    "openai":    "gpt-5.4",
    "gemini":    "gemini-2.5-pro",
    "mistral":   "mistral-large-latest",
}

# Per-1K-token costs (USD), split input/output.
# Thinking/reasoning tokens are billed at the output rate on all providers.
MODEL_COSTS = {
    # Anthropic
    "claude-opus-4-6":         {"input": 0.005,   "output": 0.025},
    "claude-sonnet-4-6":       {"input": 0.003,   "output": 0.015},
    "claude-haiku-4-5":        {"input": 0.001,   "output": 0.005},
    # OpenAI — flagship
    "gpt-5.4":                 {"input": 0.0025,  "output": 0.015},
    "gpt-5.4-mini":            {"input": 0.00075, "output": 0.0045},
    "gpt-5.4-pro":             {"input": 0.030,   "output": 0.180},
    "gpt-5.2":                 {"input": 0.00175, "output": 0.014},
    "gpt-4o":                  {"input": 0.0025,  "output": 0.010},
    "gpt-4o-mini":             {"input": 0.00015, "output": 0.0006},
    # OpenAI — reasoning (thinking tokens billed as output)
    "o3":                      {"input": 0.002,   "output": 0.008},
    "o3-pro":                  {"input": 0.020,   "output": 0.080},
    "o4-mini":                 {"input": 0.0011,  "output": 0.0044},
    # Google Gemini (<=200K prompt tier for pro)
    "gemini-2.5-pro":          {"input": 0.00125, "output": 0.010},
    "gemini-2.5-flash":        {"input": 0.0003,  "output": 0.0025},
    "gemini-2.5-flash-lite":   {"input": 0.0001,  "output": 0.0004},
    # Google Gemma (free tier only via Gemini API as of 2026-04, also runs locally via Ollama)
    "gemma-4-31b-it":          {"input": 0,       "output": 0},
    # Mistral
    "mistral-large-latest":    {"input": 0.0005,  "output": 0.0015},
    "mistral-small-latest":    {"input": 0.00015, "output": 0.0006},
}

# Per-model context window and max output token limits
MODEL_LIMITS = {
    # Anthropic
    "claude-opus-4-6":         {"max_context": 1000000, "max_output": 128000},
    "claude-sonnet-4-6":       {"max_context": 1000000, "max_output": 64000},
    "claude-haiku-4-5":        {"max_context": 200000,  "max_output": 64000},
    # OpenAI — flagship
    "gpt-5.4":                 {"max_context": 1000000, "max_output": 128000},
    "gpt-5.4-mini":            {"max_context": 1000000, "max_output": 128000},
    "gpt-5.4-pro":             {"max_context": 1000000, "max_output": 128000},
    "gpt-5.2":                 {"max_context": 400000,  "max_output": 128000},
    "gpt-4o":                  {"max_context": 128000,  "max_output": 16384},
    "gpt-4o-mini":             {"max_context": 128000,  "max_output": 16384},
    # OpenAI — reasoning
    "o3":                      {"max_context": 200000,  "max_output": 100000},
    "o3-pro":                  {"max_context": 200000,  "max_output": 100000},
    "o4-mini":                 {"max_context": 200000,  "max_output": 100000},
    # Google Gemini
    "gemini-2.5-pro":          {"max_context": 1048576, "max_output": 65536},
    "gemini-2.5-flash":        {"max_context": 1048576, "max_output": 65536},
    "gemini-2.5-flash-lite":   {"max_context": 1048576, "max_output": 65536},
    # Google Gemma (free tier only via Gemini API as of 2026-04, also runs locally via Ollama)
    "gemma-4-31b-it":          {"max_context": 262144,  "max_output": 32768},
    # Mistral
    "mistral-large-latest":    {"max_context": 262100,  "max_output": 262100},
    "mistral-small-latest":    {"max_context": 256000,  "max_output": 256000},
}

# Provider -> env var mapping for API key lookup
PROVIDER_ENV_KEYS = {
    "anthropic": "ANTHROPIC_API_KEY",
    "openai": "OPENAI_API_KEY",
    "gemini": "GEMINI_API_KEY",
    "mistral": "MISTRAL_API_KEY",
}
