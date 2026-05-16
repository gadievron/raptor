#!/usr/bin/env python3
"""
Static model data — costs, limits, endpoints, defaults.

Pure data, no logic. Updated during development from provider
documentation. Changes at a different rate than code — when
providers update pricing or release new models, edit this file.

Last verified: 2026-05-03.

Verification provenance for the 2026-05-03 refresh:

  * Anthropic: ``platform.claude.com/docs/en/docs/about-claude/models/overview``
    — all entries verified directly. Includes deprecated-but-still-
    available ``claude-sonnet-4-0`` / ``claude-opus-4-0`` (retire
    2026-06-15 per Anthropic's deprecation page).
  * OpenAI: ``platform.openai.com/docs/models`` model cards — every
    entry verified directly against the model card.
  * Gemini: ``ai.google.dev/gemini-api/docs/pricing`` — 2.5 family
    only. 3.x preview models deliberately not listed (preview-only
    IDs unstable across releases).
  * Mistral: ``mistral.ai/pricing`` + ``docs.mistral.ai/models/model-cards/*``
    — existing ``mistral-large-latest`` + ``mistral-small-latest``
    pricing confirmed unchanged. Added ``mistral-medium-latest``
    ($1.50/$7.50, Mistral Medium 3.5, 256K ctx) plus
    ``ministral-{3b,8b,14b}-latest`` (the Ministral 3 family, all
    256K ctx per their model cards). All Mistral entries verified.
"""

# Provider API endpoints (Anthropic uses native SDK, no base_url needed)
PROVIDER_ENDPOINTS = {
    "openai":    "https://api.openai.com/v1",
    "gemini":    "https://generativelanguage.googleapis.com/v1beta/openai",
    "mistral":   "https://api.mistral.ai/v1",
    "ollama":    "http://localhost:11434/v1",
}

# Default model per provider (used when user specifies provider without model)
# Defaults to the most capable model — quality over cost for security analysis.
# ``claude-opus-4-6`` deliberately retained as the Anthropic default — Opus 4.7
# has a measurably higher refusal rate on cve-diff-class workloads, so
# 4.6 stays the conservative default. Switch to 4.7 when refusal-rate
# evidence improves.
PROVIDER_DEFAULT_MODELS = {
    "anthropic": "claude-opus-4-6",
    "openai":    "gpt-5.4",
    "gemini":    "gemini-2.5-pro",
    "mistral":   "mistral-large-latest",
}

# Fast/cheap-tier model per provider — used as the default for
# routing-light task types (binary verdicts, classification, severity
# triage) where a flagship model is overkill. Aim is "good enough"
# quality at ~10× cost reduction and ~3× latency reduction vs the
# flagship default.
#
# Cost-class ratio (input/output, per-1K, vs flagship default):
#   Anthropic:  Opus  $0.005/$0.025  →  Haiku   $0.001/$0.005   (~5×)
#   OpenAI:     5.4   $0.0025/$0.015 →  4o-mini $0.00015/$0.0006 (~25×)
#   Gemini:     Pro   $0.00125/$0.01 →  Flash-L $0.0001/$0.0004  (~25×)
#   Mistral:    Large $0.0005/$0.0015→  Small   $0.00015/$0.0006 (~3×)
#
# OpenAI mapping prefers ``gpt-4o-mini`` over the cheaper
# ``gpt-5-nano`` because the 4o-mini has a longer track record for
# structured-output reliability across third-party libraries (Instructor,
# pydantic-ai). Switch to a 5.x mini when its structured-output story
# stabilises in those libraries.
#
# Providers without a fast-model mapping (Ollama, Claude Code via
# subprocess) are intentionally absent — for Ollama the operator picks
# a small tagged model themselves; for Claude Code there's only one
# "model".
PROVIDER_FAST_MODELS = {
    "anthropic": "claude-haiku-4-5",
    "openai":    "gpt-4o-mini",
    "gemini":    "gemini-2.5-flash-lite",
    "mistral":   "mistral-small-latest",
}

# Per-1K-token costs (USD), split input/output.
# Thinking/reasoning tokens are billed at the output rate on all providers.
MODEL_COSTS = {
    # Anthropic — current
    "claude-opus-4-7":         {"input": 0.005,   "output": 0.025},
    "claude-sonnet-4-6":       {"input": 0.003,   "output": 0.015},
    "claude-haiku-4-5":        {"input": 0.001,   "output": 0.005},
    # Anthropic — legacy (still served via API)
    "claude-opus-4-6":         {"input": 0.005,   "output": 0.025},
    "claude-sonnet-4-5":       {"input": 0.003,   "output": 0.015},
    "claude-opus-4-5":         {"input": 0.005,   "output": 0.025},
    "claude-opus-4-1":         {"input": 0.015,   "output": 0.075},
    # Anthropic — deprecated, retires 2026-06-15
    "claude-sonnet-4-0":       {"input": 0.003,   "output": 0.015},
    "claude-opus-4-0":         {"input": 0.015,   "output": 0.075},
    # OpenAI — flagship (5.5/5.4 families)
    "gpt-5.5":                 {"input": 0.005,   "output": 0.030},
    "gpt-5.5-pro":             {"input": 0.030,   "output": 0.180},
    "gpt-5.4":                 {"input": 0.0025,  "output": 0.015},
    "gpt-5.4-mini":            {"input": 0.00075, "output": 0.0045},
    "gpt-5.4-nano":            {"input": 0.0002,  "output": 0.00125},
    "gpt-5.4-pro":             {"input": 0.030,   "output": 0.180},
    "gpt-5.2":                 {"input": 0.00175, "output": 0.014},
    "gpt-5.2-pro":             {"input": 0.021,   "output": 0.168},
    "gpt-5.1":                 {"input": 0.00125, "output": 0.010},
    "gpt-5":                   {"input": 0.00125, "output": 0.010},
    "gpt-5-mini":              {"input": 0.00025, "output": 0.002},
    "gpt-5-nano":              {"input": 0.00005, "output": 0.0004},
    "gpt-5-pro":               {"input": 0.015,   "output": 0.120},
    # OpenAI — gpt-4 family
    "gpt-4.1":                 {"input": 0.002,   "output": 0.008},
    "gpt-4.1-mini":            {"input": 0.0004,  "output": 0.0016},
    "gpt-4.1-nano":            {"input": 0.0001,  "output": 0.0004},
    "gpt-4o":                  {"input": 0.0025,  "output": 0.010},
    "gpt-4o-mini":             {"input": 0.00015, "output": 0.0006},
    # OpenAI — reasoning (thinking tokens billed as output)
    "o1":                      {"input": 0.015,   "output": 0.060},
    "o1-pro":                  {"input": 0.150,   "output": 0.600},
    "o1-mini":                 {"input": 0.0011,  "output": 0.0044},
    "o3":                      {"input": 0.002,   "output": 0.008},
    "o3-mini":                 {"input": 0.0011,  "output": 0.0044},
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
    "mistral-medium-latest":   {"input": 0.0015,  "output": 0.0075},
    "mistral-small-latest":    {"input": 0.00015, "output": 0.0006},
    "ministral-14b-latest":    {"input": 0.0002,  "output": 0.0002},
    "ministral-8b-latest":     {"input": 0.00015, "output": 0.00015},
    "ministral-3b-latest":     {"input": 0.0001,  "output": 0.0001},
}

# Per-model context window and max output token limits.
# All entries verified directly against provider model cards as of
# the verification date in the module docstring above.
MODEL_LIMITS = {
    # Anthropic — current
    "claude-opus-4-7":         {"max_context": 1000000, "max_output": 128000},
    "claude-sonnet-4-6":       {"max_context": 1000000, "max_output": 64000},
    "claude-haiku-4-5":        {"max_context": 200000,  "max_output": 64000},
    # Anthropic — legacy (still served via API)
    "claude-opus-4-6":         {"max_context": 1000000, "max_output": 128000},
    "claude-sonnet-4-5":       {"max_context": 200000,  "max_output": 64000},
    "claude-opus-4-5":         {"max_context": 200000,  "max_output": 64000},
    "claude-opus-4-1":         {"max_context": 200000,  "max_output": 32000},
    # Anthropic — deprecated, retires 2026-06-15
    "claude-sonnet-4-0":       {"max_context": 200000,  "max_output": 64000},
    "claude-opus-4-0":         {"max_context": 200000,  "max_output": 32000},
    # OpenAI — flagship
    "gpt-5.5":                 {"max_context": 1050000, "max_output": 128000},
    "gpt-5.5-pro":             {"max_context": 1050000, "max_output": 128000},
    "gpt-5.4":                 {"max_context": 1050000, "max_output": 128000},
    "gpt-5.4-mini":            {"max_context": 400000,  "max_output": 128000},
    "gpt-5.4-nano":            {"max_context": 400000,  "max_output": 128000},
    "gpt-5.4-pro":             {"max_context": 1050000, "max_output": 128000},
    "gpt-5.2":                 {"max_context": 400000,  "max_output": 128000},
    "gpt-5.2-pro":             {"max_context": 400000,  "max_output": 128000},
    "gpt-5.1":                 {"max_context": 400000,  "max_output": 128000},
    "gpt-5":                   {"max_context": 400000,  "max_output": 128000},
    "gpt-5-mini":              {"max_context": 400000,  "max_output": 128000},
    "gpt-5-nano":              {"max_context": 400000,  "max_output": 128000},
    "gpt-5-pro":               {"max_context": 400000,  "max_output": 272000},
    # OpenAI — gpt-4 family
    "gpt-4.1":                 {"max_context": 1047576, "max_output": 32768},
    "gpt-4.1-mini":            {"max_context": 1047576, "max_output": 32768},
    "gpt-4.1-nano":            {"max_context": 1047576, "max_output": 32768},
    "gpt-4o":                  {"max_context": 128000,  "max_output": 16384},
    "gpt-4o-mini":             {"max_context": 128000,  "max_output": 16384},
    # OpenAI — reasoning
    "o1":                      {"max_context": 200000,  "max_output": 100000},
    "o1-pro":                  {"max_context": 200000,  "max_output": 100000},
    "o1-mini":                 {"max_context": 128000,  "max_output": 65536},
    "o3":                      {"max_context": 200000,  "max_output": 100000},
    "o3-mini":                 {"max_context": 200000,  "max_output": 100000},
    "o3-pro":                  {"max_context": 200000,  "max_output": 100000},
    "o4-mini":                 {"max_context": 200000,  "max_output": 100000},
    # Google Gemini
    "gemini-2.5-pro":          {"max_context": 1048576, "max_output": 65536},
    "gemini-2.5-flash":        {"max_context": 1048576, "max_output": 65536},
    "gemini-2.5-flash-lite":   {"max_context": 1048576, "max_output": 65536},
    # Google Gemma (free tier only via Gemini API as of 2026-04, also runs locally via Ollama)
    "gemma-4-31b-it":          {"max_context": 262144,  "max_output": 32768},
    # Mistral — max_output = max_context per Mistral convention
    "mistral-large-latest":    {"max_context": 262100,  "max_output": 262100},
    "mistral-medium-latest":   {"max_context": 256000,  "max_output": 256000},
    "mistral-small-latest":    {"max_context": 256000,  "max_output": 256000},
    "ministral-14b-latest":    {"max_context": 256000,  "max_output": 256000},
    "ministral-8b-latest":     {"max_context": 256000,  "max_output": 256000},
    "ministral-3b-latest":     {"max_context": 256000,  "max_output": 256000},
}

# Provider -> env var mapping for API key lookup
PROVIDER_ENV_KEYS = {
    "anthropic": "ANTHROPIC_API_KEY",
    "openai": "OPENAI_API_KEY",
    "gemini": "GEMINI_API_KEY",
    "mistral": "MISTRAL_API_KEY",
}


# ---------------------------------------------------------------------------
# Lookup helpers
# ---------------------------------------------------------------------------

def context_window_for(model: str) -> int:
    """Total input tokens the model accepts in one request.

    Raises ``KeyError`` for unknown models — the tool-use loop's
    context-policy enforcement (truncate vs raise vs summarise) needs
    a definite number; an approximate fallback would silently mis-gate.
    """
    limits = MODEL_LIMITS.get(model)
    if limits is None:
        raise KeyError(f"context_window_for: unknown model {model!r}")
    return limits["max_context"]


def max_output_for(model: str) -> int:
    """Maximum tokens the model can emit in one response. Raises
    ``KeyError`` for unknown models — useful for capping ``max_tokens``
    request kwargs to a value the provider will accept."""
    limits = MODEL_LIMITS.get(model)
    if limits is None:
        raise KeyError(f"max_output_for: unknown model {model!r}")
    return limits["max_output"]


def price_for(
    model: str,
    *,
    default: tuple[float, float] = (0.0, 0.0),
) -> tuple[float, float]:
    """Return ``(input_per_million_usd, output_per_million_usd)`` for ``model``.

    ``MODEL_COSTS`` is stored per-1K tokens for human readability; this
    helper converts to per-million which is the unit consumers (loop
    cost tracking, ``max_cost_usd`` enforcement) actually want.

    Unknown models return ``default`` rather than raising — the caller
    chooses between (a) soft warn + treat as $0 (cost tracking
    degrades cleanly, ``max_cost_usd`` cap effectively disabled) and
    (b) hard error by passing ``default=None`` and checking — but
    ``None`` isn't a valid tuple so callers wanting hard errors should
    test the return against ``(0.0, 0.0)`` and act accordingly.
    """
    cost = MODEL_COSTS.get(model)
    if cost is None:
        return default
    return (cost["input"] * 1000.0, cost["output"] * 1000.0)


# Anthropic-specific cache pricing multipliers (vs base input rate).
# Cache writes are 1.25x input; cache reads are 0.1x input. Used by
# AnthropicToolUseProvider to compute cost when the response carries
# ``cache_creation_input_tokens`` / ``cache_read_input_tokens``.
ANTHROPIC_CACHE_WRITE_MULTIPLIER = 1.25
ANTHROPIC_CACHE_READ_MULTIPLIER = 0.1
