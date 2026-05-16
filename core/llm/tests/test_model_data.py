"""Tests for ``core.llm.model_data`` lookup helpers.

The helpers are pure functions over the static ``MODEL_COSTS`` /
``MODEL_LIMITS`` tables. Tests assert behaviour for known models +
documented unknown-model semantics (raise vs fallback).
"""

from __future__ import annotations

import pytest

from core.llm.model_data import (
    ANTHROPIC_CACHE_READ_MULTIPLIER,
    ANTHROPIC_CACHE_WRITE_MULTIPLIER,
    MODEL_COSTS,
    MODEL_LIMITS,
    context_window_for,
    max_output_for,
    price_for,
)


# --- context_window_for -------------------------------------------------

def test_context_window_returns_known() -> None:
    """Known models surface ``max_context`` from the limits table."""
    assert context_window_for("claude-opus-4-6") == 1_000_000
    assert context_window_for("gpt-4o") == 128_000
    assert context_window_for("o3") == 200_000


def test_context_window_unknown_raises() -> None:
    """Loop policy enforcement (truncate vs raise vs summarise) needs
    a definite number — silently falling back would mis-gate."""
    with pytest.raises(KeyError, match="unknown model 'does-not-exist'"):
        context_window_for("does-not-exist")


# --- max_output_for ------------------------------------------------------

def test_max_output_returns_known() -> None:
    assert max_output_for("claude-opus-4-6") == 128_000
    assert max_output_for("gpt-4o") == 16_384
    assert max_output_for("gemini-2.5-pro") == 65_536


def test_max_output_unknown_raises() -> None:
    with pytest.raises(KeyError, match="unknown model 'mystery'"):
        max_output_for("mystery")


# --- price_for ----------------------------------------------------------

def test_price_for_known_converts_per_1k_to_per_million() -> None:
    """``MODEL_COSTS`` is per-1K USD for human readability; the helper
    surfaces per-million which is what cost trackers actually want."""
    cost = MODEL_COSTS["claude-opus-4-6"]               # {input: 0.005, output: 0.025}
    assert price_for("claude-opus-4-6") == (cost["input"] * 1000.0,
                                            cost["output"] * 1000.0)
    # Sanity-check absolute values for one entry to catch off-by-1000s.
    assert price_for("claude-opus-4-6") == (5.0, 25.0)


def test_price_for_unknown_returns_default() -> None:
    """Soft fallback so cost tracking degrades cleanly when a new model
    arrives before ``MODEL_COSTS`` is updated. Caller using a non-zero
    cap will see the cap effectively disabled — that's the documented
    contract."""
    assert price_for("future-model-2030") == (0.0, 0.0)


def test_price_for_unknown_honours_explicit_default() -> None:
    """Caller can pass a probe value to detect "unknown" without a try/except."""
    sentinel = (-1.0, -1.0)
    assert price_for("future-model-2030", default=sentinel) == sentinel


# --- Anthropic cache multipliers ---------------------------------------

def test_anthropic_cache_multipliers_match_anthropic_docs() -> None:
    """Cache writes are 1.25x input rate; cache reads are 0.1x.
    Documented at https://docs.anthropic.com/en/docs/build-with-claude/prompt-caching
    """
    assert ANTHROPIC_CACHE_WRITE_MULTIPLIER == 1.25
    assert ANTHROPIC_CACHE_READ_MULTIPLIER == 0.1


# --- table consistency --------------------------------------------------

def test_every_priced_model_has_limits() -> None:
    """Cost and limits tables should agree on which models exist —
    drift here causes silent ``KeyError`` for callers fetching one
    after the other."""
    cost_models = set(MODEL_COSTS.keys())
    limit_models = set(MODEL_LIMITS.keys())
    only_in_costs = cost_models - limit_models
    only_in_limits = limit_models - cost_models
    assert not only_in_costs, (
        f"models in MODEL_COSTS but not MODEL_LIMITS: {only_in_costs}")
    assert not only_in_limits, (
        f"models in MODEL_LIMITS but not MODEL_COSTS: {only_in_limits}")
