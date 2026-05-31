"""Tests for LLMConfig.config_for_model — credential reuse by specificity.

The rule: when resolving an arbitrary model id, reuse the most specific
configured credential — exact model, else the closest same-provider relative
(longest shared name prefix), else any same-provider key, else bare.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

# core/llm/tests/test_config_for_model.py -> parents[3] = repo root
REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO))

from core.llm.config import LLMConfig, ModelConfig  # noqa: E402
from core.security.llm_family import provider_of  # noqa: E402


def _cfg():
    # primary=None so __post_init__ does not seed specialized fast-tier models.
    return LLMConfig(
        primary_model=None,
        fallback_models=[
            ModelConfig(provider="anthropic", model_name="claude-opus-4-6", api_key="K_OPUS"),
            ModelConfig(
                provider="anthropic",
                model_name="claude-haiku-4-5-20251001",
                api_key="K_HAIKU",
            ),
            ModelConfig(provider="gemini", model_name="gemini-2.5-pro", api_key="K_GEM"),
        ],
        specialized_models={},
    )


def test_exact_match_returns_configured_entry_as_is():
    cfg = _cfg()
    got = cfg.config_for_model("claude-opus-4-6")
    assert got.api_key == "K_OPUS"
    assert got.model_name == "claude-opus-4-6"


def test_closest_relative_lends_credential():
    # opus-4-8 is unconfigured; the opus-4-6 key is a closer fit than haiku's.
    cfg = _cfg()
    got = cfg.config_for_model("claude-opus-4-8")
    assert got.provider == "anthropic"
    assert got.model_name == "claude-opus-4-8"
    assert got.api_key == "K_OPUS"


def test_any_same_provider_key_when_no_close_relative():
    # sonnet shares only "claude-" with both; any anthropic key is acceptable.
    cfg = _cfg()
    got = cfg.config_for_model("claude-sonnet-4-6")
    assert got.provider == "anthropic"
    assert got.api_key in {"K_OPUS", "K_HAIKU"}


def test_provider_isolation_gemini_borrows_gemini_key():
    cfg = _cfg()
    got = cfg.config_for_model("gemini-2.5-flash")
    assert got.provider == "gemini"
    assert got.api_key == "K_GEM"


def test_bare_config_when_no_matching_provider_key():
    cfg = _cfg()
    got = cfg.config_for_model("gpt-5.4")
    assert got.api_key is None
    assert got.provider == provider_of("gpt-5.4")
    assert got.model_name == "gpt-5.4"


def test_unrecognized_model_name_raises_loudly():
    # prefix-less nickname -> no resolvable provider -> loud error, not a
    # silent keyless config
    cfg = _cfg()
    with pytest.raises(ValueError) as ei:
        cfg.config_for_model("opus-4-8")
    assert "opus-4-8" in str(ei.value)


def test_exact_configured_name_wins_even_if_provider_unrecognized():
    # an operator who configured a model under an unusual name still gets it
    # (exact match short-circuits the loud-failure path)
    weird = ModelConfig(provider="ollama", model_name="weird-local-model", api_key="K")
    cfg = LLMConfig(primary_model=None, fallback_models=[weird], specialized_models={})
    assert cfg.config_for_model("weird-local-model") is weird
