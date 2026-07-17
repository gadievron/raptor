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


# -----------------------------------------------------------------------
# Shorthand expansion — task #402. Bare tier tokens (haiku / opus /
# sonnet) resolve to a configured model when the match is unambiguous.
# -----------------------------------------------------------------------


def test_shorthand_resolves_when_unambiguous():
    # Only one haiku entry is configured — the shorthand resolves to it,
    # borrowing the entry's api_key so downstream sees the configured
    # credential, not a bare / keyless config.
    cfg = _cfg()
    got = cfg.config_for_model("haiku")
    assert got.model_name == "claude-haiku-4-5-20251001"
    assert got.api_key == "K_HAIKU"


def test_shorthand_resolves_opus_via_token_match():
    cfg = _cfg()
    got = cfg.config_for_model("opus")
    assert got.model_name == "claude-opus-4-6"
    assert got.api_key == "K_OPUS"


def test_shorthand_case_insensitive():
    cfg = _cfg()
    got = cfg.config_for_model("HAIKU")
    assert got.model_name == "claude-haiku-4-5-20251001"


def test_shorthand_ambiguous_raises_with_candidates():
    # Two haiku entries configured — the shorthand is ambiguous; the
    # error lists both so the operator can pick.
    cfg = LLMConfig(
        primary_model=None,
        fallback_models=[
            ModelConfig(
                provider="anthropic",
                model_name="claude-haiku-4-5-20251001",
                api_key="K1",
            ),
            ModelConfig(
                provider="anthropic",
                model_name="claude-haiku-4-6",
                api_key="K2",
            ),
        ],
        specialized_models={},
    )
    with pytest.raises(ValueError) as ei:
        cfg.config_for_model("haiku")
    msg = str(ei.value)
    assert "ambiguous" in msg
    assert "claude-haiku-4-5-20251001" in msg
    assert "claude-haiku-4-6" in msg


def test_shorthand_zero_match_falls_through_to_loud_error():
    # ``bogusmodel`` doesn't match any token of the configured names.
    # Falls through to the standard unknown_model_message path, NOT the
    # shorthand-ambiguity path — so operators see the same error they
    # got before the shorthand feature landed for truly-unknown ids.
    cfg = _cfg()
    with pytest.raises(ValueError) as ei:
        cfg.config_for_model("bogusmodel")
    # standard error mentions the id; does NOT say "ambiguous"
    assert "bogusmodel" in str(ei.value)
    assert "ambiguous" not in str(ei.value)


def test_shorthand_does_not_trigger_on_qualified_names():
    # ``anthropic/claude-haiku-4-5`` contains a ``/`` — this is a
    # provider-qualified id, not a shorthand. Must resolve via the
    # existing provider_of path (borrows credential via prefix match)
    # rather than the shorthand-token path.
    cfg = _cfg()
    got = cfg.config_for_model("anthropic/claude-haiku-4-5")
    assert got.provider == "anthropic"
    assert got.api_key == "K_HAIKU"


def test_shorthand_substring_does_not_match_token():
    # ``opus`` shorthand must NOT resolve if only a substring-non-token
    # match exists. Prevents fake matches like ``pus`` on ``opus``
    # (substring inside a token, not equal to any token).
    weird = ModelConfig(
        provider="ollama",
        model_name="prometheus-opus-plus",
        api_key="K",
    )
    cfg = LLMConfig(primary_model=None, fallback_models=[weird], specialized_models={})
    # ``opus`` is a token in prometheus-opus-plus → resolves.
    assert cfg.config_for_model("opus") is weird
    # ``pus`` is NOT a token — falls through to loud error.
    with pytest.raises(ValueError):
        cfg.config_for_model("pus")
