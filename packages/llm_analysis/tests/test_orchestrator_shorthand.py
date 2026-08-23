"""Regression: /agentic / /analyze / /scan --model haiku shorthand.

Task #402 QoL: bare tier tokens (``haiku`` / ``opus`` / ``sonnet``)
resolve to the operator's configured model when there's exactly one
matching entry. Ambiguous shorthand raises with the candidate list.

The dispatch layer for /agentic / /analyze / /scan is
``build_llm_config_from_flags._resolve_model`` in ``orchestrator.py``,
which is a DIFFERENT resolution path from ``LLMConfig.config_for_model``
(the /exploit path). Both must handle shorthand consistently.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO))

from packages.llm_analysis.orchestrator import (  # noqa: E402
    build_llm_config_from_flags,
)


def test_orchestrator_resolves_shorthand_haiku(monkeypatch):
    """--model haiku on /agentic resolves to the configured Anthropic
    entry when it's the only Anthropic model in models.json."""
    fake_models = [
        {
            "provider": "anthropic",
            "model": "claude-haiku-4-5-20251001",
            "api_key": "KEY_HAIKU",
        },
        {
            "provider": "gemini",
            "model": "gemini-2.5-pro",
            "api_key": "KEY_GEMINI",
        },
    ]
    monkeypatch.setattr(
        "core.llm.config._get_configured_models",
        lambda: fake_models,
    )
    monkeypatch.setattr(
        "core.llm.detection._read_config_models",
        lambda: fake_models,
    )

    cfg = build_llm_config_from_flags(
        models=["haiku"], auto_detect=False,
    )
    assert cfg is not None
    assert cfg.primary_model is not None
    # The primary model resolves to the full configured name (not bare
    # 'haiku'), and inherits the configured api_key.
    assert cfg.primary_model.model_name == "claude-haiku-4-5-20251001"
    assert cfg.primary_model.provider == "anthropic"
    assert cfg.primary_model.api_key == "KEY_HAIKU"


def test_orchestrator_resolves_shorthand_via_alias(monkeypatch):
    """The Anthropic resolver rewrites ``model`` to the dated snapshot
    and stashes the operator's alias in ``_configured_model``. The
    shorthand pass includes the alias so a token that only appears in
    the alias still matches."""
    fake_models = [
        {
            "provider": "anthropic",
            "model": "claude-haiku-4-5-20251001",
            "_configured_model": "claude-haiku-4-5",
            "api_key": "KEY_HAIKU",
        },
    ]
    monkeypatch.setattr(
        "core.llm.config._get_configured_models",
        lambda: fake_models,
    )
    monkeypatch.setattr(
        "core.llm.detection._read_config_models",
        lambda: fake_models,
    )
    cfg = build_llm_config_from_flags(
        models=["haiku"], auto_detect=False,
    )
    assert cfg is not None
    assert cfg.primary_model.model_name == "claude-haiku-4-5-20251001"


def test_orchestrator_ambiguous_shorthand_raises(monkeypatch):
    """Two haiku models configured → shorthand ambiguous. Since
    resolve_model_shorthand raises inside _resolve_model, the caller
    surfaces the raise as a printed error and returns None. Verify the
    LLMConfig-build returns None (loud failure), not a silently-wrong
    picked entry."""
    fake_models = [
        {
            "provider": "anthropic",
            "model": "claude-haiku-4-5-20251001",
            "api_key": "K1",
        },
        {
            "provider": "anthropic",
            "model": "claude-haiku-4-6",
            "api_key": "K2",
        },
    ]
    monkeypatch.setattr(
        "core.llm.config._get_configured_models",
        lambda: fake_models,
    )
    monkeypatch.setattr(
        "core.llm.detection._read_config_models",
        lambda: fake_models,
    )
    # The raise happens inside _resolve_model; the surrounding code
    # doesn't catch ValueError so it bubbles up. Assert it bubbles up
    # so the operator sees the ambiguity message.
    import pytest
    with pytest.raises(ValueError) as ei:
        build_llm_config_from_flags(models=["haiku"], auto_detect=False)
    assert "ambiguous" in str(ei.value)


def test_orchestrator_shorthand_zero_match_returns_none(monkeypatch):
    """Truly-unknown shorthand still falls through to the standard
    'no API key / unrecognizable' failure path (returns None). Behaviour
    unchanged from pre-shorthand for unrecognizable names."""
    fake_models = [
        {
            "provider": "anthropic",
            "model": "claude-opus-4-6",
            "api_key": "K",
        },
    ]
    monkeypatch.setattr(
        "core.llm.config._get_configured_models",
        lambda: fake_models,
    )
    monkeypatch.setattr(
        "core.llm.detection._read_config_models",
        lambda: fake_models,
    )
    cfg = build_llm_config_from_flags(
        models=["bogus"], auto_detect=False,
    )
    assert cfg is None
