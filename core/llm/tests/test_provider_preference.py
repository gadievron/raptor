"""Tests for explicit provider preference and the Claude Code
fallthrough in :func:`core.llm.config._get_default_primary_model`,
plus the :attr:`LLMClient.primary_provider` accessor.

The substrate's autodetection order has historically been Anthropic-
first by convention. Consumers (e.g. cve-diff) that *rely* on that
preference should express it explicitly via ``prefer=`` rather than
depend on coincidence — otherwise their behaviour silently regresses
if the default order is ever re-tuned. This file pins the resolution
contract.
"""

from __future__ import annotations

import os
from unittest.mock import patch

import pytest

from core.llm.config import (
    LLMConfig,
    ModelConfig,
    _get_default_primary_model,
)


# ---------------------------------------------------------------------------
# Test fixtures — strip env so each test sees a clean slate
# ---------------------------------------------------------------------------


@pytest.fixture
def clean_env(monkeypatch):
    """Strip every LLM-related env var so each test starts from an
    empty environment. Tests opt in to specific keys via setenv."""
    for var in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GEMINI_API_KEY",
                "MISTRAL_API_KEY"):
        monkeypatch.delenv(var, raising=False)
    yield monkeypatch


@pytest.fixture
def no_thinking_model(monkeypatch):
    """Disable the operator's thinking-model lookup so tests that
    care about env-var fallthrough aren't surprised by a config-file
    setup on the developer's machine."""
    monkeypatch.setattr(
        "core.llm.config._get_best_thinking_model",
        lambda: None,
    )


@pytest.fixture
def no_claudecode(monkeypatch):
    """Pretend ``claude`` isn't on PATH so the ultimate fallback
    is None rather than ClaudeCodeLLMProvider."""
    monkeypatch.setattr("shutil.which", lambda _bin: None)


@pytest.fixture
def no_ollama(monkeypatch):
    """Pretend Ollama isn't running."""
    monkeypatch.setattr(
        "core.llm.config._get_available_ollama_models",
        lambda: [],
    )


# ---------------------------------------------------------------------------
# Default order — Anthropic > OpenAI > Gemini > Mistral > Ollama > CC
# ---------------------------------------------------------------------------


def test_default_order_picks_anthropic_when_only_anthropic_key(
    clean_env, no_thinking_model, no_claudecode, no_ollama,
) -> None:
    clean_env.setenv("ANTHROPIC_API_KEY", "test-key")
    config = _get_default_primary_model()
    assert config is not None
    assert config.provider == "anthropic"


def test_default_order_picks_openai_when_no_anthropic(
    clean_env, no_thinking_model, no_claudecode, no_ollama,
) -> None:
    clean_env.setenv("OPENAI_API_KEY", "test-key")
    config = _get_default_primary_model()
    assert config is not None
    assert config.provider == "openai"


def test_default_order_picks_anthropic_over_openai_when_both(
    clean_env, no_thinking_model, no_claudecode, no_ollama,
) -> None:
    """Convention: Anthropic first when both are available. This is
    what consumers like cve-diff *coincidentally* depend on today —
    explicit ``prefer="anthropic"`` is the architecturally correct
    way to express it (covered below)."""
    clean_env.setenv("ANTHROPIC_API_KEY", "a-key")
    clean_env.setenv("OPENAI_API_KEY", "o-key")
    config = _get_default_primary_model()
    assert config.provider == "anthropic"


def test_default_returns_none_when_nothing_available(
    clean_env, no_thinking_model, no_claudecode, no_ollama,
) -> None:
    """Pre-Phase-2 behaviour preserved: ``None`` when no provider
    is reachable."""
    config = _get_default_primary_model()
    assert config is None


# ---------------------------------------------------------------------------
# Claude Code fallthrough — works without any API key
# ---------------------------------------------------------------------------


def test_claudecode_fallthrough_when_no_external_llm(
    clean_env, no_thinking_model, no_ollama, monkeypatch,
) -> None:
    """The keyless case: no API keys, no Ollama, but ``claude`` on
    PATH. The resolver falls through to ClaudeCodeLLMProvider so
    tool-using consumers can still operate."""
    monkeypatch.setattr("shutil.which", lambda b: "/usr/bin/claude" if b == "claude" else None)
    config = _get_default_primary_model()
    assert config is not None
    assert config.provider == "claudecode"
    assert config.api_key is None       # no key needed for CC subprocess


def test_claudecode_only_used_as_last_resort(
    clean_env, no_thinking_model, no_ollama, monkeypatch,
) -> None:
    """When *any* API key is set, the resolver picks the API path
    over Claude Code — CC is slower (subprocess + JSON-protocol
    synthesis for tool-use) so it's the absolute last resort."""
    monkeypatch.setattr("shutil.which", lambda b: "/usr/bin/claude" if b == "claude" else None)
    clean_env.setenv("MISTRAL_API_KEY", "test-key")
    config = _get_default_primary_model()
    assert config.provider == "mistral"        # not "claudecode"


# ---------------------------------------------------------------------------
# Explicit preference — consumer-driven
# ---------------------------------------------------------------------------


def test_prefer_anthropic_when_anthropic_available(
    clean_env, no_thinking_model, no_claudecode, no_ollama,
) -> None:
    """``prefer="anthropic"`` returns Anthropic when its env var is
    set — straightforward case."""
    clean_env.setenv("ANTHROPIC_API_KEY", "a-key")
    clean_env.setenv("OPENAI_API_KEY", "o-key")
    config = _get_default_primary_model(prefer="anthropic")
    assert config.provider == "anthropic"


def test_prefer_overrides_default_order(
    clean_env, no_thinking_model, no_claudecode, no_ollama,
) -> None:
    """When operator has Anthropic+Mistral keys both set,
    ``prefer="mistral"`` picks Mistral — explicit preference beats
    the Anthropic-first default order."""
    clean_env.setenv("ANTHROPIC_API_KEY", "a-key")
    clean_env.setenv("MISTRAL_API_KEY", "m-key")
    config = _get_default_primary_model(prefer="mistral")
    assert config.provider == "mistral"


def test_prefer_falls_through_when_preferred_unavailable(
    clean_env, no_thinking_model, no_claudecode, no_ollama,
) -> None:
    """Preference is lenient — when the preferred provider isn't
    reachable, the resolver falls through to the default order. This
    is "I prefer X but give me something that works" semantics."""
    clean_env.setenv("OPENAI_API_KEY", "o-key")    # no Anthropic
    config = _get_default_primary_model(prefer="anthropic")
    assert config.provider == "openai"


def test_prefer_list_tries_each_in_order(
    clean_env, no_thinking_model, no_claudecode, no_ollama,
) -> None:
    """Multi-provider preference: try each in order; first available
    wins."""
    clean_env.setenv("MISTRAL_API_KEY", "m-key")     # only mistral
    config = _get_default_primary_model(
        prefer=["anthropic", "openai", "mistral"]
    )
    assert config.provider == "mistral"


def test_unknown_preferred_provider_silently_skipped(
    clean_env, no_thinking_model, no_claudecode, no_ollama, caplog,
) -> None:
    """A preferred provider name that doesn't match any builder
    (typo, deprecated provider) logs a warning but falls through
    to the rest — better than failing an entire run for a typo."""
    clean_env.setenv("OPENAI_API_KEY", "o-key")
    import logging
    with caplog.at_level(logging.WARNING):
        config = _get_default_primary_model(
            prefer=["nonexistent", "openai"]
        )
    assert config.provider == "openai"


def test_prefer_falls_through_to_claudecode(
    clean_env, no_thinking_model, no_ollama, monkeypatch,
) -> None:
    """Keyless preference: cve-diff says ``prefer="anthropic"``,
    operator has nothing set up, ``claude`` is on PATH → CC subprocess.
    The complete fallback chain ends here."""
    monkeypatch.setattr("shutil.which", lambda b: "/usr/bin/claude" if b == "claude" else None)
    config = _get_default_primary_model(prefer="anthropic")
    assert config.provider == "claudecode"


# ---------------------------------------------------------------------------
# Operator thinking-model interaction with prefer
# ---------------------------------------------------------------------------


def test_thinking_model_beats_env_var_default(
    clean_env, no_claudecode, no_ollama, monkeypatch,
) -> None:
    """Operator's explicit thinking-model config beats env-var
    default-order. If operator has Gemini in models.json AND has
    OPENAI_API_KEY env var, default-order returns Gemini (the
    explicit choice) not OpenAI (just an env var)."""
    fake_thinking = ModelConfig(
        provider="gemini",
        model_name="gemini-2.5-pro",
        api_key="fake",
        api_base="https://generativelanguage.googleapis.com/v1beta/openai",
    )
    monkeypatch.setattr(
        "core.llm.config._get_best_thinking_model",
        lambda: fake_thinking,
    )
    clean_env.setenv("OPENAI_API_KEY", "o-key")
    config = _get_default_primary_model()
    assert config.provider == "gemini"


def test_prefer_env_var_beats_operator_thinking_model(
    clean_env, no_claudecode, no_ollama, monkeypatch,
) -> None:
    """When consumer says prefer="anthropic" and Anthropic IS
    available via env var, that beats the operator's thinking model
    — the consumer's explicit signal is the strongest signal."""
    fake_thinking = ModelConfig(
        provider="gemini",
        model_name="gemini-2.5-pro",
        api_key="fake",
        api_base="https://generativelanguage.googleapis.com/v1beta/openai",
    )
    monkeypatch.setattr(
        "core.llm.config._get_best_thinking_model",
        lambda: fake_thinking,
    )
    clean_env.setenv("ANTHROPIC_API_KEY", "a-key")
    config = _get_default_primary_model(prefer="anthropic")
    assert config.provider == "anthropic"


def test_prefer_unavailable_falls_to_thinking_model(
    clean_env, no_claudecode, no_ollama, monkeypatch,
) -> None:
    """Consumer prefers Anthropic, env var not set, operator has
    Gemini configured → falls through to operator's Gemini rather
    than dropping all the way to claudecode. Operator's explicit
    config still beats unconfigured fallbacks."""
    fake_thinking = ModelConfig(
        provider="gemini",
        model_name="gemini-2.5-pro",
        api_key="fake",
        api_base="https://generativelanguage.googleapis.com/v1beta/openai",
    )
    monkeypatch.setattr(
        "core.llm.config._get_best_thinking_model",
        lambda: fake_thinking,
    )
    config = _get_default_primary_model(prefer="anthropic")
    assert config.provider == "gemini"


# ---------------------------------------------------------------------------
# LLMClient.primary_provider — public accessor for tool-use consumers
# ---------------------------------------------------------------------------


def test_llmclient_primary_provider_returns_provider_instance(
    clean_env, no_thinking_model, no_claudecode, no_ollama,
) -> None:
    """The accessor surfaces the provider for the configured
    primary_model. Cached: same instance returned across calls."""
    pytest.importorskip("anthropic")
    clean_env.setenv("ANTHROPIC_API_KEY", "test-key")
    from core.llm.client import LLMClient
    from core.llm.providers import LLMProvider
    cfg = LLMConfig(primary_model=_get_default_primary_model())
    client = LLMClient(cfg)

    p1 = client.primary_provider
    p2 = client.primary_provider
    assert isinstance(p1, LLMProvider)
    assert p1 is p2          # cached


def test_llmclient_primary_provider_raises_without_primary_model() -> None:
    """When no primary_model is configured, the accessor raises a
    clear error rather than returning None silently. Callers should
    have used ``get_client()`` (which returns ``None``) instead of
    constructing LLMClient directly."""
    from core.llm.client import LLMClient
    cfg = LLMConfig.__new__(LLMConfig)             # bypass autodetect
    cfg.primary_model = None
    cfg.fallback_models = []
    cfg.specialized_models = {}
    cfg.enable_fallback = True
    cfg.max_retries = 3
    cfg.retry_delay = 2.0
    cfg.retry_delay_remote = 5.0
    cfg.enable_caching = False
    from pathlib import Path
    cfg.cache_dir = Path("/tmp")
    cfg.enable_cost_tracking = False
    cfg.max_cost_per_scan = 10.0
    client = LLMClient.__new__(LLMClient)
    client.config = cfg
    client.providers = {}
    import threading
    client._key_locks = {}
    client._key_locks_guard = threading.Lock()

    with pytest.raises(RuntimeError, match="primary_model"):
        _ = client.primary_provider


# ---------------------------------------------------------------------------
# get_client(prefer=...) — the public entrypoint cve-diff uses
# ---------------------------------------------------------------------------


def test_get_client_with_prefer_kwarg(
    clean_env, no_thinking_model, no_claudecode, no_ollama,
) -> None:
    pytest.importorskip("anthropic")
    clean_env.setenv("ANTHROPIC_API_KEY", "a-key")
    clean_env.setenv("MISTRAL_API_KEY", "m-key")

    from packages.llm_analysis import get_client
    client = get_client(prefer="mistral")
    assert client is not None
    assert client.config.primary_model.provider == "mistral"


def test_get_client_returns_none_when_no_provider(
    clean_env, no_thinking_model, no_claudecode, no_ollama,
) -> None:
    """No keys, no thinking model, no claude binary → ``None``.
    Callers can then surface a clear "configure an LLM" error to
    the operator."""
    from packages.llm_analysis import get_client
    assert get_client() is None
    assert get_client(prefer="anthropic") is None
