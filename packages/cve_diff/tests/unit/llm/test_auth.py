"""Tests for cve-diff's model→provider→auth resolver.

Covers:
  * model-id → provider routing for every supported family
  * RAPTOR_LLM_SOCKET takes precedence (dispatcher route)
  * env-var direct auth (any provider's env var lets the SDK
    pick it up without cve-diff naming the var)
  * Claude Code OAuth fallback for Anthropic models when no
    other auth is available
  * Non-Anthropic models never get the CC fallback
"""

from __future__ import annotations

import os

import pytest

from cve_diff.llm.auth import AuthDecision, resolve_auth


@pytest.fixture(autouse=True)
def _clean_llm_env(monkeypatch):
    """Strip every LLM-provider env var + RAPTOR_LLM_SOCKET so each
    test starts from a known state. Pulls the canonical list from
    central config — no cve-diff-local enumeration."""
    from core.config import RaptorConfig
    for var in RaptorConfig.LLM_API_KEY_VARS:
        monkeypatch.delenv(var, raising=False)
    monkeypatch.delenv("RAPTOR_LLM_SOCKET", raising=False)


# ---------------------------------------------------------------------
# Provider resolution from model id
# ---------------------------------------------------------------------


@pytest.mark.parametrize(
    "model_id,expected_provider",
    [
        ("claude-opus-4-7",         "claudecode"),  # CC fallback (no key)
        ("claude-sonnet-4-6",       "claudecode"),
        ("claude-haiku-4-5",        "claudecode"),
    ],
)
def test_anthropic_models_fall_back_to_claudecode_without_auth(
    model_id, expected_provider,
):
    """Anthropic-family models with no env key + no dispatcher fall
    through to Claude Code OAuth — historical cve-diff behaviour
    preserved."""
    decision = resolve_auth(model_id)
    assert decision.provider == expected_provider
    assert decision.api_key is None
    assert decision.via_dispatcher is False


@pytest.mark.parametrize(
    "model_id,expected_provider",
    [
        ("claude-opus-4-7",      "anthropic"),
        ("gpt-5",                "openai"),
        ("gemini-2.5-pro",       "gemini"),
        ("mistral-large-latest", "mistral"),
    ],
)
def test_provider_from_model_id_with_anthropic_key(
    monkeypatch, model_id, expected_provider,
):
    """When ``ANTHROPIC_API_KEY`` is set, Anthropic models route to
    ``anthropic``. Other-family models still resolve to their own
    provider — cve-diff is model-agnostic. ``api_key`` stays None
    because cve-diff defers to the SDK to read its own env var
    (matches the central LLM-config pattern; cve-diff doesn't
    enumerate provider env vars itself)."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "real-anthropic")
    decision = resolve_auth(model_id)
    assert decision.provider == expected_provider
    assert decision.api_key is None
    assert decision.via_dispatcher is False


@pytest.mark.parametrize(
    "env_var,model_id,expected_provider",
    [
        ("OPENAI_API_KEY",  "gpt-5",                "openai"),
        ("GEMINI_API_KEY",  "gemini-2.5-pro",       "gemini"),
        ("MISTRAL_API_KEY", "mistral-large-latest", "mistral"),
    ],
)
def test_other_providers_resolve_with_their_env_var(
    monkeypatch, env_var, model_id, expected_provider,
):
    """Setting any non-Anthropic provider's env var lets cve-diff
    use that provider for matching models — no Anthropic key
    required, no Claude Code fallback. Operator with only Gemini
    can run cve-diff.

    Aggregator-prefixed models (``groq/...``, ``openrouter/...``)
    are deliberately not tested here — ``provider_of`` peels the
    aggregator prefix to find the underlying *family* (e.g.
    ``groq/llama-3.3-70b`` → ``ollama``/meta, not ``groq``), which
    is correct for cross-family safety but means routing to the
    aggregator API requires a separate aggregator-aware resolver.
    Pre-existing issue independent of this refactor; tracked
    separately."""
    monkeypatch.setenv(env_var, "real-key")
    decision = resolve_auth(model_id)
    assert decision.provider == expected_provider
    assert decision.via_dispatcher is False


# ---------------------------------------------------------------------
# Dispatcher route
# ---------------------------------------------------------------------


@pytest.mark.parametrize(
    "model_id,expected_provider",
    [
        ("claude-opus-4-7",      "anthropic"),
        ("gpt-5",                "openai"),
        ("gemini-2.5-pro",       "gemini"),
        ("mistral-large-latest", "mistral"),
    ],
)
def test_dispatcher_socket_overrides_other_paths(
    monkeypatch, model_id, expected_provider,
):
    """``RAPTOR_LLM_SOCKET`` set → dispatcher route wins over both
    env-direct and Claude Code fallback. The dispatcher's
    ``CredentialStore`` handles auth; cve-diff doesn't see keys."""
    monkeypatch.setenv("RAPTOR_LLM_SOCKET", "/tmp/fake.sock")
    # Even WITH Anthropic key set, dispatcher route still wins:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "would-be-direct")
    decision = resolve_auth(model_id)
    assert decision.via_dispatcher is True
    assert decision.provider == expected_provider
    # ``api_key`` is None — provider's dispatcher branch uses
    # the dispatcher's CredentialStore, not the value in env.
    assert decision.api_key is None


def test_dispatcher_skips_claudecode_fallback_for_anthropic():
    """Dispatcher route is a real auth path; Anthropic-with-dispatcher
    must NOT fall through to claudecode (which would dispatch via
    Claude Code OAuth instead of Anthropic API)."""
    os.environ["RAPTOR_LLM_SOCKET"] = "/tmp/fake.sock"
    try:
        decision = resolve_auth("claude-opus-4-7")
        assert decision.provider == "anthropic"
        assert decision.via_dispatcher is True
    finally:
        os.environ.pop("RAPTOR_LLM_SOCKET", None)


# ---------------------------------------------------------------------
# Negative cases
# ---------------------------------------------------------------------


def test_non_anthropic_model_no_auth_does_not_fall_to_claudecode():
    """An OpenAI / Gemini / Mistral model with no key + no dispatcher
    must NOT silently re-route to Claude Code (operator passed
    ``--model gpt-5``; falling to claudecode would silently use
    Claude instead). The decision is handed to ``core.llm.providers``
    which surfaces a clear SDK error at first call."""
    # No env var set, no dispatcher.
    decision = resolve_auth("gpt-5")
    assert decision.provider == "openai"
    assert decision.api_key is None
    assert decision.via_dispatcher is False
    # The "ok"-style boolean isn't on AuthDecision anymore — cve-diff
    # always hands off to providers.py and lets the SDK raise.
    # This test exists to pin that we don't quietly fall back.


def test_unknown_model_id_defaults_to_anthropic():
    """Provider resolver returns "" for unknown model ids; cve-diff
    falls back to Anthropic for the historical default-cheap
    behaviour. Important: a typo'd model name shouldn't crash hard;
    it should land somewhere sensible."""
    decision = resolve_auth("not-a-real-model-name-12345")
    # Falls to claudecode because no Anthropic key + no dispatcher.
    assert decision.provider == "claudecode"


# ---------------------------------------------------------------------
# Module-shape pin
# ---------------------------------------------------------------------


def test_auth_module_does_not_enumerate_provider_env_vars():
    """cve-diff's auth resolver must not maintain its own list of
    LLM-provider env vars — that list belongs in
    ``core.config.RaptorConfig.LLM_API_KEY_VARS`` (single source of
    truth). The resolver looks at exactly two env vars:
    ``ANTHROPIC_API_KEY`` (for the CC fallback decision) and
    ``RAPTOR_LLM_SOCKET`` (for dispatcher routing). Pin this so a
    future change that adds a new provider doesn't accidentally
    grow a parallel list here."""
    import inspect
    from cve_diff.llm import auth
    src = inspect.getsource(auth)
    # The only API-key env var name allowed in the source: Anthropic
    # (for the CC fallback). Other provider env vars must NOT appear.
    forbidden = [
        "OPENAI_API_KEY", "GEMINI_API_KEY", "MISTRAL_API_KEY",
        "GROQ_API_KEY", "TOGETHER_API_KEY", "OPENROUTER_API_KEY",
        "FIREWORKS_API_KEY", "DEEPINFRA_API_KEY",
        "PERPLEXITY_API_KEY", "COHERE_API_KEY",
        "REPLICATE_API_TOKEN", "AZURE_OPENAI_API_KEY",
    ]
    leaked = [v for v in forbidden if v in src]
    assert not leaked, (
        f"cve_diff/llm/auth.py enumerates provider env vars: "
        f"{leaked}. The central LLM config "
        f"(RaptorConfig.LLM_API_KEY_VARS) should be the only place "
        f"that lists them."
    )
