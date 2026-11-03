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

from cve_diff.llm.auth import resolve_auth


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
    """
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
    monkeypatch.setenv("RAPTOR_LLM_SOCKET", "./fake.sock")
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
    os.environ["RAPTOR_LLM_SOCKET"] = "./fake.sock"
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
# Auth handoff contract
# ---------------------------------------------------------------------


def test_auth_reads_only_dispatcher_and_anthropic_fallback_env(monkeypatch):
    """Provider credentials belong to core; cve-diff only chooses its auth path."""
    from types import SimpleNamespace
    from unittest.mock import Mock
    from cve_diff.llm import auth

    env = Mock()
    env.get.return_value = None
    monkeypatch.setattr(auth, "os", SimpleNamespace(environ=env))
    decision = resolve_auth("claude-opus-4-7")
    assert decision.provider == "claudecode"
    assert {call.args[0] for call in env.get.call_args_list} == {
        "RAPTOR_LLM_SOCKET", "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN",
    }


def test_provider_resolution_is_delegated_to_core(monkeypatch):
    """A provider returned by core needs no cve-diff-specific registration."""
    monkeypatch.setattr("core.security.llm_family.provider_of", lambda model: "example-provider")
    monkeypatch.setenv("RAPTOR_LLM_SOCKET", "./fake.sock")
    decision = resolve_auth("example-model")
    assert decision.provider == "example-provider"
    assert decision.api_key is None
    assert decision.via_dispatcher is True


# ---------- default_model_id ----------


def test_default_model_id_uses_shared_registry(monkeypatch):
    from types import SimpleNamespace

    from cve_diff.llm.auth import default_model_id

    monkeypatch.setattr(
        "core.llm.config._get_default_primary_model",
        lambda prefer=None: SimpleNamespace(model_name="gemini-2.5-pro"),
    )
    assert default_model_id() == "gemini-2.5-pro"


def test_default_model_id_falls_back_when_unconfigured(monkeypatch):
    from cve_diff.llm.auth import FALLBACK_MODEL_ID, default_model_id

    monkeypatch.setattr(
        "core.llm.config._get_default_primary_model",
        lambda prefer=None: None,
    )
    assert default_model_id() == FALLBACK_MODEL_ID


def test_default_model_id_survives_registry_errors(monkeypatch):
    from cve_diff.llm.auth import FALLBACK_MODEL_ID, default_model_id

    def _boom(prefer=None):
        raise RuntimeError("registry unavailable")

    monkeypatch.setattr("core.llm.config._get_default_primary_model", _boom)
    assert default_model_id() == FALLBACK_MODEL_ID


def test_auth_token_spelling_keeps_direct_sdk_route(monkeypatch):
    """ANTHROPIC_AUTH_TOKEN is first-party SDK auth (see
    core.security.credential_env.ANTHROPIC_FIRST_PARTY_AUTH_VARS) —
    a bearer-token-only operator must not be demoted to the
    claudecode subprocess route."""
    monkeypatch.setenv("ANTHROPIC_AUTH_TOKEN", "sk-ant-test-bearer")
    decision = resolve_auth("claude-opus-4-7")
    assert decision.provider == "anthropic"


def test_claude_code_oauth_token_alone_still_falls_back(monkeypatch):
    """CLAUDE_CODE_OAUTH_TOKEN is NOT SDK auth — the claudecode
    fallback is exactly right for it."""
    monkeypatch.setenv("CLAUDE_CODE_OAUTH_TOKEN", "test-oauth")
    decision = resolve_auth("claude-opus-4-7")
    assert decision.provider == "claudecode"
