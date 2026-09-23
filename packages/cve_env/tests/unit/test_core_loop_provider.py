"""Provider resolution: first-party auth spellings and the claudecode
fallback boundary."""

from __future__ import annotations

import pytest

from cve_env.agent import core_loop


@pytest.fixture()
def _capture_provider(monkeypatch):
    captured: dict = {}
    monkeypatch.setattr(
        core_loop, "create_provider", lambda mc: captured.setdefault("mc", mc)
    )
    import core.llm.dispatcher.lifecycle as lifecycle

    monkeypatch.setattr(
        lifecycle, "ensure_route_for_model_configs", lambda *a, **k: None
    )
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_AUTH_TOKEN", raising=False)
    monkeypatch.delenv("RAPTOR_LLM_SOCKET", raising=False)
    return captured


def test_auth_token_spelling_keeps_direct_sdk_route(
    _capture_provider, monkeypatch
) -> None:
    """ANTHROPIC_AUTH_TOKEN is first-party SDK auth (see
    core.security.credential_env.ANTHROPIC_FIRST_PARTY_AUTH_VARS) — a
    bearer-token-only operator must not be demoted to the claudecode
    subprocess route."""
    monkeypatch.setenv("ANTHROPIC_AUTH_TOKEN", "sk-ant-test-bearer")
    core_loop._resolve_provider("claude-sonnet-4-6")
    assert _capture_provider["mc"].provider == "anthropic"


def test_no_first_party_auth_falls_back_to_claudecode(
    _capture_provider,
) -> None:
    core_loop._resolve_provider("claude-sonnet-4-6")
    assert _capture_provider["mc"].provider == "claudecode"
