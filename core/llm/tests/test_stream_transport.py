"""Opt-in streaming transport for non-streaming Anthropic calls.

``RAPTOR_LLM_STREAM_TRANSPORT=1`` carries ``generate()`` / ``turn()``
over ``messages.stream`` + ``get_final_message()`` — the identical
``Message`` object a plain ``create`` returns, so downstream parsing
is unchanged. The point is corporate proxies that idle-kill tunnels
carrying no bytes: SSE keeps bytes flowing for the whole generation.
Off by default; the task-budget beta endpoint always stays on plain
``create``.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from core.llm.tool_use.types import Message, StopReason, TextBlock


def _response():
    return SimpleNamespace(
        content=[SimpleNamespace(type="text", text="pong")],
        stop_reason="end_turn",
        usage=SimpleNamespace(
            input_tokens=5, output_tokens=3,
            cache_creation_input_tokens=0, cache_read_input_tokens=0,
        ),
        model="claude-sonnet-5",
    )


class _FakeStreamManager:
    def __init__(self, response):
        self._response = response

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def get_final_message(self):
        return self._response


class _FakeClient:
    """Records which transport carried each call."""

    def __init__(self, response):
        self.create_calls: list[dict] = []
        self.stream_calls: list[dict] = []
        self.beta_create_calls: list[dict] = []

        def create(**kw):
            self.create_calls.append(kw)
            return response

        def stream(**kw):
            self.stream_calls.append(kw)
            return _FakeStreamManager(response)

        def beta_create(**kw):
            self.beta_create_calls.append(kw)
            return response

        self.messages = SimpleNamespace(create=create, stream=stream)
        self.beta = SimpleNamespace(
            messages=SimpleNamespace(create=beta_create),
        )


@pytest.fixture
def provider(monkeypatch):
    monkeypatch.delenv("RAPTOR_LLM_SOCKET", raising=False)
    monkeypatch.delenv("RAPTOR_LLM_STREAM_TRANSPORT", raising=False)
    # Hermetic provider (core.testing): the transports are exercised
    # against _FakeClient, so construction must not require the
    # optional anthropic SDK; the error-type stub keeps the retry
    # taxonomy's `from anthropic import ...` satisfied on SDK-less
    # hosts.
    from core.testing import (
        ensure_anthropic_error_types,
        make_anthropic_provider,
    )

    ensure_anthropic_error_types(monkeypatch)
    return make_anthropic_provider(_FakeClient(_response()))


def _fake(p) -> _FakeClient:
    return p.client


class TestGenerate:

    def test_default_uses_create(self, provider):
        resp = provider.generate("ping")
        assert resp.content == "pong"
        assert len(_fake(provider).create_calls) == 1
        assert not _fake(provider).stream_calls

    def test_opt_in_uses_stream_transport(self, provider, monkeypatch):
        monkeypatch.setenv("RAPTOR_LLM_STREAM_TRANSPORT", "1")
        resp = provider.generate("ping")
        # Identical response object via get_final_message — parsing
        # unchanged.
        assert resp.content == "pong"
        assert len(_fake(provider).stream_calls) == 1
        assert not _fake(provider).create_calls
        # Same request kwargs either way.
        assert _fake(provider).stream_calls[0]["model"] == "claude-sonnet-5"


class TestTurn:

    _messages = [Message(role="user", content=[TextBlock(text="hi")])]

    def test_default_uses_create(self, provider):
        out = provider.turn(self._messages, tools=[])
        assert out.stop_reason == StopReason.COMPLETE
        assert len(_fake(provider).create_calls) == 1
        assert not _fake(provider).stream_calls

    def test_opt_in_uses_stream_transport(self, provider, monkeypatch):
        monkeypatch.setenv("RAPTOR_LLM_STREAM_TRANSPORT", "1")
        out = provider.turn(self._messages, tools=[])
        assert out.stop_reason == StopReason.COMPLETE
        assert out.content[0].text == "pong"
        assert len(_fake(provider).stream_calls) == 1
        assert not _fake(provider).create_calls

    def test_task_budget_beta_never_streams(self, provider, monkeypatch):
        """The cost-cap beta endpoint is create-only — the opt-in
        must not reroute it."""
        monkeypatch.setenv("RAPTOR_LLM_STREAM_TRANSPORT", "1")
        provider.turn(
            self._messages, tools=[],
            anthropic_task_budget_beta=True,
            anthropic_task_budget_tokens=1000,
        )
        assert len(_fake(provider).beta_create_calls) == 1
        assert not _fake(provider).stream_calls


@pytest.mark.parametrize("value,expected", [
    ("1", True), ("true", True), ("YES", True), ("on", True),
    ("0", False), ("false", False), ("", False), ("off", False),
])
def test_env_gate_spellings(monkeypatch, value, expected):
    from core.llm.providers import _stream_transport_enabled
    monkeypatch.setenv("RAPTOR_LLM_STREAM_TRANSPORT", value)
    assert _stream_transport_enabled() is expected
