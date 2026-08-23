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


class TestStructuredInstructorLeg:
    """``_streamify_messages_create`` rebinds ``messages.create`` so
    instructor's structured calls — which bypass ``generate()`` and
    hit ``create`` directly — inherit the opt-in streaming transport.
    Structured study batches on a thinking model are the calls that
    exceed upstream's ~10-minute non-streaming abort."""

    def _patched_client(self, monkeypatch):
        monkeypatch.delenv("RAPTOR_LLM_STREAM_TRANSPORT", raising=False)
        from core.llm.providers import _streamify_messages_create
        client = _FakeClient(_response())
        _streamify_messages_create(client)
        return client

    def test_default_delegates_to_create(self, monkeypatch):
        client = self._patched_client(monkeypatch)
        out = client.messages.create(model="m", max_tokens=5, messages=[])
        assert out.content[0].text == "pong"
        assert len(client.create_calls) == 1
        assert not client.stream_calls

    def test_opt_in_routes_via_stream(self, monkeypatch):
        client = self._patched_client(monkeypatch)
        monkeypatch.setenv("RAPTOR_LLM_STREAM_TRANSPORT", "1")
        out = client.messages.create(model="m", max_tokens=5, messages=[])
        # Identical Message via get_final_message — instructor's
        # parsing/validation unchanged.
        assert out.content[0].text == "pong"
        assert len(client.stream_calls) == 1
        assert not client.create_calls
        assert client.stream_calls[0]["model"] == "m"

    def test_gate_read_per_call_not_at_patch_time(self, monkeypatch):
        client = self._patched_client(monkeypatch)
        client.messages.create(model="m", max_tokens=5, messages=[])
        monkeypatch.setenv("RAPTOR_LLM_STREAM_TRANSPORT", "1")
        client.messages.create(model="m", max_tokens=5, messages=[])
        assert len(client.create_calls) == 1
        assert len(client.stream_calls) == 1

    def test_stream_kwarg_never_forwarded(self, monkeypatch):
        # ``messages.stream`` rejects an explicit ``stream=`` kwarg;
        # a caller passing one must not break the rerouted path.
        client = self._patched_client(monkeypatch)
        monkeypatch.setenv("RAPTOR_LLM_STREAM_TRANSPORT", "1")
        client.messages.create(model="m", max_tokens=5, messages=[],
                               stream=False)
        assert "stream" not in client.stream_calls[0]

    def test_provider_construction_wires_the_patch(self, monkeypatch):
        pytest.importorskip("anthropic")
        pytest.importorskip("instructor")
        monkeypatch.delenv("RAPTOR_LLM_SOCKET", raising=False)
        from core.llm.config import ModelConfig
        from core.llm.providers import AnthropicProvider
        provider = AnthropicProvider(ModelConfig(
            provider="anthropic", model_name="claude-opus-4-7",
            api_key="sk-test", timeout=1,
        ))
        assert (provider.client.messages.create.__name__
                == "_create_via_stream_transport")


class TestPerCallOptIn:
    """``stream=True`` on a single call rides the streaming transport
    without the env knob — the caller knows its response is long
    (study batches), which topology detection cannot."""

    def test_generate_stream_kwarg_uses_stream_transport(self, provider):
        resp = provider.generate("ping", stream=True)
        assert resp.content == "pong"
        assert len(_fake(provider).stream_calls) == 1
        assert not _fake(provider).create_calls
        # The opt-in kwarg is transport routing, not a request param.
        assert "stream" not in _fake(provider).stream_calls[0]

    def test_generate_sse_incapable_surface_degrades_to_create(
        self, provider,
    ):
        provider._stream_sse_ok = False
        provider.generate("ping", stream=True)
        assert len(_fake(provider).create_calls) == 1
        assert not _fake(provider).stream_calls

    def test_structured_stream_kwarg_scopes_thread_local(self, provider):
        from core.llm import providers as P
        seen = {}

        def fake_impl(prompt, schema, system_prompt=None, **kw):
            seen["during"] = P._stream_override_active()
            return "ok"

        provider._generate_structured_impl = fake_impl
        assert provider.generate_structured("p", {}, stream=True) == "ok"
        assert seen["during"] is True
        # Cleared after the call — the override must never leak into
        # a sibling call on the same worker thread.
        assert P._stream_override_active() is False

    def test_structured_without_stream_leaves_override_off(self, provider):
        from core.llm import providers as P
        seen = {}

        def fake_impl(prompt, schema, system_prompt=None, **kw):
            seen["during"] = P._stream_override_active()
            return "ok"

        provider._generate_structured_impl = fake_impl
        provider.generate_structured("p", {})
        assert seen["during"] is False

    def test_structured_sse_incapable_surface_ignores_opt_in(
        self, provider,
    ):
        from core.llm import providers as P
        seen = {}

        def fake_impl(prompt, schema, system_prompt=None, **kw):
            seen["during"] = P._stream_override_active()
            return "ok"

        provider._stream_sse_ok = False
        provider._generate_structured_impl = fake_impl
        provider.generate_structured("p", {}, stream=True)
        assert seen["during"] is False

    def test_nested_opt_in_restores_outer_override(self, provider):
        # A nested opted-in call must restore (not clear) the override,
        # or the remainder of the outer call silently goes non-streaming.
        from core.llm import providers as P
        states = []

        def inner_impl(prompt, schema, system_prompt=None, **kw):
            return "inner"

        def outer_impl(prompt, schema, system_prompt=None, **kw):
            provider._generate_structured_impl = inner_impl
            provider.generate_structured("q", {}, stream=True)
            states.append(P._stream_override_active())
            return "outer"

        provider._generate_structured_impl = outer_impl
        assert provider.generate_structured("p", {}, stream=True) == "outer"
        assert states == [True]
        assert P._stream_override_active() is False

    def test_override_cleared_even_when_impl_raises(self, provider):
        from core.llm import providers as P

        def fake_impl(prompt, schema, system_prompt=None, **kw):
            raise RuntimeError("boom")

        provider._generate_structured_impl = fake_impl
        with pytest.raises(RuntimeError):
            provider.generate_structured("p", {}, stream=True)
        assert P._stream_override_active() is False

    def test_rebound_create_honours_override(self, monkeypatch):
        monkeypatch.delenv("RAPTOR_LLM_STREAM_TRANSPORT", raising=False)
        from core.llm import providers as P
        client = _FakeClient(_response())
        P._streamify_messages_create(client)
        P._STREAM_OVERRIDE.on = True
        try:
            client.messages.create(model="m", max_tokens=5, messages=[])
        finally:
            P._STREAM_OVERRIDE.on = False
        assert len(client.stream_calls) == 1
        assert not client.create_calls


@pytest.mark.parametrize("value,expected", [
    ("1", True), ("true", True), ("YES", True), ("on", True),
    ("0", False), ("false", False), ("", False), ("off", False),
])
def test_env_gate_spellings(monkeypatch, value, expected):
    from core.llm.providers import _stream_transport_enabled
    monkeypatch.setenv("RAPTOR_LLM_STREAM_TRANSPORT", value)
    assert _stream_transport_enabled() is expected
