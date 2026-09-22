"""Spend-aware gate on the providers' ``turn()`` transient-retry loops.

Sibling surface of ``LLMClient``'s attempt loops (covered in
``test_consumed_attempt_gate.py``): the non-streaming ``turn()`` loops
classify connection errors transient and re-send — including
mid-response deaths whose generation the upstream already processed
and billed. The gate (one shared veto, one escape hatch) must make
those terminal for the turn while pre-response transient behaviour is
preserved. ``turn_stream()`` loops need no gate: they wrap the stream
OPEN alone, which completes at the response head, before any billed
output is at stake.

Hermetic — stub SDK clients and synthetic hook state.
"""

from __future__ import annotations

import logging
import time

import pytest

import core.llm.dispatcher.client as dispatcher_client
from core.llm.providers import ModelConfig


@pytest.fixture(autouse=True)
def _clean_attempt_state():
    dispatcher_client._attempt_state.response_started = False
    yield
    dispatcher_client._attempt_state.response_started = False


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch):
    monkeypatch.setattr(time, "sleep", lambda _s: None)


def _mark_response_started() -> None:
    dispatcher_client._attempt_state.response_started = True


def _turn_messages():
    from core.llm.tool_use import Message, TextBlock
    return [Message(role="user", content=[TextBlock(text="x")])]


def _anthropic_provider():
    pytest.importorskip("anthropic")
    from core.llm.providers import AnthropicProvider
    return AnthropicProvider(ModelConfig(
        provider="anthropic", model_name="claude-opus-4-6",
        api_key="test-key", timeout=1,
    ))


def _openai_provider():
    pytest.importorskip("openai")
    from core.llm.providers import OpenAICompatibleProvider
    return OpenAICompatibleProvider(ModelConfig(
        provider="openai", model_name="gpt-5.2",
        api_key="sk-test", timeout=1,
    ))


def _stub_anthropic_client(calls: dict, *, mark_started: bool):
    import anthropic
    import httpx

    class _Messages:
        def create(self, **_kwargs):
            calls["n"] += 1
            if mark_started:
                _mark_response_started()
            raise anthropic.APIConnectionError(
                request=httpx.Request("POST", "http://unit.test"),
            )

    class _Client:
        messages = _Messages()

    return _Client()


def _stub_openai_client(calls: dict, *, mark_started: bool):
    import httpx
    import openai

    class _Completions:
        def create(self, **_kwargs):
            calls["n"] += 1
            if mark_started:
                _mark_response_started()
            raise openai.APIConnectionError(
                request=httpx.Request("POST", "http://unit.test"),
            )

    class _Chat:
        completions = _Completions()

    class _Client:
        chat = _Chat()

    return _Client()


class TestAnthropicTurnConsumedGate:
    def test_mid_response_death_is_terminal_not_resent(self, caplog):
        provider = _anthropic_provider()
        calls = {"n": 0}
        provider.client = _stub_anthropic_client(calls, mark_started=True)
        with caplog.at_level(logging.WARNING):
            resp = provider.turn(messages=_turn_messages(), tools=[])
        assert calls["n"] == 1
        assert resp.error_message is not None
        assert "already processed and billed" in resp.error_message
        assert any(
            "NOT re-sending" in r.getMessage() for r in caplog.records
        )

    def test_pre_response_connection_error_keeps_transient_retry(self):
        provider = _anthropic_provider()
        calls = {"n": 0}
        provider.client = _stub_anthropic_client(calls, mark_started=False)
        resp = provider.turn(messages=_turn_messages(), tools=[])
        # Default budget: max_retries=3 → 4 attempts, then terminal.
        assert calls["n"] == 4
        assert resp.error_message is not None
        assert "transient error" in resp.error_message

    def test_escape_hatch_keeps_paid_retries(self, caplog, monkeypatch):
        monkeypatch.setenv("RAPTOR_LLM_RETRY_CONSUMED", "1")
        provider = _anthropic_provider()
        calls = {"n": 0}
        provider.client = _stub_anthropic_client(calls, mark_started=True)
        with caplog.at_level(logging.WARNING):
            resp = provider.turn(messages=_turn_messages(), tools=[])
        assert calls["n"] == 4
        assert resp.error_message is not None
        assert sum(
            "re-buys the generation" in r.getMessage()
            for r in caplog.records
        ) == 4


class TestOpenAITurnConsumedGate:
    def test_mid_response_death_is_terminal_not_resent(self, caplog):
        provider = _openai_provider()
        calls = {"n": 0}
        provider.client = _stub_openai_client(calls, mark_started=True)
        with caplog.at_level(logging.WARNING):
            resp = provider.turn(messages=_turn_messages(), tools=[])
        assert calls["n"] == 1
        assert resp.error_message is not None
        assert "already processed and billed" in resp.error_message
        assert any(
            "NOT re-sending" in r.getMessage() for r in caplog.records
        )

    def test_pre_response_connection_error_keeps_transient_retry(self):
        provider = _openai_provider()
        calls = {"n": 0}
        provider.client = _stub_openai_client(calls, mark_started=False)
        resp = provider.turn(messages=_turn_messages(), tools=[])
        assert calls["n"] == 4
        assert resp.error_message is not None
