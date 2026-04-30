"""ResilientLLMClient tests — mocks the Anthropic SDK directly.

Was previously OpenAI-SDK-via-LiteLLM-proxy. Migrated to Anthropic
SDK direct on 2026-05-01 to drop the LiteLLM operational dependency
(the agent loop already used Anthropic-direct; the analyzer now
matches). Tests mock ``client._client.messages.create`` instead of
``client._client.chat.completions.create``.
"""

from __future__ import annotations

import time
from unittest.mock import MagicMock, patch

import httpx
import pytest
from anthropic import APIConnectionError, APIStatusError

from cve_diff.llm.client import CostBudgetExceeded, LLMCallFailed, ResilientLLMClient


def _mk_response(text: str = "ok", in_t: int = 10, out_t: int = 5):
    """Build a stand-in for ``anthropic.types.Message``. Returns an
    object whose ``content`` is a list of text blocks (Anthropic shape)
    and whose ``usage`` has ``input_tokens`` / ``output_tokens``."""
    block = MagicMock()
    block.type = "text"
    block.text = text
    usage = MagicMock()
    usage.input_tokens = in_t
    usage.output_tokens = out_t
    resp = MagicMock()
    resp.content = [block]
    resp.usage = usage
    return resp


def test_successful_completion_returns_text_and_usage():
    client = ResilientLLMClient()
    with patch.object(client._client.messages, "create",
                      return_value=_mk_response("hi", 12, 3)):
        result = client.complete("claude-opus-4-7", "hello")
    assert result.text == "hi"
    assert result.model_id == "claude-opus-4-7"
    assert result.input_tokens == 12
    assert result.output_tokens == 3
    assert result.retries == 0


def test_transient_connection_error_is_retried(monkeypatch):
    monkeypatch.setattr(time, "sleep", lambda *_: None)
    client = ResilientLLMClient(max_retries=2)
    req = httpx.Request("POST", "https://api.anthropic.com/v1/messages")
    err = APIConnectionError(request=req)
    create = MagicMock(side_effect=[err, err, _mk_response("yay")])
    with patch.object(client._client.messages, "create", create):
        result = client.complete("m", "p")
    assert result.text == "yay"
    assert result.retries == 2
    assert create.call_count == 3


def test_transient_429_is_retried(monkeypatch):
    monkeypatch.setattr(time, "sleep", lambda *_: None)
    client = ResilientLLMClient(max_retries=1)
    http_resp = httpx.Response(
        status_code=429,
        request=httpx.Request("POST", "https://api.anthropic.com/v1/messages"),
    )
    err = APIStatusError("rate limited", response=http_resp, body=None)
    create = MagicMock(side_effect=[err, _mk_response("ok-after-429")])
    with patch.object(client._client.messages, "create", create):
        result = client.complete("m", "p")
    assert result.text == "ok-after-429"
    assert result.retries == 1


def test_permanent_4xx_raises_without_retry(monkeypatch):
    monkeypatch.setattr(time, "sleep", lambda *_: None)
    client = ResilientLLMClient(max_retries=3)
    http_resp = httpx.Response(
        status_code=400,
        request=httpx.Request("POST", "https://api.anthropic.com/v1/messages"),
    )
    err = APIStatusError("bad req", response=http_resp, body=None)
    create = MagicMock(side_effect=err)
    with patch.object(client._client.messages, "create", create):
        with pytest.raises(LLMCallFailed):
            client.complete("m", "p")
    assert create.call_count == 1  # no retries on permanent


def test_transient_exhausted_raises(monkeypatch):
    monkeypatch.setattr(time, "sleep", lambda *_: None)
    client = ResilientLLMClient(max_retries=2)
    req = httpx.Request("POST", "https://api.anthropic.com/v1/messages")
    err = APIConnectionError(request=req)
    create = MagicMock(side_effect=[err, err, err])
    with patch.object(client._client.messages, "create", create):
        with pytest.raises(LLMCallFailed):
            client.complete("m", "p")
    assert create.call_count == 3  # initial + 2 retries


def test_cost_tracked_on_successful_call():
    client = ResilientLLMClient()
    # opus: $15/M input + $75/M output. 1000 in + 500 out = 0.015 + 0.0375 = 0.0525
    with patch.object(client._client.messages, "create",
                      return_value=_mk_response("ok", 1000, 500)):
        result = client.complete("claude-opus-4-7", "hello")
    assert result.cost_usd == pytest.approx(0.0525, rel=1e-4)
    assert client.cumulative_cost_usd == pytest.approx(0.0525, rel=1e-4)


def test_cost_budget_blocks_next_call():
    client = ResilientLLMClient(max_cost_usd=0.10)
    # Two large opus calls at 1M input + 500k output each = $22.50 each.
    big_resp = _mk_response("expensive", 1_000_000, 500_000)
    create = MagicMock(return_value=big_resp)
    with patch.object(client._client.messages, "create", create):
        # first call goes through (we don't know cost pre-flight)
        client.complete("claude-opus-4-7", "p1")
        assert client.cumulative_cost_usd > 0.10
        # second call is blocked
        with pytest.raises(CostBudgetExceeded):
            client.complete("claude-opus-4-7", "p2")
    assert create.call_count == 1


def test_unknown_model_counts_zero_cost(capsys):
    client = ResilientLLMClient()
    with patch.object(client._client.messages, "create",
                      return_value=_mk_response("ok", 100, 50)):
        result = client.complete("some-fictional-model", "hi")
    assert result.cost_usd == 0.0
    assert client.cumulative_cost_usd == 0.0
    err = capsys.readouterr().err
    assert "some-fictional-model" in err


def test_cost_budget_disabled_with_high_ceiling():
    client = ResilientLLMClient(max_cost_usd=1e9)
    with patch.object(client._client.messages, "create",
                      return_value=_mk_response("ok", 10, 5)):
        for _ in range(3):
            client.complete("claude-opus-4-7", "p")
    assert client.cumulative_cost_usd > 0


def test_system_message_is_passed_as_top_level_field():
    """Anthropic API takes ``system`` as a top-level kwarg, not a
    {role: system} message. The migration must preserve this — passing
    a system message in the messages array would error against the API."""
    client = ResilientLLMClient()
    create = MagicMock(return_value=_mk_response())
    with patch.object(client._client.messages, "create", create):
        client.complete("m", "hello", system="you are a robot")
    _args, kwargs = create.call_args
    # Anthropic-shape: system is its own field
    assert kwargs["system"] == "you are a robot"
    # Messages list does NOT contain a system entry
    assert kwargs["messages"] == [{"role": "user", "content": "hello"}]


def test_no_system_means_no_system_kwarg():
    """When the caller doesn't pass system, the kwarg is omitted (not
    sent as None or empty string)."""
    client = ResilientLLMClient()
    create = MagicMock(return_value=_mk_response())
    with patch.object(client._client.messages, "create", create):
        client.complete("m", "hello")
    _args, kwargs = create.call_args
    assert "system" not in kwargs
