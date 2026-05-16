"""ResilientLLMClient tests — mocks the core.llm provider layer.

Migrated from Anthropic SDK mocks to core.llm substrate mocks on
2026-05-04. The client now delegates to ``create_provider`` which
returns an ``LLMProvider``; tests mock the provider's ``generate()``
method.
"""

from __future__ import annotations

from dataclasses import dataclass
from unittest.mock import MagicMock, patch

import pytest

from cve_diff.llm.client import (
    CostBudgetExceeded,
    LLMCallFailed,
    ResilientLLMClient,
    _provider_for_model,
)


@dataclass
class _FakeLLMResponse:
    content: str = "ok"
    model: str = "claude-opus-4-7"
    provider: str = "anthropic"
    tokens_used: int = 15
    cost: float = 0.0525
    finish_reason: str = "end_turn"
    input_tokens: int = 10
    output_tokens: int = 5
    thinking_tokens: int = 0
    duration: float = 0.5


def _mock_provider(resp=None):
    provider = MagicMock()
    provider.generate.return_value = resp or _FakeLLMResponse()
    return provider


def test_successful_completion_returns_text_and_usage():
    provider = _mock_provider(_FakeLLMResponse(
        content="hi", input_tokens=12, output_tokens=3,
        cost=0.000255,
    ))
    client = ResilientLLMClient()
    with patch.object(client, "_get_provider", return_value=provider):
        result = client.complete("claude-opus-4-7", "hello")
    assert result.text == "hi"
    assert result.model_id == "claude-opus-4-7"
    assert result.input_tokens == 12
    assert result.output_tokens == 3


def test_provider_error_raises_llm_call_failed():
    provider = _mock_provider()
    provider.generate.side_effect = RuntimeError("API down")
    client = ResilientLLMClient()
    with patch.object(client, "_get_provider", return_value=provider):
        with pytest.raises(LLMCallFailed, match="API down"):
            client.complete("m", "p")


def test_cost_tracked_on_successful_call():
    provider = _mock_provider(_FakeLLMResponse(
        input_tokens=1000, output_tokens=500, cost=0.0525,
    ))
    client = ResilientLLMClient()
    with patch.object(client, "_get_provider", return_value=provider):
        result = client.complete("claude-opus-4-7", "hello")
    assert result.cost_usd == pytest.approx(0.0525, rel=1e-4)
    assert client.cumulative_cost_usd == pytest.approx(0.0525, rel=1e-4)


def test_cost_budget_blocks_next_call():
    provider = _mock_provider(_FakeLLMResponse(cost=50.0))
    client = ResilientLLMClient(max_cost_usd=0.10)
    with patch.object(client, "_get_provider", return_value=provider):
        client.complete("claude-opus-4-7", "p1")
        assert client.cumulative_cost_usd > 0.10
        with pytest.raises(CostBudgetExceeded):
            client.complete("claude-opus-4-7", "p2")
    assert provider.generate.call_count == 1


def test_cost_budget_disabled_with_high_ceiling():
    provider = _mock_provider(_FakeLLMResponse(cost=0.001))
    client = ResilientLLMClient(max_cost_usd=1e9)
    with patch.object(client, "_get_provider", return_value=provider):
        for _ in range(3):
            client.complete("claude-opus-4-7", "p")
    assert client.cumulative_cost_usd > 0


def test_system_prompt_forwarded_to_provider():
    provider = _mock_provider()
    client = ResilientLLMClient()
    with patch.object(client, "_get_provider", return_value=provider):
        client.complete("m", "hello", system="you are a robot")
    _, kwargs = provider.generate.call_args
    assert kwargs["system_prompt"] == "you are a robot"


def test_no_system_passes_none():
    provider = _mock_provider()
    client = ResilientLLMClient()
    with patch.object(client, "_get_provider", return_value=provider):
        client.complete("m", "hello")
    _, kwargs = provider.generate.call_args
    assert kwargs.get("system_prompt") is None


def test_temperature_forwarded():
    provider = _mock_provider()
    client = ResilientLLMClient()
    with patch.object(client, "_get_provider", return_value=provider):
        client.complete("m", "hello", temperature=0.5)
    _, kwargs = provider.generate.call_args
    assert kwargs["temperature"] == 0.5


def test_provider_cached_per_model():
    client = ResilientLLMClient()
    with patch("cve_diff.llm.client._provider_for_model") as factory:
        factory.return_value = _mock_provider()
        client.complete("claude-opus-4-7", "p1")
        client.complete("claude-opus-4-7", "p2")
    assert factory.call_count == 1


def test_provider_for_model_uses_anthropic_when_key_set(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    with patch("cve_diff.llm.client.create_provider") as cp:
        cp.return_value = _mock_provider()
        _provider_for_model("claude-opus-4-7", 120.0)
    config = cp.call_args[0][0]
    assert config.provider == "anthropic"
    assert config.model_name == "claude-opus-4-7"


def test_provider_for_model_falls_back_to_claudecode(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    with patch("cve_diff.llm.client.create_provider") as cp:
        cp.return_value = _mock_provider()
        _provider_for_model("claude-opus-4-7", 120.0)
    config = cp.call_args[0][0]
    assert config.provider == "claudecode"
