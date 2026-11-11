"""Permitted output cost cannot be clipped to a typical-call reservation."""
import json
from dataclasses import replace
from types import SimpleNamespace

import httpx
import pytest

from core.llm import detection, http_pool
from core.llm.budget_errors import LLMBudgetExceededError
from core.llm.client import LLMClient
from core.llm.config import LLMConfig, ModelConfig


@pytest.fixture
def scripted_client(monkeypatch, tmp_path):
    calls = []

    def respond(request):
        payload = json.loads(request.content)
        calls.append(payload)
        return httpx.Response(200, request=request, json={
            "id": "captured-completion", "object": "chat.completion", "created": 0,
            "model": payload["model"],
            "choices": [{"index": 0, "message": {"role": "assistant", "content": "captured"},
                         "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 5, "completion_tokens": 8, "total_tokens": 13},
        })

    transport = httpx.MockTransport(respond)
    monkeypatch.setattr(http_pool, "_keepalive_transport_and_mounts",
                        lambda **kwargs: (transport, {}))
    monkeypatch.setattr(detection, "detect_llm_availability",
                        lambda: SimpleNamespace(external_llm=True))
    clients = []

    def build(*, model_name="gpt-4o", max_tokens=16000, fallback_rate=0.0,
              tracking=True):
        model = ModelConfig(provider="openai", model_name=model_name, api_key="inert",
                            api_base="https://scripted.invalid/v1", max_tokens=max_tokens,
                            cost_per_1k_tokens=fallback_rate)
        client = LLMClient(LLMConfig(primary_model=model, fallback_models=[],
            enable_fallback=False, max_retries=1, enable_caching=False,
            enable_cost_tracking=tracking, max_cost_per_scan=0.12,
            max_calls_per_scan=1, scorecard_enabled=False,
            cache_dir=tmp_path / "cache", scorecard_path=tmp_path / "scorecard"))
        clients.append(client)
        return client

    try:
        yield build, calls
    finally:
        for client in clients:
            for provider in client.providers.values():
                provider.client.close()
        transport.close()


@pytest.mark.parametrize("structured", [False, True], ids=["text", "structured"])
@pytest.mark.parametrize("model_name,rate", [("gpt-4o", 0.0), ("priced-override-control", 0.01)],
                         ids=["table-price", "configured-price"])
def test_output_allowance_must_fit_before_dispatch(scripted_client, structured, model_name, rate):
    build, calls = scripted_client
    client = build(model_name=model_name, fallback_rate=rate)
    assert client._estimate_call_cost("review") == pytest.approx(0.1)
    with pytest.raises(LLMBudgetExceededError):
        if structured:
            client.generate_structured("captured", {"type": "object"}, call_class="review")
        else:
            client.generate("captured", call_class="review")
    assert calls == []
    assert client.provider_spend_usd == client.reported_spend_usd == 0
    assert client._inflight_budget_reserve == 0


@pytest.mark.parametrize("override", [False, True], ids=["configured", "per-call"])
def test_small_output_allowance_reaches_actual_sdk_once(scripted_client, override):
    build, calls = scripted_client
    client = build(max_tokens=16000 if override else 16)
    response = client.generate("captured", **({"max_tokens": 16} if override else {}))
    assert len(calls) == 1 and calls[0]["max_tokens"] == 16
    assert response.content == "captured"
    assert response.cost == pytest.approx(0.0000925)
    assert client.reported_spend_usd == pytest.approx(response.cost)
    assert client._inflight_budget_reserve == 0


def test_disabled_dollar_tracking_keeps_existing_behavior(scripted_client):
    build, calls = scripted_client
    client = build(tracking=False)
    client.generate("captured")
    assert len(calls) == 1 and calls[0]["max_tokens"] == 16000
    assert client._inflight_budget_reserve == 0


@pytest.mark.parametrize("cached,selected,refused", [(16000, 16, True), (16, 16000, False)],
                         ids=["cached-high", "cached-low"])
def test_default_ceiling_follows_the_actual_cached_provider(scripted_client, cached, selected, refused):
    build, calls = scripted_client
    client = build(max_tokens=cached)
    provider = client.primary_provider
    other_config = replace(client.config.primary_model, max_tokens=selected)
    if refused:
        with pytest.raises(LLMBudgetExceededError):
            client.generate("captured", model_config=other_config)
        assert calls == []
    else:
        client.generate("captured", model_config=other_config)
        assert len(calls) == 1 and calls[0]["max_tokens"] == cached
    assert client.primary_provider is provider
