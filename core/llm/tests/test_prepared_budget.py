"""Prepared quotes use complete wire bytes and the existing billing arithmetic."""
from dataclasses import FrozenInstanceError
import json

import httpx
import pytest

from core.llm import model_data
from core.llm.budget_errors import LLMCallAdmissionRefused
from core.llm.config import ModelConfig
from core.llm.dispatcher.server import _request_cost_ceiling_usd
from core.llm.prepared_budget import quote_prepared_request
from core.llm.providers import LLMProvider


class _QuotedProvider(LLMProvider):
    def generate(self, *args, **kwargs):
        raise AssertionError("a quote must not generate")

    def generate_structured(self, *args, **kwargs):
        raise AssertionError("a quote must not generate")


def _provider(model="gpt-4o", rate=0.0):
    return _QuotedProvider(ModelConfig(provider="openai", model_name=model,
        api_key="inert", max_tokens=32000, cost_per_1k_tokens=rate))


def _body(model="gpt-4o", **changes):
    return {"model": model, "messages": [{"role": "user", "content": "captured λ"}],
            "max_tokens": 32, **changes}


def _request(body, path="/v1/chat/completions", *, method="POST"):
    return httpx.Request(method, "https://scripted.invalid" + path,
        content=json.dumps(body, ensure_ascii=False).encode("utf-8"))


@pytest.mark.parametrize("model,path", [
    ("gpt-4o", "/v1/chat/completions"), ("gpt-4o", "/openai/v1/chat/completions"),
    ("claude-sonnet-4-6", "/v1/messages"), ("claude-sonnet-4-6", "/anthropic/v1/messages"),
])
def test_complete_wire_quote_matches_existing_priced_bound(model, path):
    provider = _provider(model)
    request = _request(_body(model), path)
    before = request.content
    quote = quote_prepared_request(request, provider)
    assert quote.reservation_tokens == len(before) + 32
    assert quote.reservation_usd == pytest.approx(_request_cost_ceiling_usd(model, 32, len(before)))
    assert request.content == before and provider.total_cost == provider.total_tokens == 0
    with pytest.raises(FrozenInstanceError):
        quote.reservation_tokens = 0


def test_actual_wire_ceiling_overrides_the_cached_configuration_default():
    provider = _provider()
    request = _request(_body(max_tokens=2))
    quote = quote_prepared_request(request, provider)
    assert provider.config.max_tokens == 32000
    assert quote.reservation_tokens == len(request.content) + 2


def test_positive_configured_price_includes_input_when_catalogue_entry_is_absent():
    provider = _provider("quoted-rate-control", rate=0.02)
    request = _request(_body(provider.config.model_name))
    quote = quote_prepared_request(request, provider)
    expected = provider._calculate_cost_split(len(request.content), 32)
    assert quote.reservation_usd == pytest.approx(expected)
    assert quote.reservation_usd > provider._calculate_cost_split(0, 32)


def test_unknown_zero_price_is_not_evidence_of_free_generation():
    provider = _provider("quoted-unpriced-control")
    request = _request(_body(provider.config.model_name))
    with pytest.raises(LLMCallAdmissionRefused, match="pricing missing"):
        quote_prepared_request(request, provider)
    quote = quote_prepared_request(request, provider, track_cost=False)
    assert quote.reservation_usd == 0
    assert quote.reservation_tokens == len(request.content) + 32


def test_registered_zero_price_is_distinct_from_an_unknown_model(monkeypatch):
    monkeypatch.setitem(model_data.MODEL_COSTS, "quoted-zero-control", {"input": 0.0, "output": 0.0})
    provider = _provider("quoted-zero-control")
    quote = quote_prepared_request(_request(_body(provider.config.model_name)), provider)
    assert quote.reservation_usd == 0 and quote.reservation_tokens > 32


@pytest.mark.parametrize("rate", [float("nan"), float("inf"), -0.01, True])
def test_invalid_fallback_price_is_refused(rate):
    provider = _provider("quoted-invalid-rate", rate=rate)
    with pytest.raises(LLMCallAdmissionRefused):
        quote_prepared_request(_request(_body(provider.config.model_name)), provider)


def test_real_price_arithmetic_overflow_is_refused():
    provider = _provider("quoted-overflow-control", rate=1e308)
    with pytest.raises(LLMCallAdmissionRefused, match="pricing invalid"):
        quote_prepared_request(_request(_body(provider.config.model_name, max_tokens=16000)), provider)


def test_text_cache_and_local_function_schemas_are_supported():
    provider = _provider("claude-sonnet-4-6")
    request = _request(_body(provider.config.model_name,
        system=[{"type": "text", "text": "owned system", "cache_control": {"type": "ephemeral"}}],
        tools=[{"name": "Answer", "input_schema": {"type": "object", "properties": {
            "answer": {"$ref": "#/$defs/Answer"}}, "$defs": {"Answer": {"type": "string"}}}}],
        tool_choice={"type": "tool", "name": "Answer"}), "/v1/messages")
    assert quote_prepared_request(request, provider).reservation_tokens == len(request.content) + 32


def test_local_response_schemas_are_supported_without_remote_inputs():
    request = _request(_body(response_format={"type": "json_schema", "json_schema": {
        "name": "Answer", "schema": {"type": "object"}, "strict": True}}))
    assert quote_prepared_request(request, _provider()).reservation_tokens == len(request.content) + 32
    request = _request(_body(output_config={"effort": "medium", "format": {
        "type": "json_schema", "schema": {"type": "object"}}}), "/v1/messages")
    assert quote_prepared_request(request, _provider()).reservation_tokens == len(request.content) + 32


@pytest.mark.parametrize("changes", [
    {"stream": True}, {"stream": 0}, {"n": 2}, {"n": True}, {"best_of": 2},
    {"max_tokens": None}, {"max_tokens": 0}, {"max_tokens": True},
    {"previous_response_id": "remote"}, {"conversation": "remote"}, {"container": "remote"},
    {"mcp_servers": []}, {"future_semantics": "unknown"},
    {"messages": [{"role": "user", "content": [{"type": "image_url", "image_url": "remote"}]}]},
    {"messages": [{"role": "user", "content": None}]},
    {"messages": [{"role": "user", "content": "text", "file_id": "remote"}]},
    {"system": [{"type": "document", "source": "remote"}]},
    {"system": [{"type": "text", "text": "cached", "cache_control": {"type": "ephemeral", "ttl": "1h"}}]},
    {"tools": [{"type": "web_search_20250305", "name": "search"}]},
    {"tools": [{"type": "function", "function": {"name": "Answer", "parameters": {"$ref": "https://remote.invalid/schema"}}}]},
    {"tool_choice": {"type": "web_search"}}, {"response_format": {"type": "image"}},
    {"response_format": {"type": "json_schema", "file_id": "remote"}},
    {"output_config": {"format": {"type": "json_schema", "schema": {"$ref": "https://remote.invalid/schema"}}}},
    {"output_config": {"format": {"type": "json_schema", "file_id": "remote"}}},
    {"thinking": {"type": "enabled", "budget_tokens": 33}},
])
def test_unproved_envelopes_are_unavailable_even_without_dollar_tracking(changes):
    with pytest.raises(LLMCallAdmissionRefused):
        quote_prepared_request(_request(_body(**changes)), _provider(), track_cost=False)


@pytest.mark.parametrize("raw", [b"{", b"[]", b"\xff", b'{"model":"gpt-4o","max_tokens":2,"max_tokens":3}',
    b'{"model":"gpt-4o","messages":[],"max_tokens":3,"temperature":NaN}',
    b'{"model":"gpt-4o","messages":[],"max_tokens":3,"temperature":1e999}'])
def test_ambiguous_or_invalid_json_is_unavailable(raw):
    request = httpx.Request("POST", "https://scripted.invalid/v1/chat/completions", content=raw)
    with pytest.raises(LLMCallAdmissionRefused, match="invalid JSON|envelope"):
        quote_prepared_request(request, _provider())


@pytest.mark.parametrize("path,method", [("/v1/responses", "POST"), ("/bedrock/runtime/model/invoke", "POST"),
    ("/v1/messages?context=remote", "POST"), ("/v1/messages", "GET")])
def test_unproved_routes_are_unavailable(path, method):
    with pytest.raises(LLMCallAdmissionRefused, match="unsupported route"):
        quote_prepared_request(_request(_body(), path, method=method), _provider())


def test_request_stream_is_not_consumed_to_guess_a_bound():
    consumed = []

    def chunks():
        consumed.append(True)
        yield b"text"

    request = httpx.Request("POST", "https://scripted.invalid/v1/chat/completions", content=chunks())
    with pytest.raises(LLMCallAdmissionRefused, match="unbuffered"):
        quote_prepared_request(request, _provider())
    assert consumed == []


def test_reasoning_output_key_is_read_from_wire_but_not_accepted_for_messages():
    body = _body()
    del body["max_tokens"]
    body["max_completion_tokens"] = 64
    request = _request(body)
    assert quote_prepared_request(request, _provider()).reservation_tokens == len(request.content) + 64
    with pytest.raises(LLMCallAdmissionRefused):
        quote_prepared_request(_request(body, "/v1/messages"), _provider())
