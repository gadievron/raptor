"""Supported SDK providers carry owned admission without exposing its token."""
import json
from types import SimpleNamespace

import httpx
import pytest

from core.llm import http_pool, providers
from core.llm.budget_errors import LLMCallAdmissionRefused
from core.llm.config import ModelConfig
from core.llm.prepared_admission import WIRE_HEADER, prepared_attempt
from core.llm.providers import AnthropicProvider, OpenAICompatibleProvider, _sdk_usage_reported


SCHEMA = {"type": "object", "properties": {"answer": {"type": "string"}},
          "required": ["answer"]}


@pytest.fixture
def sdk_provider(monkeypatch):
    monkeypatch.delenv("RAPTOR_LLM_SOCKET", raising=False)
    monkeypatch.setattr(providers, "_stream_transport_enabled", lambda: False)
    calls = []
    opened = []
    script = {"kind": "openai", "usage": "known", "malformed": False}

    def respond(request):
        assert WIRE_HEADER not in request.headers
        body = json.loads(request.content)
        assert "_governed_wire_token" not in body and "extra_headers" not in body
        calls.append(body)
        tool = next(iter(body.get("tools", [])), None)
        count = 0 if script["usage"] == "zero" else 3
        if script["kind"] == "openai":
            message = {"role": "assistant", "content":
                       "not-json" if script["malformed"] else '{"answer":"captured"}'}
            if tool:
                message = {"role": "assistant", "content": None, "tool_calls": [{
                    "id": "owned-tool", "type": "function", "function": {
                        "name": tool["function"]["name"], "arguments": '{"answer":"captured"}'}}]}
            response = {"id": "captured-completion", "object": "chat.completion", "created": 0,
                "model": body["model"], "choices": [{"index": 0, "message": message,
                    "finish_reason": "tool_calls" if tool else "stop"}],
                "usage": None if script["usage"] == "missing" else {
                    "prompt_tokens": count, "completion_tokens": count, "total_tokens": 2 * count}}
        else:
            content = [{"type": "text", "text":
                        "not-json" if script["malformed"] else '{"answer":"captured"}'}]
            if tool:
                content = [{"type": "tool_use", "id": "owned-tool", "name": tool["name"],
                            "input": {"answer": "captured"}}]
            response = {"id": "captured-message", "type": "message", "role": "assistant",
                "model": body["model"], "content": content,
                "stop_reason": "tool_use" if tool else "end_turn", "stop_sequence": None,
                "usage": None if script["usage"] == "missing" else {
                    "input_tokens": count, "output_tokens": count}}
        return httpx.Response(200, request=request, json=response)

    transport = httpx.MockTransport(respond)
    monkeypatch.setattr(http_pool, "_keepalive_transport_and_mounts",
                        lambda **kwargs: (transport, {}))

    def build(kind, *, route="text", usage="known", malformed=False):
        if kind == "anthropic":
            pytest.importorskip("anthropic")
        script.update(kind=kind, usage=usage, malformed=malformed)
        config = ModelConfig(provider=kind,
            model_name="gpt-4o" if kind == "openai" else "claude-sonnet-4-5",
            api_key="inert", api_base="https://scripted.invalid/v1", max_tokens=128)
        value = (OpenAICompatibleProvider if kind == "openai" else AnthropicProvider)(config)
        opened.append(value)
        if route == "fallback":
            value.instructor_client = None
        return value

    try:
        yield build, calls
    finally:
        for value in opened:
            value.client.close()
        transport.close()


def _generate(provider, route, token=None):
    kwargs = {} if token is None else {"_governed_wire_token": token}
    if route == "text":
        return provider.generate("captured", **kwargs)
    return provider.generate_structured("captured", SCHEMA,
        _governed_single_attempt=True, **kwargs)


@pytest.mark.parametrize("kind", ["openai", "anthropic"])
@pytest.mark.parametrize("route", ["text", "instructor", "fallback"])
def test_owned_request_reaches_one_sdk_leg_without_the_marker(sdk_provider, kind, route):
    build, calls = sdk_provider
    provider = build(kind, route=route)
    admitted = []

    def admit(request):
        assert WIRE_HEADER not in request.headers
        admitted.append(json.loads(request.content))

    with prepared_attempt(admit) as owned:
        response = _generate(provider, route, owned.token)
        assert owned.admitted
    assert len(admitted) == len(calls) == 1
    assert admitted == calls
    assert response.usage_reported is True
    if route != "text":
        assert response.result == {"answer": "captured"}
    assert provider._prepared_wire_admission_protocol == 1


@pytest.mark.parametrize("kind", ["openai", "anthropic"])
@pytest.mark.parametrize("usage", ["missing", "zero"])
@pytest.mark.parametrize("route", ["text", "fallback"])
def test_missing_usage_does_not_impersonate_reported_zero(sdk_provider, kind, usage, route):
    build, calls = sdk_provider
    provider = build(kind, route=route, usage=usage)
    with prepared_attempt(lambda request: None) as owned:
        response = _generate(provider, route, owned.token)
    assert len(calls) == 1
    assert response.cost == response.tokens_used == 0
    assert response.usage_reported is (usage == "zero")


@pytest.mark.parametrize("kind", ["openai", "anthropic"])
def test_no_owned_token_keeps_the_ordinary_sdk_path(sdk_provider, kind):
    build, calls = sdk_provider
    response = _generate(build(kind), "text")
    assert len(calls) == 1 and response.usage_reported is True


@pytest.mark.parametrize("kind", ["openai", "anthropic"])
def test_missing_usage_parse_error_never_claims_zero(sdk_provider, kind):
    build, calls = sdk_provider
    provider = build(kind, route="fallback", usage="missing", malformed=True)
    with prepared_attempt(lambda request: None) as owned:
        with pytest.raises(json.JSONDecodeError) as caught:
            _generate(provider, "fallback", owned.token)
    assert len(calls) == 1
    assert caught.value._llm_usage_reported is False
    assert not hasattr(caught.value, "billed_cost_usd")


@pytest.mark.parametrize("kind", ["openai", "anthropic"])
def test_provider_denial_preserves_task_cause_without_transport(sdk_provider, kind):
    build, calls = sdk_provider
    provider = build(kind)

    def refuse(request):
        raise LLMCallAdmissionRefused("captured task limit")

    with prepared_attempt(refuse) as owned:
        with pytest.raises(Exception) as caught:
            _generate(provider, "text", owned.token)
        assert not owned.admitted
    chain = []
    error = caught.value
    while error is not None and len(chain) < 8:
        chain.append(error)
        error = error.__cause__
    assert any(isinstance(error, LLMCallAdmissionRefused) for error in chain)
    assert calls == []


@pytest.mark.parametrize("value", [True, -1, None])
def test_malformed_usage_is_not_reported(value):
    usage = SimpleNamespace(prompt_tokens=value, completion_tokens=0)
    assert not _sdk_usage_reported(usage, "prompt_tokens", "completion_tokens")
