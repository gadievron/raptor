"""Governed structured calls identify every admitted generation."""
from types import SimpleNamespace
from threading import get_ident

import pytest

from core.llm import telemetry
from core.llm.client import LLMClient
from core.llm.config import LLMConfig, ModelConfig
from core.llm.providers import AnthropicProvider, GeminiProvider, OpenAICompatibleProvider, StructuredResponse
from core.testing.module_state import isolated_module_state
from core.testing.module_bindings import patch_module_attribute


def test_no_unadmitted_format_fallback(monkeypatch):
    model = ModelConfig(provider="openai", model_name="governed-stub", api_key="inert")
    provider = OpenAICompatibleProvider(model)
    generations = []
    def malformed(**kwargs):
        generations.append(("schema", kwargs))
        raise ValueError("captured invalid structured response")
    def fallback(*args, **kwargs):
        generations.append(("fallback", kwargs))
        return StructuredResponse(result={"x": "captured"}, raw='{"x":"captured"}')
    provider.instructor_client = SimpleNamespace(chat=SimpleNamespace(
        completions=SimpleNamespace(create_with_completion=malformed)))
    monkeypatch.setattr(provider, "_structured_fallback", fallback)
    client = LLMClient(LLMConfig(primary_model=model, enable_caching=False,
        enable_fallback=False, max_retries=1, max_calls_per_scan=1))
    client.providers["scripted"] = provider
    monkeypatch.setattr(client, "_get_provider", lambda _: provider)
    try:
        client.generate_structured("captured", {"type": "object", "properties": {
            "x": {"type": "string"}}})
    except RuntimeError:
        pass
    assert len(generations) == 1
    assert generations[0][1]["max_retries"] == 1
    assert client._governed_calls == 1


@pytest.mark.parametrize("kind", ["openai", "anthropic"])
def test_governed_schema_failure_preserves_identified_usage(monkeypatch, tmp_path, kind):
    if kind == "anthropic":
        pytest.importorskip("anthropic")
    model = ModelConfig(provider=kind, model_name="governed-stub", api_key="inert")
    provider = (OpenAICompatibleProvider if kind == "openai" else AnthropicProvider)(model)
    calls = []
    error = ValueError("captured malformed completion")
    error.last_completion = SimpleNamespace(usage=SimpleNamespace(
        prompt_tokens=4, completion_tokens=2))
    def malformed(**kwargs):
        calls.append(kwargs)
        raise error
    if kind == "openai":
        provider.instructor_client = SimpleNamespace(chat=SimpleNamespace(
            completions=SimpleNamespace(create_with_completion=malformed)))
    else:
        provider.instructor_client = SimpleNamespace(messages=SimpleNamespace(
            create_with_completion=malformed))
    monkeypatch.setattr(provider, "_calculate_cost_split", lambda *a, **k: 0.25)
    def forbidden(*args, **kwargs):
        pytest.fail("an internal format fallback escaped admission")
    monkeypatch.setattr(provider, "_structured_fallback", forbidden)
    client = LLMClient(LLMConfig(primary_model=model, enable_caching=False,
        enable_fallback=False, max_retries=1, max_calls_per_scan=1))
    client.providers["scripted"] = provider
    monkeypatch.setattr(client, "_get_provider", lambda _: provider)
    sink = telemetry.TelemetrySink(tmp_path / "attempts.jsonl")
    with isolated_module_state(telemetry, {"_sink": sink}, lock=telemetry._sink_lock):
        with pytest.raises(RuntimeError):
            client.generate_structured("captured", {"type": "object"},
                accounting_work_id="owned-review")
    assert len(calls) == 1 and calls[0]["max_retries"] == 1
    assert provider.total_cost == pytest.approx(0.25)
    assert client._governed_tokens == 6
    row, = sink.attempt_projection()["attempts"]
    assert row["work_id"] == "owned-review" and row["cost_usd"] == pytest.approx(0.25)
    assert row["attempt_id"] and row["billing_state"] == "reported"


def test_direct_ungoverned_provider_keeps_format_fallback(monkeypatch):
    provider = OpenAICompatibleProvider(ModelConfig(
        provider="openai", model_name="governed-stub", api_key="inert"))
    calls = []
    def malformed(**kwargs):
        assert "max_retries" not in kwargs
        calls.append("schema")
        raise ValueError("captured malformed completion")
    provider.instructor_client = SimpleNamespace(chat=SimpleNamespace(
        completions=SimpleNamespace(create_with_completion=malformed)))
    def fallback(*args, **kwargs):
        calls.append("fallback")
        return StructuredResponse(result={}, raw="{}")
    monkeypatch.setattr(provider, "_structured_fallback", fallback)
    provider.generate_structured("captured", {"type": "object"})
    assert calls == ["schema", "fallback"]


def test_governed_gemini_parse_failure_keeps_usage_without_fallback(monkeypatch, tmp_path):
    pytest.importorskip("google.genai")
    model = ModelConfig(provider="gemini", model_name="governed-stub", api_key="inert")
    provider = GeminiProvider(model)
    calls = []
    def malformed(**kwargs):
        calls.append(kwargs)
        return SimpleNamespace(text="invalid captured JSON", candidates=[],
            usage_metadata=SimpleNamespace(prompt_token_count=4,
                candidates_token_count=2, thoughts_token_count=0))
    monkeypatch.setitem(provider._clients, get_ident(), SimpleNamespace(models=SimpleNamespace(
        generate_content=malformed)))
    monkeypatch.setattr(provider, "_calculate_cost_split", lambda *a, **k: 0.25)
    def forbidden(*args, **kwargs):
        pytest.fail("native format fallback escaped admission")
    monkeypatch.setattr(provider, "_structured_fallback", forbidden)
    client = LLMClient(LLMConfig(primary_model=model, enable_caching=False,
        enable_fallback=False, max_retries=1, max_calls_per_scan=1))
    client.providers["scripted"] = provider
    monkeypatch.setattr(client, "_get_provider", lambda _: provider)
    sink = telemetry.TelemetrySink(tmp_path / "attempts.jsonl")
    with isolated_module_state(telemetry, {"_sink": sink}, lock=telemetry._sink_lock):
        with pytest.raises(RuntimeError):
            client.generate_structured("captured", {"type": "object"})
    assert len(calls) == 1 and client._governed_calls == 1
    assert provider.total_cost == pytest.approx(0.25) and client._governed_tokens == 6
    row, = sink.attempt_projection()["attempts"]
    assert row["cost_usd"] == pytest.approx(0.25) and row["billing_state"] == "reported"


def test_outer_retry_has_new_admission_and_identity(monkeypatch, tmp_path):
    from pydantic import BaseModel
    import core.llm.client as consumer
    patch_module_attribute(monkeypatch, consumer, "time", "sleep", lambda _: None)
    model = ModelConfig(provider="openai", model_name="governed-stub", api_key="inert")
    provider = OpenAICompatibleProvider(model)
    calls = []
    class Result(BaseModel):
        x: str
    usage = SimpleNamespace(prompt_tokens=4, completion_tokens=2,
        completion_tokens_details=None, prompt_tokens_details=None)
    def scripted(**kwargs):
        assert kwargs["max_retries"] == 1
        calls.append(kwargs)
        if len(calls) == 1:
            error = ConnectionError("captured connection reset")
            error.last_completion = SimpleNamespace(usage=usage)
            raise error
        return Result(x="captured"), SimpleNamespace(usage=usage, model="captured")
    provider.instructor_client = SimpleNamespace(chat=SimpleNamespace(
        completions=SimpleNamespace(create_with_completion=scripted)))
    monkeypatch.setattr(provider, "_calculate_cost_split", lambda *a, **k: 0.25)
    def forbidden(*args, **kwargs):
        pytest.fail("retry must return to client admission")
    monkeypatch.setattr(provider, "_structured_fallback", forbidden)
    client = LLMClient(LLMConfig(primary_model=model, enable_caching=False,
        enable_fallback=False, max_retries=2, max_calls_per_scan=2))
    client.providers["scripted"] = provider
    monkeypatch.setattr(client, "_get_provider", lambda _: provider)
    sink = telemetry.TelemetrySink(tmp_path / "attempts.jsonl")
    with isolated_module_state(telemetry, {"_sink": sink}, lock=telemetry._sink_lock):
        client.generate_structured("captured", {"type": "object", "properties": {
            "x": {"type": "string"}}}, accounting_work_id="owned-review")
    rows = sink.attempt_projection()["attempts"]
    assert len(calls) == client._governed_calls == len(rows) == 2
    assert len({r["attempt_id"] for r in rows}) == 2
    assert len({r["call_id"] for r in rows}) == 1
    assert {r["work_id"] for r in rows} == {"owned-review"}
    assert sum(r["cost_usd"] for r in rows) == pytest.approx(0.5)
    assert client._governed_tokens == 12


def test_no_instructor_allows_one_initial_json_generation(monkeypatch):
    model = ModelConfig(provider="openai", model_name="governed-stub", api_key="inert")
    provider = OpenAICompatibleProvider(model)
    provider.instructor_client = None
    calls = []
    def fallback(*args, **kwargs):
        assert "_governed_single_attempt" not in kwargs
        calls.append(kwargs)
        return StructuredResponse(result={}, raw="{}")
    monkeypatch.setattr(provider, "_structured_fallback", fallback)
    client = LLMClient(LLMConfig(primary_model=model, enable_caching=False,
        enable_fallback=False, max_retries=1, max_calls_per_scan=1))
    client.providers["scripted"] = provider
    monkeypatch.setattr(client, "_get_provider", lambda _: provider)
    client.generate_structured("captured", {"type": "object"})
    assert len(calls) == client._governed_calls == 1
