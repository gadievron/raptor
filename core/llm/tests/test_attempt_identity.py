"""Real governed client attempts retain identities through accounting."""
from types import SimpleNamespace

import pytest

from core.audit.cost_tracker import PhaseCostLedger
from core.llm import telemetry
from core.llm.client import LLMClient
from core.llm.config import LLMConfig, ModelConfig
from core.llm.providers import LLMResponse, _attach_billed_usage
from core.testing.module_bindings import patch_module_attribute
from core.testing.module_state import isolated_module_state
import core.llm.dispatcher.client as dispatcher


@pytest.fixture
def sink(tmp_path):
    value = telemetry.TelemetrySink(tmp_path / "attempts.jsonl")
    with isolated_module_state(telemetry, {"_sink": value}, lock=telemetry._sink_lock):
        yield value


def _client(monkeypatch, steps):
    import core.llm.client as module
    patch_module_attribute(monkeypatch, module, "time", "sleep", lambda _: None)
    monkeypatch.setattr(dispatcher._attempt_state, "response_started", False, raising=False)
    client = LLMClient(LLMConfig(primary_model=ModelConfig(
        provider="anthropic", model_name="identity-stub", api_key="inert"),
        enable_caching=False, enable_fallback=False, max_retries=2, max_cost_per_scan=10))
    provider = SimpleNamespace(total_cost=0.0, total_tokens=0, calls=0)
    script = iter(steps)
    def generate(*args, **kwargs):
        provider.calls += 1
        step = next(script)
        if step == "unknown":
            dispatcher._attempt_state.response_started = True
            raise ConnectionError("captured body ended")
        if step == "failed":
            provider.total_cost += 0.2
            error = ConnectionError("captured retry")
            _attach_billed_usage(error, cost_usd=0.2, tokens_in=4, tokens_out=2)
            raise error
        provider.total_cost += step
        return LLMResponse(content="captured", model="identity-stub", provider="anthropic",
                           cost=step, tokens_used=3, input_tokens=2, output_tokens=1,
                           finish_reason="complete")
    provider.generate = generate
    client.providers["scripted"] = provider
    monkeypatch.setattr(client, "_get_provider", lambda _: provider)
    return client, provider


def test_shared_beneficiaries_reference_one_real_dispatch(monkeypatch, sink):
    client, provider = _client(monkeypatch, [0.4])
    client.generate("inert", call_class="study", accounting_work_id="study-work",
                    accounting_beneficiaries=["first-unit", "second-unit"])
    assert provider.calls == 1
    ledger = PhaseCostLedger()
    ledger.project_attempts(sink.attempt_projection(), authoritative_spend=client.total_cost)
    data = ledger.to_dict()["attempt_accounting"]
    assert data["status"] == "projected"
    assert ledger.total_spend_usd == pytest.approx(0.4)
    assert data["attempts"][0]["beneficiaries"] == ["first-unit", "second-unit"]


def test_failed_retry_and_success_are_distinct_charged_attempts(monkeypatch, sink):
    client, provider = _client(monkeypatch, ["failed", 0.3])
    client.generate("inert", call_class="review", accounting_work_id="review-work")
    rows = sink.attempt_projection()["attempts"]
    assert provider.calls == 2 and len(rows) == 2
    assert len({r["call_id"] for r in rows}) == 1
    assert len({r["attempt_id"] for r in rows}) == 2
    ledger = PhaseCostLedger()
    ledger.project_attempts(sink.attempt_projection(), authoritative_spend=client.provider_spend_usd)
    assert ledger.total_spend_usd == pytest.approx(0.5)
    assert ledger.total_failed_attempts_cost_usd == pytest.approx(0.2)


def test_late_usage_reconciles_one_unknown_attempt_once(monkeypatch, sink):
    client, provider = _client(monkeypatch, ["unknown"])
    with pytest.raises(RuntimeError):
        client.generate("inert", call_class="review", accounting_work_id="review-work")
    attempt = client.pending_usage_reservations[0]["attempt_id"]
    assert client.reconcile_pending_usage(attempt, cost_usd=0.2, tokens_in=4, tokens_out=2)
    assert not client.reconcile_pending_usage(attempt, cost_usd=0.2, tokens_in=4, tokens_out=2)
    assert provider.calls == 1 and client.pending_usage_reservations == []
    assert client._governed_tokens == 6
    ledger = PhaseCostLedger()
    ledger.project_attempts(sink.attempt_projection(), authoritative_spend=client.total_cost)
    assert ledger.total_spend_usd == pytest.approx(0.2)
    assert ledger.to_dict()["attempt_accounting"]["status"] == "projected"
    with pytest.raises(ValueError, match="conflicting"):
        client.reconcile_pending_usage(attempt, cost_usd=0.3)
    assert client.total_cost == pytest.approx(0.2)


def test_known_failed_tokens_consume_the_global_token_allowance(monkeypatch, sink):
    from core.llm.budget_errors import LLMGovernorExceededError
    client, provider = _client(monkeypatch, ["failed", 0.3])
    client.config.max_tokens_per_scan = 5
    with pytest.raises(LLMGovernorExceededError):
        client.generate("inert", call_class="review")
    assert provider.calls == 1
    assert client._governed_tokens == 6


def test_optional_observer_failure_does_not_undo_late_accounting(monkeypatch, sink):
    client, provider = _client(monkeypatch, ["unknown"])
    with pytest.raises(RuntimeError):
        client.generate("inert", call_class="review")
    attempt = client.pending_usage_reservations[0]["attempt_id"]
    def fail_projection():
        raise OSError("captured observer failure")
    with monkeypatch.context() as observer:
        observer.setattr(sink, "attempt_projection", fail_projection)
        assert client.reconcile_pending_usage(attempt, cost_usd=0.2)
        assert not client.reconcile_pending_usage(attempt, cost_usd=0.2)
    assert provider.calls == 1 and client.pending_usage_reservations == []
    assert client.total_cost == pytest.approx(0.2)
    assert sink.total_cost_usd() == pytest.approx(0.2)
    assert not sink.attempt_projection()["conflicts"]


def test_concurrent_structured_attempts_use_their_own_usage(monkeypatch, sink):
    import threading
    from concurrent.futures import ThreadPoolExecutor
    from core.llm.providers import StructuredResponse
    client, provider = _client(monkeypatch, [])
    barrier = threading.Barrier(2)
    lock = threading.Lock()
    def structured(prompt, schema, system_prompt=None, **kwargs):
        assert "accounting_work_id" not in kwargs and "accounting_beneficiaries" not in kwargs
        cost = {"first": 0.2, "second": 0.3}[prompt]
        with lock:
            provider.calls += 1
            provider.total_cost += cost
            provider.total_tokens += 3
        barrier.wait(timeout=5)
        return StructuredResponse(result={"answer": "captured"}, raw='{"answer":"captured"}',
            cost=cost, tokens_used=3, input_tokens=2, output_tokens=1,
            model="identity-stub", provider="anthropic")
    provider.generate_structured = structured
    schema = {"type": "object", "properties": {"answer": {"type": "string"}},
              "required": ["answer"], "additionalProperties": False}
    def invoke(prompt):
        return client.generate_structured(prompt, schema, call_class="review",
            accounting_work_id="review-work", accounting_beneficiaries=[prompt])
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(invoke, name) for name in ("first", "second")]
        for future in futures:
            assert future.result(timeout=10).result == {"answer": "captured"}
    assert provider.calls == 2 and client.total_cost == pytest.approx(0.5)
    assert client._governed_tokens == 6
    ledger = PhaseCostLedger()
    ledger.project_attempts(sink.attempt_projection(), authoritative_spend=client.total_cost)
    assert ledger.total_spend_usd == pytest.approx(0.5)
    assert ledger.total_calls == 2


def test_legacy_counter_usage_is_not_reported_as_exact_per_attempt(monkeypatch, sink):
    client, provider = _client(monkeypatch, [])
    def legacy(prompt, schema, system_prompt=None, **kwargs):
        provider.calls += 1
        provider.total_cost += 0.4
        provider.total_tokens += 3
        return {"answer": "captured"}, '{"answer":"captured"}'
    provider.generate_structured = legacy
    schema = {"type": "object", "properties": {"answer": {"type": "string"}},
              "required": ["answer"], "additionalProperties": False}
    client.generate_structured("inert", schema, call_class="review")
    ledger = PhaseCostLedger()
    ledger.set_total_spend(client.total_cost)
    ledger.project_attempts(sink.attempt_projection(), authoritative_spend=client.total_cost)
    assert provider.calls == 1 and client.total_cost == pytest.approx(0.4)
    data = ledger.to_dict()["attempt_accounting"]
    assert data["status"] == "incomplete"
    assert "estimated_attempt_usage" in data["gaps"]
    assert ledger.total_spend_usd == pytest.approx(0.4)
