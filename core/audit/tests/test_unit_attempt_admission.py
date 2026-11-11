"""Owned unit limits cover real client retry and fallback attempts."""
from types import SimpleNamespace

import pytest

from core.audit.knowledge_calls import KnowledgeCallRefused, observed_client, owned_call_scope
from core.audit.knowledge_runtime import AuditKnowledgeRuntime
from core.audit.orchestrator import OrchestratorConfig, StudyQueue
from core.llm import telemetry
from core.llm.budget_errors import LLMBudgetExceededError, is_budget_exceeded_error
from core.llm.client import LLMClient
from core.llm.config import LLMConfig, ModelConfig
from core.llm.providers import LLMResponse, _attach_billed_usage
from core.testing.module_bindings import patch_module_attribute
from core.testing.module_state import isolated_module_state


@pytest.mark.parametrize("structured", [False, True], ids=["text", "structured"])
def test_unit_limit_stops_paid_retries_without_stopping_the_run(tmp_path, monkeypatch, structured):
    import core.llm.client as consumer
    patch_module_attribute(monkeypatch, consumer, "time", "sleep", lambda _: None)
    primary = ModelConfig(provider="anthropic", model_name="unit-primary-stub", api_key="inert")
    fallback = ModelConfig(provider="anthropic", model_name="unit-fallback-stub", api_key="inert")
    client = LLMClient(LLMConfig(primary_model=primary, fallback_models=[fallback],
        enable_caching=False, enable_fallback=True, max_retries=4,
        max_calls_per_scan=20, max_cost_per_scan=10))
    provider = SimpleNamespace(total_cost=0.0, total_tokens=0, calls=0)
    def fail(*args, **kwargs):
        assert "accounting_attempt_admission" not in kwargs
        provider.calls += 1
        provider.total_cost += 0.1
        provider.total_tokens += 3
        error = ConnectionError("captured paid transport failure")
        _attach_billed_usage(error, cost_usd=0.1, tokens_in=2, tokens_out=1)
        raise error
    provider.generate = provider.generate_structured = fail
    client.providers["scripted"] = provider
    monkeypatch.setattr(client, "_get_provider", lambda _: provider)
    source = "owned source context"
    (tmp_path / "unit.txt").write_text(source)
    runtime = AuditKnowledgeRuntime(tmp_path, StudyQueue(), deadline=float("inf"), max_model_calls=2)
    def review(ctx, config):
        view = observed_client(client, purpose="review")
        if structured:
            view.generate_structured("captured", {"type": "object"}, call_class="review",
                accounting_attempt_admission=lambda: True)
        else:
            view.generate("captured", call_class="review", accounting_attempt_admission=lambda: True)
        raise AssertionError("scripted failed producer returned")
    review._knowledge_observed_client_contract = True
    sink = telemetry.TelemetrySink(tmp_path / "attempts.jsonl")
    try:
        with isolated_module_state(telemetry, {"_sink": sink}, lock=telemetry._sink_lock):
            with pytest.raises(RuntimeError) as raised:
                runtime.wrap_review(review)({"file": "unit.txt", "function": "f", "line_start": 1,
                    "source": source, "language": "text"},
                    OrchestratorConfig(target_path=tmp_path, out_dir=None))
        assert provider.calls == 2
        assert isinstance(raised.value, KnowledgeCallRefused)
        assert not is_budget_exceeded_error(raised.value)
        assert client._governed_calls == 2 and client._governed_tokens == 6
        rows = sink.attempt_projection()["attempts"]
        assert len(rows) == 2 and len({r["attempt_id"] for r in rows}) == 2
        assert len({r["call_id"] for r in rows}) == 1
        assert sum(r["cost_usd"] for r in rows) == pytest.approx(0.2)
        events = runtime.events()
        assert len([e for e in events if e["event"] == "client_call_attempt"]) == 2
        assert any(e["event"] == "client_call_refused" and e["reason"] == "model_call_limit"
                   for e in events)
    finally:
        runtime.close()


def test_task_refusal_text_and_stale_context_are_not_global():
    try:
        raise LLMBudgetExceededError("previous captured global failure")
    except LLMBudgetExceededError as previous:
        try:
            raise KnowledgeCallRefused("budget exceeded")
        except KnowledgeCallRefused as refused:
            assert refused.__context__ is previous
            assert not is_budget_exceeded_error(refused)
    try:
        raise KnowledgeCallRefused("unit_admission")
    except KnowledgeCallRefused:
        try:
            raise LLMBudgetExceededError("current real global cap")
        except LLMBudgetExceededError as current:
            assert is_budget_exceeded_error(current)


def _client(**settings):
    model = ModelConfig(provider="anthropic", model_name="unit-stub", api_key="inert")
    fallback = ModelConfig(provider="anthropic", model_name="unit-fallback-stub", api_key="inert")
    options = dict(enable_caching=False, enable_fallback=True, max_retries=1,
                   max_calls_per_scan=20, max_cost_per_scan=10)
    options.update(settings)
    return LLMClient(LLMConfig(primary_model=model, fallback_models=[fallback], **options))


def test_first_credit_does_not_reset_for_fallback_model(monkeypatch):
    client = _client()
    paid = []
    def fail(*args, **kwargs):
        paid.append(1)
        raise ValueError("captured schema failure")
    monkeypatch.setattr(client, "_get_provider", lambda _: SimpleNamespace(generate=fail))
    admitted = []
    def admit(*args):
        admitted.append(1)
        return len(admitted) <= 1
    with owned_call_scope(admit):
        with pytest.raises(KnowledgeCallRefused, match="unit_admission"):
            observed_client(client).generate("captured")
    assert paid == [1] and client._governed_calls == 1


def test_cache_replay_keeps_one_wrapper_admission_without_extra_attempt(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "private"))
    client = _client(enable_caching=True, cache_dir=tmp_path / "cache")
    paid, admitted = [], []
    def generate(*args, **kwargs):
        paid.append(1)
        return LLMResponse(content="captured", model="unit-stub", provider="anthropic",
            finish_reason="complete", cost=0.1, tokens_used=0)
    monkeypatch.setattr(client, "_get_provider", lambda _: SimpleNamespace(generate=generate))
    with owned_call_scope(lambda *a: admitted.append(1) or True):
        view = observed_client(client)
        view.generate("captured", accounting_attempt_admission=lambda: False)
        cached = view.generate("captured", accounting_attempt_admission=lambda: True)
        assert client.cache_hits == 1 and cached.content == "captured"
    assert len(admitted) == 2 and paid == [1] and client._governed_calls == 1
    assert client.reported_spend_usd == pytest.approx(0.1)
    with pytest.raises(KnowledgeCallRefused, match="scope_closed"):
        view.generate("captured")


def test_closed_helper_scope_refuses_even_the_credited_first_attempt(monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event
    client = _client()
    entered, release = Event(), Event()
    paid = []
    def get_provider(*args):
        entered.set()
        assert release.wait(5)
        return SimpleNamespace(generate=lambda *a, **k: paid.append(1))
    monkeypatch.setattr(client, "_get_provider", get_provider)
    with ThreadPoolExecutor(max_workers=1) as pool:
        try:
            with owned_call_scope(lambda *a: True):
                future = pool.submit(observed_client(client).generate, "captured")
                assert entered.wait(5)
        finally:
            release.set()
        with pytest.raises(KnowledgeCallRefused, match="scope_closed"):
            future.result(timeout=5)
    assert paid == [] and client._governed_calls == 0
