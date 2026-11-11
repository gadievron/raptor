"""Consumed attempts without usage retain budget without claiming billing."""
from types import SimpleNamespace

import pytest

from core.llm.client import LLMClient
from core.llm.config import LLMConfig, ModelConfig
import core.llm.dispatcher.client as dispatcher


@pytest.mark.parametrize("structured", [False, True], ids=["text", "structured"])
def test_unknown_consumed_attempt_retains_reservation(monkeypatch, structured):
    client = LLMClient(LLMConfig(
        primary_model=ModelConfig(provider="anthropic", model_name="accounting-stub", api_key="inert"),
        enable_caching=False, enable_fallback=False, enable_cost_tracking=True,
        max_cost_per_scan=1.0, max_retries=1,
    ))
    calls = []
    def fail(*args, **kwargs):
        calls.append(1)
        dispatcher._attempt_state.response_started = True
        raise ConnectionError("captured response body ended")
    provider = SimpleNamespace(generate=fail, generate_structured=fail, total_cost=0.0, total_tokens=0)
    monkeypatch.setattr(client, "_get_provider", lambda model: provider)
    monkeypatch.setattr(dispatcher._attempt_state, "response_started", False, raising=False)
    reservation = client._estimate_call_cost("review")
    with pytest.raises(RuntimeError):
        if structured:
            client.generate_structured("inert", {"type": "object"}, call_class="review")
        else:
            client.generate("inert", call_class="review")
    assert calls == [1]
    # Neither absent usage nor a reservation is exact reported spend.
    assert client.total_cost == 0
    with client._stats_lock:
        assert client._effective_spent_locked() >= reservation
    pending = client.pending_usage_reservations
    assert len(pending) == 1
    assert pending[0]["billing_state"] == "unknown"
    assert pending[0]["reservation_usd"] == reservation
    assert pending[0]["attempt_id"] and pending[0]["call_id"]


def _scripted_client(monkeypatch, *, started, billed=None, retries=1):
    import core.llm.client as client_module
    from core.testing.module_bindings import patch_module_attribute
    patch_module_attribute(monkeypatch, client_module, "time", "sleep", lambda _: None)
    monkeypatch.setattr(dispatcher._attempt_state, "response_started", False, raising=False)
    client = LLMClient(LLMConfig(
        primary_model=ModelConfig(provider="anthropic", model_name="accounting-stub", api_key="inert"),
        enable_caching=False, enable_fallback=False, enable_cost_tracking=True,
        max_cost_per_scan=1.0, max_retries=retries,
    ))
    calls = []
    provider = SimpleNamespace(total_cost=0.0, total_tokens=0)
    def fail(*args, **kwargs):
        calls.append(1)
        dispatcher._attempt_state.response_started = started
        error = ConnectionError("captured transport failure")
        if billed is not None:
            provider.total_cost += billed
            error.billed_cost_usd = billed
        raise error
    provider.generate = provider.generate_structured = fail
    client.providers["scripted"] = provider
    monkeypatch.setattr(client, "_get_provider", lambda model: provider)
    return client, calls


def _invoke(client, structured):
    if structured:
        return client.generate_structured("inert", {"type": "object"}, call_class="review")
    return client.generate("inert", call_class="review")


@pytest.mark.parametrize("structured", [False, True], ids=["text", "structured"])
def test_pre_response_failure_releases_unused_reservation(monkeypatch, structured):
    client, calls = _scripted_client(monkeypatch, started=False)
    with pytest.raises(RuntimeError):
        _invoke(client, structured)
    assert calls == [1]
    assert client.total_cost == 0 and client.pending_usage_reservations == []


@pytest.mark.parametrize("structured", [False, True], ids=["text", "structured"])
def test_known_failed_usage_does_not_also_hold_unknown_reserve(monkeypatch, structured):
    client, calls = _scripted_client(monkeypatch, started=True, billed=0.25)
    with pytest.raises(RuntimeError):
        _invoke(client, structured)
    assert calls == [1]
    assert client.pending_usage_reservations == []
    with client._stats_lock:
        assert client._effective_spent_locked() == 0.25


@pytest.mark.parametrize("structured", [False, True], ids=["text", "structured"])
def test_retry_opt_in_retains_distinct_unknown_attempts(monkeypatch, structured):
    monkeypatch.setenv("RAPTOR_LLM_RETRY_CONSUMED", "1")
    client, calls = _scripted_client(monkeypatch, started=True, retries=2)
    reservation = client._estimate_call_cost("review")
    with pytest.raises(RuntimeError):
        _invoke(client, structured)
    assert len(calls) == 2
    rows = client.pending_usage_reservations
    assert len(rows) == 2
    assert len({r["call_id"] for r in rows}) == 1
    assert len({r["attempt_id"] for r in rows}) == 2
    assert client.total_cost == 0
    with client._stats_lock:
        assert client._effective_spent_locked() == pytest.approx(2 * reservation)
    # Readers cannot erase the governor's retained reservation.
    rows[0]["reservation_usd"] = 0
    assert client.pending_usage_reservations[0]["reservation_usd"] == reservation


@pytest.mark.parametrize("structured", [False, True], ids=["text", "structured"])
def test_unknown_reserve_blocks_later_dispatch(monkeypatch, structured):
    from core.llm.client import LLMBudgetExceededError
    client, calls = _scripted_client(monkeypatch, started=True)
    with pytest.raises(RuntimeError):
        _invoke(client, structured)
    client.config.max_cost_per_scan = client.pending_usage_reservations[0]["reservation_usd"] / 2
    with pytest.raises(LLMBudgetExceededError):
        _invoke(client, structured)
    assert len(calls) == 1


@pytest.mark.parametrize("billed", ["invalid", -1, float("nan"), float("inf"), True])
def test_malformed_billed_marker_keeps_unknown_reservation(monkeypatch, billed):
    client, _ = _scripted_client(monkeypatch, started=True)
    provider = client.providers["scripted"]
    def fail(*args, **kwargs):
        dispatcher._attempt_state.response_started = True
        error = ConnectionError("captured body ended")
        error.billed_cost_usd = billed
        raise error
    provider.generate = fail
    with pytest.raises(RuntimeError):
        client.generate("inert")
    assert client.total_cost == 0
    assert len(client.pending_usage_reservations) == 1


def test_error_after_provider_return_preserves_consumed_gate(monkeypatch):
    from core.llm.client import MidResponseDeathError
    from core.llm.providers import LLMResponse
    client, _ = _scripted_client(monkeypatch, started=True)
    def complete(*args, **kwargs):
        dispatcher._attempt_state.response_started = True
        return LLMResponse(content="inert", model="accounting-stub", provider="anthropic",
                           tokens_used=0, cost=0, finish_reason="complete")
    def fail_after_return(tokens):
        raise ConnectionError("captured post-return transport observation")
    client.providers["scripted"].generate = complete
    monkeypatch.setattr(client, "_record_governed_tokens", fail_after_return)
    with pytest.raises(RuntimeError) as caught:
        client.generate("inert")
    assert isinstance(caught.value.__cause__, MidResponseDeathError)
