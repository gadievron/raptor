"""Identified provider usage projects once into the real audit ledger."""
from copy import deepcopy
from types import SimpleNamespace

import pytest

from core.audit.cost_tracker import PhaseCostLedger
from core.audit.orchestrator import OrchestratorConfig, OrchestratorResult, _reconcile_cost_ledgers
from core.llm import telemetry
from core.testing.module_state import isolated_module_state


@pytest.fixture
def sink(tmp_path):
    value = telemetry.TelemetrySink(tmp_path / "captured.jsonl")
    with isolated_module_state(telemetry, {"_sink": value}, lock=telemetry._sink_lock):
        yield value


def _row(**changes):
    return {"event": "attempt_failed", "call_class": "review",
            "attempt_id": "attempt-one", "call_id": "call-one", "work_id": "work-one",
            "cost_usd": 0.25, "billing_state": "reported",
            "beneficiaries": ["function-one", "function-two"], **changes}


def _project(sink, tmp_path, spend, result=None):
    result = result or OrchestratorResult()
    config = OrchestratorConfig(target_path=tmp_path, out_dir=None,
        llm_budget_client=SimpleNamespace(total_cost=spend, provider_spend_usd=spend))
    _reconcile_cost_ledgers(config, result)
    return result


def test_reprojection_of_one_failed_attempt_is_idempotent(sink, tmp_path):
    sink.record(_row())
    result = _project(sink, tmp_path, 0.25)
    result = _project(sink, tmp_path, 0.25, result)
    assert result.cost_tracker.total_spend_usd == pytest.approx(0.25)
    assert result.cost_tracker.total_failed_attempts_cost_usd == pytest.approx(0.25)
    data = result.cost_tracker.to_dict()["attempt_accounting"]
    assert data["status"] == "projected" and len(data["attempts"]) == 1
    assert data["attempts"][0]["beneficiaries"] == ["function-one", "function-two"]


def test_replayed_usage_changes_no_cost_tokens_or_count(sink, tmp_path):
    row = _row(event="call", tokens_in=7, tokens_out=3)
    sink.record(row)
    sink.record(deepcopy(row))
    result = _project(sink, tmp_path, 0.25)
    phase = result.cost_tracker.phases["review"]
    assert phase.calls == 1 and phase.tokens_in == 7 and phase.tokens_out == 3
    assert sink.total_cost_usd() == pytest.approx(0.25)
    assert result.cost_tracker.total_spend_usd == pytest.approx(0.25)


def test_explicit_revision_replaces_charge(sink, tmp_path):
    row = _row(event="call")
    sink.record(row)
    sink.record({**row, "usage_revision": 1, "cost_usd": 0.1})
    result = _project(sink, tmp_path, 0.1)
    assert result.cost_tracker.total_spend_usd == pytest.approx(0.1)
    assert result.cost_tracker.total_calls == 1


@pytest.mark.parametrize("field,value", [("cost_usd", 0.4), ("model", "conflict"), ("call_id", "other")])
def test_conflict_is_not_summed_or_certified(sink, tmp_path, field, value):
    row = _row()
    sink.record(row)
    sink.record({**row, field: value})
    result = _project(sink, tmp_path, 0.25)
    data = result.cost_tracker.to_dict()["attempt_accounting"]
    assert "conflicting_usage_records" in data["gaps"]
    assert sink.total_cost_usd() == pytest.approx(0.25)


def test_unidentified_mixed_usage_is_an_explicit_gap(sink, tmp_path):
    sink.record(_row())
    sink.record({"event": "call", "call_class": "study", "cost_usd": 0.1})
    result = _project(sink, tmp_path, 0.35)
    assert "unidentified_usage_records" in result.cost_tracker.to_dict()["attempt_accounting"]["gaps"]


def test_unknown_zero_cost_does_not_certify_billing(sink, tmp_path):
    sink.record(_row(cost_usd=0, billing_state="unknown", reservation_usd=0.2))
    result = _project(sink, tmp_path, 0)
    data = result.cost_tracker.to_dict()["attempt_accounting"]
    assert "unknown_attempt_usage" in data["gaps"]
    assert data["pending_reservation_usd"] == 0.2


def test_append_failure_remains_a_durability_gap(tmp_path):
    value = telemetry.TelemetrySink(tmp_path)  # directory cannot be an append file
    value.record(_row())
    ledger = PhaseCostLedger()
    ledger.project_attempts(value.attempt_projection(), authoritative_spend=0.25)
    assert "usage_persistence_failed" in ledger.to_dict()["attempt_accounting"]["gaps"]


def test_new_beneficiary_is_a_reference_not_another_charge(sink, tmp_path):
    row = _row(event="call", beneficiaries=["first"])
    sink.record(row)
    sink.record({**row, "beneficiaries": ["second"]})
    result = _project(sink, tmp_path, 0.25)
    data = result.cost_tracker.to_dict()["attempt_accounting"]
    assert data["status"] == "projected"
    assert data["attempts"][0]["beneficiaries"] == ["first", "second"]
    assert result.cost_tracker.total_calls == 1
    assert result.cost_tracker.total_spend_usd == pytest.approx(0.25)


def test_authoritative_ledger_mismatch_never_erases_known_spend(sink, tmp_path):
    sink.record(_row(event="call"))
    result = _project(sink, tmp_path, 0.5)
    assert result.cost_tracker.total_spend_usd >= 0.5
    assert "provider_ledger_not_reconciled" in result.cost_tracker.to_dict()["attempt_accounting"]["gaps"]


def test_historical_accepted_revision_replay_is_inert(sink, tmp_path):
    original = _row(event="call", beneficiaries=["first"])
    sink.record(original)
    sink.record({**original, "usage_revision": 1, "cost_usd": 0.1, "beneficiaries": []})
    sink.record(deepcopy(original))
    result = _project(sink, tmp_path, 0.1)
    data = result.cost_tracker.to_dict()["attempt_accounting"]
    assert data["status"] == "projected"
    assert data["attempts"][0]["beneficiaries"] == ["first"]
    assert result.cost_tracker.total_calls == 1
    assert result.cost_tracker.total_spend_usd == pytest.approx(0.1)


@pytest.mark.parametrize("bad", ["invalid", -1, True])
def test_invalid_revision_cannot_partially_replace_known_totals(sink, bad):
    original = _row(event="call", tokens_in=7)
    sink.record(original)
    sink.record({**original, "usage_revision": 1, "cost_usd": 0.1, "tokens_in": bad})
    assert sink.class_costs()["review"] == (1, 0.25)
    assert sink.attempt_projection()["attempts"][0]["tokens_in"] == 7
    assert sink.attempt_projection()["conflicts"]
