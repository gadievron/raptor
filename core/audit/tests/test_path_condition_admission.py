"""Audit path adapters must not solve a silently shortened conjunction."""

from dataclasses import asdict

import pytest

from core.audit import path_feasibility as audit
from core.audit import sweep


@pytest.fixture
def native_sweep(monkeypatch):
    pytest.importorskip("z3")
    from core.smt_solver import BVProfile
    from core.smt_solver import path_feasibility as core

    def solve(*, file_path, function_name, verb, smt_args):
        assert verb == "validate-path"
        conditions = [
            core.PathCondition(condition, index) if isinstance(condition, str)
            else core.PathCondition(condition["text"], index, condition["negated"])
            for index, condition in enumerate(smt_args["conditions"])
        ]
        result = core.check_path_feasibility(conditions, profile=BVProfile(8, False), reduce_constraints=False)
        return sweep.SweepResult(tool="smt", file_path=file_path, function_name=function_name,
                                 outcome="inconclusive", details={**asdict(result), "oracle_scope": "supplied-predicates"})

    monkeypatch.setattr(sweep, "run_smt_sweep", solve)


def test_empty_condition_cannot_certify_a_satisfiable_subset(native_sweep):
    result = audit.check_path_feasibility([audit.PathCondition("Value == 0"), audit.PathCondition("")])
    assert result.feasible is None


def test_malformed_trace_cell_cannot_certify_a_satisfiable_subset(native_sweep):
    result = audit.check_flow_trace_feasibility({"path_conditions": ["Value == 0", None]})
    assert result.feasible is None


@pytest.mark.parametrize("texts,expected", [
    (["Value == 0", "Value < 2"], True),
    (["Value == 0", "Value == 1"], False),
    (["Value == 0", "Value / 2 == 1"], None),
    (["Value == 0", "Value == 1", "Value / 2 == 1"], False),
])
def test_native_complete_partial_and_independent_contradiction_controls(native_sweep, texts, expected):
    result = audit.check_path_feasibility([audit.PathCondition(text) for text in texts])
    assert result.feasible is expected


@pytest.mark.parametrize("text", ["", " \t\n", None, 0, False, [], {}])
def test_invalid_direct_text_declines_before_dispatch(monkeypatch, text):
    monkeypatch.setattr(sweep, "run_smt_sweep", lambda **kw: pytest.fail("invalid condition reached solver"))
    result = audit.check_path_feasibility([audit.PathCondition("Value == 0"), audit.PathCondition(text)])
    assert result.feasible is None and result.error


@pytest.mark.parametrize("raw", [
    None, False, 1, {}, "", ["Value == 0", None], ["Value == 0", 1],
    ["Value == 0", {}], ["Value == 0", {"text": None}],
    ["Value == 0", {"text": ""}], ["Value == 0", {"text": False}],
])
@pytest.mark.parametrize("location", ["top", "steps", "hops"])
def test_malformed_condition_metadata_declines_the_whole_trace(monkeypatch, raw, location):
    monkeypatch.setattr(sweep, "run_smt_sweep", lambda **kw: pytest.fail("malformed trace reached solver"))
    trace = ({"path_conditions": raw, "steps": [{"path_conditions": ["Value == 0"]}]}
             if location == "top" else {location: [{"path_conditions": raw}], "path_conditions": ["Value == 0"]})
    with pytest.raises(ValueError):
        audit.extract_conditions_from_flow_trace(trace)
    result = audit.check_flow_trace_feasibility(trace)
    assert result.feasible is None and result.error


@pytest.mark.parametrize("outcome", ["confirmed", "refuted"])
@pytest.mark.parametrize("scoped", [True, False])
def test_failed_sweep_cannot_supply_a_verdict(monkeypatch, outcome, scoped):
    details = {"oracle_scope": "supplied-predicates", "feasible": outcome == "confirmed"} if scoped else {}
    monkeypatch.setattr(sweep, "run_smt_sweep", lambda **kw: sweep.SweepResult(
        tool="smt", file_path="record.c", function_name="Read", outcome=outcome,
        details=details, errors=["owned incomplete query"],
    ))
    result = audit.check_path_feasibility([audit.PathCondition("Value == 0")])
    assert result.feasible is None and "owned incomplete query" in result.error


@pytest.mark.parametrize("field,value", [
    ("smt_available", False), ("unknown", ["unencoded"]),
    ("unknown_reasons", [{"kind": "unrecognized_form"}]),
])
@pytest.mark.parametrize("scoped", [True, False])
def test_incomplete_positive_details_cannot_certify_the_conjunction(monkeypatch, field, value, scoped):
    details = {"feasible": True, field: value}
    if scoped:
        details["oracle_scope"] = "supplied-predicates"
    monkeypatch.setattr(sweep, "run_smt_sweep", lambda **kw: sweep.SweepResult(
        tool="smt", file_path="record.c", function_name="Read", outcome="confirmed", details=details,
    ))
    result = audit.check_path_feasibility([audit.PathCondition("Value == 0")])
    assert result.feasible is None


@pytest.mark.parametrize("trace", [None, [], False, ""])
def test_invalid_trace_root_is_an_inconclusive_observation(monkeypatch, trace):
    monkeypatch.setattr(sweep, "run_smt_sweep", lambda **kw: pytest.fail("invalid trace reached solver"))
    result = audit.check_flow_trace_feasibility(trace)
    assert result.feasible is None and "flow trace" in result.error
