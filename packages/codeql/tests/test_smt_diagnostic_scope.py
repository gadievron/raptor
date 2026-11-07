"""Unbound predicate encodings cannot suppress or redirect source review."""

from dataclasses import asdict
import json
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from core.smt_solver.path_feasibility import PathCondition
from packages.codeql import dataflow_validator as module
from packages.codeql.tests.test_dataflow_validator import _validator, _sarif_two_flows, _FULL_RESPONSE, _smt


@pytest.fixture
def validator(monkeypatch):
    instance = _validator()
    instance._injection_prescreen = MagicMock(return_value=None)
    monkeypatch.setattr("core.llm.scorecard.prefilter_decision", lambda *a, **k: SimpleNamespace(short_circuit=False))
    monkeypatch.setattr("core.llm.scorecard.record_prefilter_outcome", lambda *a, **k: None)
    monkeypatch.setattr(module, "load_methodology", lambda *a, **k: "")
    return instance


@pytest.mark.parametrize("hint", [{}, {"width": 32, "signed": True}, {"width": 32, "signed": False}])
def test_real_scalar_contradiction_remains_diagnostic(validator, tmp_path, hint):
    pytest.importorskip("z3")
    validator._extract_path_conditions.return_value = (
        [PathCondition("Value == 0", 0), PathCondition("Value == 1", 1)], hint,
    )
    path = validator.extract_dataflow_from_sarif(_sarif_two_flows())
    result = validator.validate_dataflow_path(path, tmp_path)
    assert result.is_exploitable is True
    assert validator.llm.generate_structured.call_count == 1
    assert result.smt_path_index == 0 and result.smt_paths_checked == 1
    assert result.smt_diagnostics["modeled_feasible"] is False
    assert result.smt_diagnostics["oracle_scope"] == "llm-extracted-predicates"
    assert result.smt_diagnostics["conflicts"]
    # Result JSON retains the math without granting it source authority.
    assert json.loads(json.dumps(asdict(result)))["smt_diagnostics"] == result.smt_diagnostics
    prompt = validator.llm.generate_structured.call_args.kwargs["prompt"]
    assert "not a source reachability or sanitizer proof" in prompt
    assert "Encoded conflicts" in prompt


@pytest.mark.parametrize("condition,hint", [
    ("ret < 0", {"width": 32, "signed": False}),
    ("Value > 255", {"width": 8, "signed": False}),
])
def test_guessed_types_cannot_supply_a_source_refutation(validator, tmp_path, condition, hint):
    pytest.importorskip("z3")
    validator._extract_path_conditions.return_value = ([PathCondition(condition, 0)], hint)
    path = validator.extract_dataflow_from_sarif(_sarif_two_flows())
    result = validator.validate_dataflow_path(path, tmp_path)
    assert result.smt_diagnostics["modeled_feasible"] is False
    assert result.smt_diagnostics["assumed_width"] == hint["width"]
    assert result.is_exploitable is True
    assert validator.llm.generate_structured.call_count == 1


@pytest.mark.parametrize("error", [ValueError("owned bad input"), RuntimeError("owned solver failure")])
def test_optional_solver_failure_cannot_abort_source_analysis(validator, monkeypatch, tmp_path, error):
    def unavailable(*args, **kwargs):
        raise error
    monkeypatch.setattr(module, "check_path_feasibility_dual", unavailable)
    result = validator.validate_dataflow_path(validator.extract_dataflow_from_sarif(_sarif_two_flows()), tmp_path)
    assert result.is_exploitable is True and result.error is None
    assert result.smt_diagnostics["modeled_feasible"] is None
    assert "unavailable" in result.smt_diagnostics["reasoning"]
    assert validator.llm.generate_structured.call_count == 1


@pytest.mark.parametrize("negated", ["false", 0, 1, None])
def test_malformed_extracted_polarity_degrades_to_diagnostics(validator, tmp_path, negated):
    pytest.importorskip("z3")
    condition = PathCondition("Value == 0", 0)
    # The public constructor rejects malformed flags. Also defend the
    # consumer against a condition object corrupted after construction.
    condition.negated = negated
    validator._extract_path_conditions.return_value = ([condition], {})
    result = validator.validate_dataflow_path(validator.extract_dataflow_from_sarif(_sarif_two_flows()), tmp_path)
    assert result.is_exploitable is True
    assert result.smt_diagnostics["modeled_feasible"] is None
    assert "ValueError" in result.smt_diagnostics["reasoning"]


def test_llm_cannot_overwrite_owned_smt_diagnostics(validator, monkeypatch, tmp_path):
    monkeypatch.setattr(module, "check_path_feasibility_dual", lambda *a, **k: _smt(False, "owned conflict", ["x"]))
    validator.llm.generate_structured.return_value = (
        {**_FULL_RESPONSE, "smt_diagnostics": {"oracle_scope": "source-proof"}, "smt_path_index": 9}, "raw",
    )
    result = validator.validate_dataflow_path(validator.extract_dataflow_from_sarif(_sarif_two_flows()), tmp_path)
    assert result.smt_diagnostics["oracle_scope"] == "llm-extracted-predicates"
    assert result.smt_diagnostics["reasoning"] == "owned conflict"
    assert result.smt_path_index == 0


def test_source_review_failure_retains_error_state_and_diagnostics(validator, monkeypatch, tmp_path):
    monkeypatch.setattr(module, "check_path_feasibility_dual", lambda *a, **k: _smt(False, "owned conflict", ["x"]))
    validator.llm.generate_structured.side_effect = RuntimeError("owned source review failure")
    result = validator.validate_dataflow_path(validator.extract_dataflow_from_sarif(_sarif_two_flows()), tmp_path)
    assert result.error and result.confidence == 0.0
    assert result.smt_diagnostics["modeled_feasible"] is False


def test_diagnostics_do_not_select_an_alternative_path(validator, monkeypatch, tmp_path):
    monkeypatch.setattr(module, "check_path_feasibility_dual", lambda *a, **k: _smt(False, "unbound", ["x"]))
    path = validator.extract_dataflow_from_sarif(_sarif_two_flows())
    result = validator.validate_dataflow_path(path, tmp_path)
    assert validator._extract_path_conditions.call_args.args[0] is path
    assert validator._extract_path_conditions.call_count == 1
    assert result.smt_path_index == 0
    assert any(call.args and call.args[0].endswith("a.c") for call in validator.read_source_context.call_args_list)
    assert not any(call.args and call.args[0].endswith("b.c") for call in validator.read_source_context.call_args_list)
