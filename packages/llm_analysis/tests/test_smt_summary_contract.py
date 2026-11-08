"""SMT assumptions and uncertainty survive the native writer/reader path."""

import pytest

from packages.exploit_feasibility import smt_path
from packages.hypothesis_validation.result import ValidationResult
from packages.llm_analysis.dataflow_validation import _tier4_smt_refine
from packages.llm_analysis.prompts.exploit import _format_smt_witness


@pytest.fixture(autouse=True)
def native_solver():
    pytest.importorskip("z3")


def confirmed():
    return ValidationResult(verdict="confirmed", evidence=[], iterations=1)


def test_native_call_assumptions_reach_the_diagnostic_renderer():
    conditions = ["min(Value, 3) == 2"]
    analysis = {"path_conditions": conditions, "path_profile": "uint8"}
    _, outcome = _tier4_smt_refine(confirmed(), {}, analysis)
    assert outcome == "smt_witness"
    witness = analysis["smt_witness"]
    assert witness["summary_axioms"] == ["summary: min(Value, 3)"]
    text = _format_smt_witness(witness)
    assert "Recorded call-summary assumptions:" in text
    assert witness["summary_axioms"][0] in text
    assert "not verified program inputs" in text
    assert "reachability proof" in text
    assert "HARD CONSTRAINT" not in text


@pytest.mark.parametrize("marker", ["missing", "false", 1, None, True])
def test_writer_preserves_explicit_completeness_only(monkeypatch, marker):
    wire = smt_path.validate_path(["Value == 0"], profile="uint8")
    wire["summary_axioms"] = ["owned conditional assumption"]
    if marker == "missing":
        wire.pop("wp_complete")
    else:
        wire["wp_complete"] = marker
    monkeypatch.setattr(smt_path, "validate_path", lambda *a, **k: wire)
    analysis = {"path_conditions": ["Value == 0"]}
    _, outcome = _tier4_smt_refine(confirmed(), {}, analysis)
    assert outcome == "smt_witness"
    witness = analysis["smt_witness"]
    assert witness["wp_complete"] is (marker is True)
    assert witness["summary_axioms"] == wire["summary_axioms"]
    assert witness["summary_axioms"] is not wire["summary_axioms"]
    text = _format_smt_witness(witness)
    assert "Reported bitvector profile: unspecified" in text
    assert "guaranteed correct" not in text


@pytest.mark.parametrize("marker", ["missing", "false", 1, None])
def test_renderer_does_not_assume_a_legacy_summary_is_complete(marker):
    witness = {"model": {"Value": 0}, "wp_predicate": "true"}
    if marker != "missing":
        witness["wp_complete"] = marker
    text = _format_smt_witness(witness)
    assert "reduction completeness is unestablished" in text
    assert "HARD CONSTRAINT" not in text


def test_unverified_solver_availability_does_not_attach_a_witness(monkeypatch):
    wire = smt_path.validate_path(["Value == 0"], profile="uint8")
    wire["smt_available"] = "false"
    monkeypatch.setattr(smt_path, "validate_path", lambda *a, **k: wire)
    analysis = {"path_conditions": ["Value == 0"]}
    _, outcome = _tier4_smt_refine(confirmed(), {}, analysis)
    assert outcome == "smt_unavailable"
    assert "smt_witness" not in analysis


@pytest.mark.parametrize("old", [None, "old record", [], {"model": {"Old": 7}, "foreign_metadata": "stale"}],
                         ids=["null", "string", "list", "stale-dict"])
def test_recomputation_replaces_the_owned_record_without_mutating_prior_data(old):
    snapshot = dict(old) if isinstance(old, dict) else old
    analysis = {"path_conditions": ["Value == 0"], "path_profile": "uint8", "smt_witness": old}
    _, outcome = _tier4_smt_refine(confirmed(), {}, analysis)
    assert outcome == "smt_witness"
    assert analysis["smt_witness"]["model"] == {"Value": 0}
    assert "foreign_metadata" not in analysis["smt_witness"]
    assert old == snapshot


@pytest.mark.parametrize("case", ["no-conditions", "refuted", "unknown", "unavailable", "error", "internal-error", "empty-model"])
def test_a_new_check_cannot_leave_a_stale_witness_available_to_the_reader(monkeypatch, case):
    conditions = {
        "no-conditions": [], "refuted": ["Value == 0", "Value == 1"],
        "unknown": ["Value / 2 == 0"], "empty-model": ["0 == 0"],
    }.get(case, ["Value == 0"])
    if case == "unavailable":
        monkeypatch.setattr(smt_path, "validate_path", lambda *a, **k: {"smt_available": False})
    elif case == "error":
        def unavailable(*args, **kwargs):
            raise ValueError("owned failed query")
        monkeypatch.setattr(smt_path, "validate_path", unavailable)
    elif case == "internal-error":
        from packages.llm_analysis import dataflow_validation

        def unavailable(*args, **kwargs):
            raise RuntimeError("owned internal failure")
        monkeypatch.setattr(dataflow_validation, "_tier4_smt_refine_inner", unavailable)
    analysis = {"path_conditions": conditions, "path_profile": "uint8",
                "smt_witness": {"model": {"Old": 7}, "wp_predicate": "stale"}}
    _tier4_smt_refine(confirmed(), {}, analysis)
    assert "smt_witness" not in analysis
