"""Solver SAT is not a source counterexample until independent evaluation passes."""

from dataclasses import replace

import pytest

from core.audit.arithmetic_operation import ArithmeticOperation
from core.audit.integer_witness import validate_integer_witness, validate_overflow_result

OPERATION = ArithmeticOperation("bound", type_status="bound", profile="uint32", kind="unsigned_wrap",
                                types=(("Value", "unsigned"), ("Step", "unsigned")),
                                premises=("Value >= 1", "Step <= 1"))


@pytest.mark.parametrize("model", [
    pytest.param({"Value": 1, "Step": 1}, id="no-overflow"),
    pytest.param({"Value": 0, "Step": 4294967295}, id="violated-guards"),
    pytest.param({"Value": -1, "Step": 1}, id="negative-unsigned"),
    pytest.param({"Value": 4294967296, "Step": 1}, id="outside-storage"),
    pytest.param({"Value": True, "Step": 1}, id="bool-is-not-witness-int"),
    pytest.param({"Value": "4294967295", "Step": 1}, id="string-is-not-witness-int"),
    pytest.param({}, id="missing-required-value"),
    pytest.param(None, id="no-model"),
])
def test_invalid_overflow_assignments_cannot_confirm(model):
    checked = validate_overflow_result({"feasible": True, "model": model}, OPERATION, ["Value", "Step"], "+", "ilp32")
    assert checked["feasible"] is None
    assert checked["model"] == {}
    assert checked["witness_validated"] is False


def test_valid_witness_has_exact_math_and_declared_range():
    checked = validate_overflow_result({"feasible": True, "model": {"Value": 4294967295, "Step": 1}},
                                       OPERATION, ["Value", "Step"], "+", "ilp32")
    assert checked["feasible"] is True
    assert checked["witness_validated"] is True
    assert checked["mathematical_result"] == 4294967296
    assert checked["result_range"] == {"minimum": 0, "maximum": 4294967295}


@pytest.mark.parametrize("field,value", [("unknown", ["unencoded"]), ("unknown_reasons", ["timeout"]),
                                         ("smt_available", False), ("feasible", "sat")])
@pytest.mark.parametrize("feasible", [True, False])
def test_partial_or_malformed_results_never_gain_proof_authority(field, value, feasible):
    result = {"feasible": feasible, "model": {"Value": 4294967295, "Step": 1}, field: value}
    assert validate_overflow_result(result, OPERATION, ["Value", "Step"], "+", "ilp32")["feasible"] is None


def test_original_narrow_domain_is_checked_before_promoted_arithmetic():
    narrow = replace(OPERATION, types=(("Value", "unsigned short"), ("Step", "unsigned short")))
    result = validate_overflow_result({"feasible": True, "model": {"Value": 2147483647, "Step": 1}},
                                     narrow, ["Value", "Step"], "+", "ilp32")
    assert result["feasible"] is None


def test_tautological_parameter_completion_is_checked_and_solver_symbols_are_removed():
    assert validate_integer_witness({"Value": 4, "tracking": True}, (("Value", "int"), ("Unused", "int")),
                                    ("Unused == Unused", "Value >= 4"), "ilp32") == {"Value": 4, "Unused": 0}
    assert validate_integer_witness({}, (("Value", "int"),), ("Value > 0",), "ilp32") is None


@pytest.mark.parametrize("premise", ["Value", "Value + 1 > 0", "Value ? 1", "Missing == 1"])
def test_unknown_independent_predicate_never_defaults_to_true(premise):
    assert validate_integer_witness({"Value": 4}, (("Value", "int"),), (premise,), "ilp32") is None


@pytest.mark.parametrize("feasible", [True, False])
@pytest.mark.parametrize("field,value", [("unknown", ["omitted guard"]),
                                        ("unknown_reasons", [{"kind": "solver_timeout", "detail": "timeout"}])])
def test_audit_and_auxiliary_paths_enforce_validation(monkeypatch, feasible, field, value):
    pytest.importorskip("tree_sitter_c")
    pytest.importorskip("z3")
    from core.audit import sweep
    from core.audit.condition_smt import disprove_integer_overflow
    from packages.exploit_feasibility import smt_verbs
    bad = {"feasible": feasible, "model": {"Value": 1, "Step": 1}, field: value}
    monkeypatch.setattr(smt_verbs, "check_overflow", lambda *a, **kw: bad)
    source = "unsigned Read(unsigned Value, unsigned Step) { if(Value >= 1 && Step <= 1) return Value + Step; return 0; }"
    hypothesis = "integer overflow in `Value + Step`"
    result = sweep._run_smt_verb_inner(file_path="record.c", function_name="Read", verb="check-overflow",
                                     source=source, hypothesis=hypothesis, integer_abi="ilp32")
    assert result.outcome == "inconclusive"
    assert not result.matches
    assert result.details["witness_validated"] is False
    assert result.details["model"] == {}
    assert disprove_integer_overflow(hypothesis, source, file_path="record.c", function_name="Read",
                                    integer_abi="ilp32").disproved is None


@pytest.mark.parametrize('verdict', [False, None, True])
def test_reused_result_cannot_retain_stale_positive_witness_evidence(verdict):
    result = {'feasible': verdict, 'model': {'Value': 1, 'Step': 1},
              'witness_validated': True, 'mathematical_result': 4294967296,
              'result_range': {'minimum': 0, 'maximum': 4294967295}}
    checked = validate_overflow_result(result, OPERATION, ['Value', 'Step'], '+', 'ilp32')
    assert checked['witness_validated'] is False
    assert checked['model'] == {}
    assert 'mathematical_result' not in checked and 'result_range' not in checked
    assert result['witness_validated'] is True  # caller dictionary is not mutated
