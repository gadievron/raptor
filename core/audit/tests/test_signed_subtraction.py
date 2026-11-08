"""Source-bound signed subtraction checks both ends of the promoted range."""

import pytest

from core.audit import sweep
from core.audit.condition_smt import disprove_integer_overflow

pytestmark = pytest.mark.usefixtures("overflow_disproof_unit_worker")


@pytest.mark.parametrize("guard,expected,direction", [
    pytest.param("Value == 2147483647 && Step < 0", "confirmed", "upper", id="positive-overflow"),
    pytest.param("Value < 0 && Step == 2147483647", "confirmed", "lower", id="negative-overflow"),
    pytest.param("Value >= 0 && Value <= 10 && Step >= 0 && Step <= 10", "refuted", "none", id="bounded-safe"),
    pytest.param("Value < 0 && Step == 0", "refuted", "none", id="negative-safe"),
    pytest.param("Value > 10 && Value < 5", "inconclusive", "none", id="unreachable"),
])
@pytest.mark.parametrize("language", ["c", "cpp"])
def test_signed_subtraction_is_bound_and_independently_verified(guard, expected, direction, language):
    pytest.importorskip("tree_sitter_c" if language == "c" else "tree_sitter_cpp")
    pytest.importorskip("z3")
    source = f"int Read(int Value, int Step) {{ if({guard}) return Value - Step; return 0; }}"
    hypothesis = "integer overflow in `Value - Step`"
    result = sweep._run_smt_verb_inner(file_path="record." + language, function_name="Read", verb="check-overflow",
                                     source=source, hypothesis=hypothesis, integer_abi="ilp32")
    assert result.outcome == expected, result.errors
    if expected != "inconclusive":
        assert result.details["proof_scope"] == "function-entry-source-model"
    if expected == "confirmed":
        assert result.details["witness_validated"]
        value = result.details["model"]["Value"] - result.details["model"]["Step"]
        assert value > 2147483647 if direction == "upper" else value < -2147483648
    auxiliary = disprove_integer_overflow(hypothesis, source, file_path="record." + language,
                                         function_name="Read", integer_abi="ilp32")
    assert auxiliary.disproved is {"confirmed": False, "refuted": True, "inconclusive": None}[expected]


@pytest.mark.slow
@pytest.mark.parametrize("guard", ["Value == 2147483647 && Step < 0", "Value < 0 && Step == 2147483647"])
def test_confined_worker_preserves_checked_subtraction_artifact(guard):
    pytest.importorskip("tree_sitter_c")
    pytest.importorskip("z3")
    source = f"int Read(int Value, int Step) {{ if({guard}) return Value - Step; return 0; }}"
    result = sweep.run_smt_verb_direct(file_path="record.c", function_name="Read", verb="check-overflow",
                                     source=source, hypothesis="integer overflow in `Value - Step`", integer_abi="ilp32")
    assert result.outcome == "confirmed", result.errors
    assert result.details["witness_validated"] is True
    assert result.details["mathematical_result"] == result.details["model"]["Value"] - result.details["model"]["Step"]
    assert result.details["proof_scope"] == "function-entry-source-model"
    assert result.details["source_scope"]["query_contract"] == "common-width-integer-operands-v22"
