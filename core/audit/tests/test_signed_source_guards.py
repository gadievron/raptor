"""Negative source guards share typed admission and independent evaluation."""

import pytest

from core.audit import sweep
from core.audit.array_bounds import check_array_bounds
from core.audit.condition_smt import disprove_integer_overflow
from core.audit.integer_literals import integer_literal_value
from core.audit.literal_call import check_literal_calls

pytestmark = pytest.mark.usefixtures("overflow_disproof_unit_worker")


@pytest.fixture(autouse=True)
def prerequisites():
    pytest.importorskip("tree_sitter_c")
    pytest.importorskip("z3")


@pytest.mark.parametrize("guard,violation", [
    pytest.param("Index >= -1 && Index < 4", True, id="off-by-one-lower-bound"),
    pytest.param("Index > -1 && Index < 4", False, id="safe-negative-threshold"),
    pytest.param("Index >= -0x1 && Index < 4", True, id="negative-hex-normalized"),
    pytest.param("Index >= -(1) && Index < 4", True, id="unary-numeric-atom"),
    pytest.param("Index >= (-1) && Index < 4", True, id="grouped-negative-atom"),
    pytest.param("-1 <= Index && Index < 4", True, id="reversed-comparison"),
    pytest.param("Index >= -0 && Index < 4", False, id="negative-zero-is-zero"),
])
@pytest.mark.parametrize("language", ["c", "cpp"])
def test_array_read_negatives_are_encoded_and_checked(guard, violation, language):
    if language == "cpp":
        pytest.importorskip("tree_sitter_cpp")
    source = f"int Read(int Index) {{ int Data[4]={{0}}; if({guard}) return Data[Index]; return 0; }}"
    result = check_array_bounds(source, "Data[Index] out-of-bounds read", language=language, integer_abi="ilp32")
    assert result["array_bounds_status"] == "checked", result
    assert result["violation"] is violation
    if violation:
        assert result["witness_index"] == -1
        assert "-1" in " ".join(result["source_access"]["premises"])


@pytest.mark.parametrize("expression,guard,expected", [
    pytest.param("Value + Step", "Value <= -2147483647 && Step == -2", "confirmed", id="negative-add-overflow"),
    pytest.param("Value - Step", "Value <= -2 && Step == 2147483647", "confirmed", id="negative-subtract-overflow"),
    pytest.param("Value * Step", "Value >= -65535 && Value <= -1 && Step == 65535", "confirmed", id="negative-multiply-overflow"),
    pytest.param("Value + Step", "Value >= -10 && Value <= -1 && Step == -1", "refuted", id="safe-negative-sum"),
    pytest.param("Value + Step", "Value < -1 && Value >= -1 && Step == 1", "inconclusive", id="contradictory-path"),
])
def test_overflow_and_auxiliary_paths_share_signed_guard_semantics(expression, guard, expected):
    source = f"int Read(int Value, int Step) {{ if({guard}) return {expression}; return 0; }}"
    hypothesis = f"integer overflow in `{expression}`"
    result = sweep._run_smt_verb_inner(file_path="record.c", function_name="Read", verb="check-overflow",
                                     source=source, hypothesis=hypothesis, integer_abi="ilp32")
    assert result.outcome == expected, result.errors
    if expected == "confirmed":
        assert result.details["witness_validated"] is True
        value = result.details["mathematical_result"]
        assert value < -2147483648 or value > 2147483647
    auxiliary = disprove_integer_overflow(hypothesis, source, file_path="record.c", function_name="Read", integer_abi="ilp32")
    assert auxiliary.disproved is {"confirmed": False, "refuted": True, "inconclusive": None}[expected]


@pytest.mark.parametrize("literal", ["-2147483648", "-0xffffffff", "-01", "-1U", "-LIMIT", "-(-1)"])
def test_wider_literals_ambiguous_syntax_and_compound_negation_decline(literal):
    source = f"int Read(int Index) {{ int Data[4]={{0}}; if(Index >= {literal}) return Data[Index]; return 0; }}"
    result = check_array_bounds(source, "Data[Index]", language="c", integer_abi="ilp32")
    assert result["array_bounds_status"] == "unavailable", result
    assert result["violation"] is None


def test_unsigned_comparison_conversion_is_not_signed_comparison():
    source = "int Read(unsigned Index) { int Data[4]={0}; if(Index > -1) return Data[Index]; return 0; }"
    result = check_array_bounds(source, "Data[Index]", language="c", integer_abi="ilp32")
    assert result["array_bounds_status"] == "unavailable"
    assert result["violation"] is None


@pytest.mark.parametrize("abi,limit,available", [("i16", "-32767", True), ("i16", "-32768", False),
                                                ("ilp32", "-32768", True), ("ilp64", "-9223372036854775808", False)])
def test_negative_literal_type_admission_uses_target_int_not_host(abi, limit, available):
    source = f"int Read(int Index) {{ int Data[4]={{0}}; if(Index >= {limit}) return Data[Index]; return 0; }}"
    result = check_array_bounds(source, "Data[Index]", language="c", integer_abi=abi)
    assert (result["array_bounds_status"] == "checked") is available
    if available:
        assert result["violation"] is True


@pytest.mark.parametrize("argument,verdict", [("-1", "violation"), ("-(1)", "violation"), ("0", "safe"), ("-2", "guard-excluded")])
def test_literal_caller_checks_negative_guards_and_arguments_together(argument, verdict):
    source = ("int Read(int Index) { int Data[4]={0}; if(Index >= -1 && Index < 4) return Data[Index]; return 0; }\n"
              f"int Drive(void) {{ return Read({argument}); }}\n")
    result = check_literal_calls(source, "Read", "check-array-bounds", "Data[Index]", "ilp32", [2])
    assert result["status"] == "checked", result
    assert result["calls"][0]["verdict"] == verdict


@pytest.mark.parametrize("text,value", [("-1", -1), ("-0x10", -16), ("-0", 0), ("0x10", 16),
                                         ("-01", None), ("-1U", None), ("- 1", None), ("9" * 1000, None)])
def test_bounded_source_literal_syntax_has_no_type_guess(text, value):
    assert integer_literal_value(text) == value


@pytest.mark.slow
@pytest.mark.parametrize("guard,expected", [("Index >= -1 && Index < 4", "confirmed"),
                                           ("Index > -1 && Index < 4", "inconclusive")])
def test_confined_array_worker_preserves_signed_guard_semantics(guard, expected):
    source = f"int Read(int Index) {{ int Data[4]={{0}}; if({guard}) return Data[Index]; return 0; }}"
    result = sweep.run_smt_verb_direct(file_path="record.c", function_name="Read", verb="check-array-bounds",
                                      source=source, hypothesis="out-of-bounds read at Data[Index]", integer_abi="ilp32")
    assert result.outcome == expected, result.errors
    assert result.details["source_scope"]["query_contract"] == "common-width-array-guards-v10"
    assert result.details["violation"] is (expected == "confirmed")
    if expected == "confirmed":
        assert result.details["witness_index"] == -1


@pytest.mark.slow
def test_confined_overflow_worker_checks_negative_counterexample():
    source = "int Read(int Value, int Step) { if(Value <= -2147483647 && Step == -2) return Value + Step; return 0; }"
    result = sweep.run_smt_verb_direct(file_path="record.c", function_name="Read", verb="check-overflow",
                                      source=source, hypothesis="integer overflow in `Value + Step`", integer_abi="ilp32")
    assert result.outcome == "confirmed", result.errors
    assert result.details["witness_validated"] is True
    assert result.details["mathematical_result"] < -2147483648
    assert result.details["source_scope"]["query_contract"] == "common-width-integer-operands-v21"


@pytest.mark.slow
@pytest.mark.parametrize("argument,action", [("-1", "promote"), ("-2", "hold")])
def test_confined_literal_caller_checks_the_same_negative_guard(tmp_path, argument, action):
    from core.audit.smt_promotion_gate import evaluate_caller_gate
    source = ("int Read(int Index) { int Data[4]={0}; if(Index >= -1 && Index < 4) return Data[Index]; return 0; }\n"
              f"int Drive(void) {{ return Read({argument}); }}\n")
    (tmp_path / "record.c").write_text(source)
    decision = evaluate_caller_gate(tmp_path, "record.c", "Read", "check-array-bounds", "Data[Index]",
                                    source=source, def_span=(1, 1), integer_abi="ilp32")
    assert decision.action == action, decision.reason
    assert decision.details["binding"]["query_contract"] == "common-width-literal-frame-v7"
