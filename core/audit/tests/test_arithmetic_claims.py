"""Overflow verification and disproof must solve the same explicit claim."""

import pytest

from core.audit import sweep
from core.audit.condition_smt import disprove_integer_overflow

pytestmark = pytest.mark.usefixtures("overflow_disproof_unit_worker")


@pytest.fixture
def c_parser():
    pytest.importorskip("tree_sitter")
    pytest.importorskip("tree_sitter_c")


@pytest.mark.parametrize("expression,hypothesis", [
    pytest.param("Value + size", "integer overflow in `Value + size`", id="whole-sum"),
    pytest.param("Value + size", "integer overflow in `Value` + `size`", id="individual-sum"),
    pytest.param("Value + size", "integer overflow in Value + size", id="unquoted-sum"),
    pytest.param("Value + size", "integer overflow in `Value+size`", id="compact-sum"),
    pytest.param("Value + size", "integer overflow in `Value` plus `size`", id="explicit-plus"),
    pytest.param("Value * size", "integer overflow in `Value * size`", id="whole-product"),
    pytest.param("Value * size", "integer overflow in `Value` * `size`", id="individual-product"),
    pytest.param("Value * size", "integer overflow in Value * size", id="unquoted-product"),
    pytest.param("Value * size", "integer overflow in `Value` times `size`", id="explicit-times"),
])
def test_both_overflow_paths_agree_for_supported_expression_formats(c_parser, expression, hypothesis):
    pytest.importorskip("z3")
    source = (
        "unsigned Read(unsigned Value, unsigned size) {"
        f"if(Value <= 65536 && size <= 65536) return {expression};"
        "return 0; }"
    )
    feasible = "*" in expression
    direct = sweep._run_smt_verb_inner(file_path="record.c", function_name="Read", verb="check-overflow",
                                     source=source, hypothesis=hypothesis, integer_abi="ilp32")
    auxiliary = disprove_integer_overflow(hypothesis, source, file_path="record.c", function_name="Read", integer_abi="ilp32")
    assert direct.outcome == ("confirmed" if feasible else "refuted")
    assert auxiliary.disproved is (not feasible), auxiliary.reasoning
    assert not direct.errors and not auxiliary.error


@pytest.mark.parametrize("hypothesis", [
    "integer underflow in `4 - Value`", "integer underflow in `4` - `Value`",
    "integer underflow in 4 - Value", "integer underflow in `4` minus `Value`",
])
def test_subtraction_keeps_literal_order_in_both_paths(c_parser, hypothesis):
    pytest.importorskip("z3")
    source = "unsigned Read(unsigned Value) { if(Value > 4) return 4 - Value; return 0; }"
    direct = sweep._run_smt_verb_inner(file_path="record.c", function_name="Read", verb="check-overflow",
                                     source=source, hypothesis=hypothesis, integer_abi="ilp32")
    auxiliary = disprove_integer_overflow(hypothesis, source, file_path="record.c", function_name="Read", integer_abi="ilp32")
    assert direct.outcome == "confirmed"
    assert auxiliary.disproved is False, auxiliary.reasoning


@pytest.mark.parametrize("hypothesis", [
    "integer overflow in `Value` and `size`",
    "integer overflow in `Value + size` but also `Value * size`",
    "integer overflow in `Value + size * 4`",
    "integer overflow in `obj.Value + size`",
])
def test_missing_ambiguous_or_compound_queries_cannot_refute_a_claim(c_parser, hypothesis):
    pytest.importorskip("z3")
    source = (
        "unsigned Read(unsigned Value, unsigned size) {"
        "if(Value <= 65536 && size <= 65536) { unsigned sum = Value + size; return Value * size; }"
        "return 0; }"
    )
    direct = sweep._run_smt_verb_inner(file_path="record.c", function_name="Read", verb="check-overflow",
                                     source=source, hypothesis=hypothesis, integer_abi="ilp32")
    auxiliary = disprove_integer_overflow(hypothesis, source, file_path="record.c", function_name="Read", integer_abi="ilp32")
    assert direct.outcome == "inconclusive"
    assert auxiliary.disproved is None
