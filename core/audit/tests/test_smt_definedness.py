"""A query cannot assume that unmodeled evaluations reach its source operation."""

import pytest

from core.audit import sweep
from core.audit.arithmetic_operation import bind_arithmetic_operation
from core.audit.condition_smt import disprove_integer_overflow

pytestmark = pytest.mark.usefixtures("overflow_disproof_unit_worker")


@pytest.mark.parametrize("prefix", [
    pytest.param("int Other = 1 / Flag;", id="division-before-guards"),
    pytest.param("int Other = Flag + 1;", id="signed-add-before-guards"),
    pytest.param("if(Flag << 32) {}", id="invalid-shift-before-guards"),
    pytest.param("int Other = *Pointer;", id="unverified-dereference"),
    pytest.param("int Other = Pointer[Flag];", id="unverified-subscript"),
    pytest.param("int Buffer[Flag];", id="variable-extent-declaration"),
    pytest.param("int Other; if(Other) {}", id="indeterminate-prior-read"),
])
def test_unmodeled_prior_operations_cannot_mint_source_proof(prefix):
    pytest.importorskip("tree_sitter_c")
    pytest.importorskip("z3")
    source = f"unsigned Read(unsigned Value, unsigned Step, int Flag, int *Pointer) {{ {prefix} if(Value >= 1 && Step <= 1) return Value + Step; return 0; }}"
    hypothesis = "integer overflow in `Value + Step`"
    result = sweep._run_smt_verb_inner(file_path="record.c", function_name="Read", verb="check-overflow",
                                     source=source, hypothesis=hypothesis, integer_abi="ilp32")
    assert result.outcome == "inconclusive", result.errors
    assert result.details["arithmetic_guard_status"] == "unavailable"
    assert disprove_integer_overflow(hypothesis, source, file_path="record.c", function_name="Read",
                                    integer_abi="ilp32").disproved is None


def test_nested_arithmetic_needs_a_definedness_and_evaluation_order_model():
    pytest.importorskip("tree_sitter_c")
    result = bind_arithmetic_operation("unsigned Read(unsigned a, unsigned b) { if(a > 1) return (a + b) / 0; return 0; }",
                                       ["a", "b"], "+", language="c", integer_abi="ilp32")
    assert result.guard_status == "unavailable"


def test_immediate_cpp_function_does_not_establish_runtime_execution():
    pytest.importorskip("tree_sitter_cpp")
    result = bind_arithmetic_operation("consteval int Read(int a, int b) { if(a > 1) return a + b; return 0; }",
                                       ["a", "b"], "+", language="cpp", integer_abi="ilp32")
    assert result.status == "unavailable"


def test_implicit_constructor_is_not_a_pure_declaration():
    pytest.importorskip("tree_sitter_cpp")
    source = "unsigned Read(unsigned a, unsigned b) { Guard token; if(a > 1) return a + b; return 0; }"
    result = bind_arithmetic_operation(source, ["a", "b"], "+", language="cpp", integer_abi="ilp32")
    assert result.guard_status == "unavailable"


@pytest.mark.parametrize("source", [
    pytest.param("unsigned Read(unsigned a, unsigned b) {" + " " * 65536 + "return a+b;}", id="source-budget"),
    pytest.param("unsigned Read(unsigned a, unsigned b) {" + ";" * 2100 + "return a+b;}", id="node-budget"),
])
def test_source_budget_exhaustion_never_truncates_to_a_proof(source):
    pytest.importorskip("tree_sitter_c")
    result = bind_arithmetic_operation(source, ["a", "b"], "+", language="c", integer_abi="ilp32")
    assert result.status == "unavailable"
