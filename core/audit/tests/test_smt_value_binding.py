"""Source types alone cannot establish symbolic input value domains."""

import pytest

from core.audit import sweep
from core.audit.condition_smt import disprove_integer_overflow


@pytest.fixture(autouse=True)
def prerequisites():
    pytest.importorskip("tree_sitter_c")
    pytest.importorskip("z3")


@pytest.mark.parametrize("declarations", [
    pytest.param("unsigned Value = 0;", id="initialized-local"),
    pytest.param("const unsigned Value = 0;", id="constant-local"),
    pytest.param("static unsigned Value;", id="static-local"),
    pytest.param("unsigned Value;", id="indeterminate-local"),
])
def test_local_values_are_not_unconstrained_entry_inputs(declarations):
    source = f"unsigned Read(unsigned Step) {{ {declarations} if(Value >= 0 && Step <= 1) return Value + Step; return 0; }}"
    hypothesis = "integer overflow in `Value + Step`"
    result = sweep._run_smt_verb_inner(file_path="record.c", function_name="Read", verb="check-overflow",
                                     source=source, hypothesis=hypothesis, integer_abi="ilp32")
    assert result.outcome == "inconclusive"
    assert disprove_integer_overflow(hypothesis, source, file_path="record.c", function_name="Read",
                                    integer_abi="ilp32").disproved is None


def test_guard_local_requires_value_flow_even_when_operands_are_parameters():
    source = "unsigned Read(unsigned Value, unsigned Step) { unsigned Limit = 0; if(Value <= Limit && Step <= 1) return Value + Step; return 0; }"
    result = sweep._run_smt_verb_inner(file_path="record.c", function_name="Read", verb="check-overflow",
                                     source=source, hypothesis="integer overflow in `Value + Step`", integer_abi="ilp32")
    assert result.outcome == "inconclusive"
    assert result.details["arithmetic_type_status"] == "unavailable"


def test_entry_parameters_still_have_symbolic_domains():
    source = "unsigned Read(unsigned Value, unsigned Step) { if(Value >= 1 && Step <= 1) return Value + Step; return 0; }"
    result = sweep._run_smt_verb_inner(file_path="record.c", function_name="Read", verb="check-overflow",
                                     source=source, hypothesis="integer overflow in `Value + Step`", integer_abi="ilp32")
    assert result.outcome == "confirmed", result.errors
