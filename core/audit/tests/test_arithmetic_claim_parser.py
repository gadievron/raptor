"""Strict binary claim parsing keeps all producers on one query."""

from dataclasses import asdict

import pytest

from core.audit import arithmetic_claim as claims, sweep
from core.audit.condition_smt import disprove_integer_overflow
from core.audit.probe_function_scope import source_binding, source_for_function
from core.audit.smt_promotion_gate import receipt_preconditions


@pytest.mark.parametrize("text,left,operator,right", [
    pytest.param("`Value + size`", "Value", "+", "size", id="whole-quote"),
    pytest.param("`Value`+`size`", "Value", "+", "size", id="individual-quotes"),
    pytest.param("Value+size", "Value", "+", "size", id="compact"),
    pytest.param("Value plus size", "Value", "+", "size", id="explicit-plus"),
    pytest.param("`a` times `b`", "a", "*", "b", id="explicit-times"),
    pytest.param("`4` minus `Value`", "4", "-", "Value", id="explicit-minus"),
    pytest.param("`((Value) + (size))`", "Value", "+", "size", id="parentheses"),
    pytest.param("`0x10 * Value`", "0x10", "*", "Value", id="hex-literal"),
    pytest.param("`Value - size`", "Value", "-", "size", id="ordered-subtraction"),
    pytest.param("CWE-190: 32-bit overflow in `Value + size`", "Value", "+", "size", id="metadata"),
    pytest.param("`Value - size` and `Value - size`", "Value", "-", "size", id="same-repeat"),
])
def test_one_explicit_expression_retains_its_operands_and_operator(text, left, operator, right):
    result = claims.parse_arithmetic_claim(text)
    assert result is not None
    assert result.operands == (left, right)
    assert result.operator == operator


@pytest.mark.parametrize("text", [
    "integer overflow in size calc", "multiplication of count and size can wrap",
    "`Value` and `size`", "`Value + size * scale`", "`Value + size + scale`",
    "Value + size * scale", "`Value + size` but also `Value * size`",
    "`Value - size` and `size - Value`", "`obj.Value + size`", "obj . Value + size",
    "obj->Value + size", "`Value[0] + size`", "Value[0] + size", "Value + size.field",
    "`(unsigned)Value + size`", "(unsigned) Value + size", "`get(Value) + size`",
    "get (Value) + size", "Value + get (size)", "`Value + -1`", "Value + 3.14",
    "`Value + 010`", "`Value + 1U`", "Value + 1U", "Value + 0xZZ",
    "`Value + size", "Value + size`", "`Value + size > limit`",
], ids=["no-operator", "keyword-guess", "missing-operator", "mixed-chain", "same-chain", "unquoted-chain",
        "multiple-expressions", "ordered-conflict", "quoted-field", "spaced-field", "pointer-field",
        "quoted-subscript", "subscript", "field-suffix", "quoted-cast", "cast", "quoted-call",
        "spaced-call", "right-call", "unary-minus", "float", "octal", "suffix", "bare-suffix",
        "bad-hex", "unclosed-quote", "stray-quote", "compound-predicate"])
def test_unsupported_or_ambiguous_claims_are_not_reduced_to_a_prefix(text):
    assert claims.parse_arithmetic_claim(text) is None


@pytest.mark.parametrize("text", ["x" * 9000 + " `Value + size`", "`a+b` " * 600,
                                  "`" + "(" * 100 + "Value + size" + ")" * 100 + "`"])
def test_work_limits_decline_the_complete_claim_instead_of_truncating(text):
    assert claims.parse_arithmetic_claim(text) is None


@pytest.mark.parametrize("mechanism", ["integer overflow in `Value + size`", "integer overflow in `Value` + `size`",
                                       "integer overflow in Value + size"])
def test_caller_gate_reads_the_same_explicit_operands(mechanism):
    contracts = receipt_preconditions("check-overflow", mechanism, ["Value", "size"],
                                     "unsigned Read(unsigned Value, unsigned size) { return Value + size; }")
    assert {contract.param for contract in contracts} == {"Value", "size"}


@pytest.fixture
def c_parser():
    pytest.importorskip("tree_sitter")
    pytest.importorskip("tree_sitter_c")


@pytest.mark.parametrize("hypothesis", ["integer overflow in `Value` and `size`",
                                       "integer overflow in `Value + size` and `Value * size`"])
def test_unavailable_claim_stops_before_source_operation_or_solver(c_parser, monkeypatch, hypothesis):
    pytest.importorskip("z3")

    def forbidden(*args, **kwargs):
        pytest.fail("unsupported claim must not choose a source operation or invoke SMT")

    monkeypatch.setattr("core.audit.arithmetic_operation.bind_arithmetic_operation", forbidden)
    source = "unsigned Read(unsigned Value, unsigned size) { if(size < 10) return Value + size; return 0; }"
    result = sweep._run_smt_verb_inner(file_path="record.c", function_name="Read", verb="check-overflow",
                                     source=source, hypothesis=hypothesis, integer_abi="ilp32")
    assert result.outcome == "inconclusive"
    assert not result.errors
    assert disprove_integer_overflow(hypothesis, source, file_path="record.c", function_name="Read",
                                    integer_abi="ilp32").disproved is None


@pytest.mark.parametrize("verdict", ["confirmed", "refuted"])
def test_parent_rejects_workers_using_the_separate_operand_and_operator_heuristics(c_parser, monkeypatch, verdict):
    source = "unsigned Read(unsigned Value, unsigned size) { return Value + size; }"
    hypothesis = "integer overflow in `Value + size`"
    _, selected = source_for_function(source, "record.c", "Read")
    binding = source_binding(selected, "Read", verb="check-overflow", hypothesis=hypothesis, integer_abi="ilp32")
    binding["query_contract"] = "case-sensitive-overflow-v5"
    worker = sweep.SweepResult(tool="smt", file_path="record.c", function_name="Read", rule_id="smt:check-overflow",
                               outcome=verdict, matches=[{}], details={"source_scope": binding})
    monkeypatch.setattr("core.audit.subproc_json.run_json_child", lambda *a, **kw: asdict(worker))
    observed = sweep._smt_verb_in_subprocess(file_path="record.c", function_name="Read", verb="check-overflow",
                                           source=source, hypothesis=hypothesis, integer_abi="ilp32")
    assert observed.outcome == "inconclusive"
    assert not observed.matches
    assert observed.details["source_scope_status"] == "unbound-worker-result"


def test_commutative_references_still_name_one_expression():
    result = claims.parse_arithmetic_claim("`Value + size` and `size + Value`")
    assert result is not None
    assert result.operator == "+" and set(result.operands) == {"Value", "size"}


@pytest.mark.parametrize("hypothesis", [
    "authorization bypass after `Value + size`", "buffer overflow at `Value + size`",
    "integer field corruption involving `Value + size`",
])
def test_auxiliary_disproof_does_not_reinterpret_other_bug_classes(c_parser, monkeypatch, hypothesis):
    pytest.importorskip("z3")

    def forbidden(*args, **kwargs):
        pytest.fail("a non-integer-overflow claim must not start a source proof")

    monkeypatch.setattr("core.audit.arithmetic_operation.bind_arithmetic_operation", forbidden)
    source = "unsigned Read(unsigned Value, unsigned size) { if(Value < 10 && size < 10) return Value + size; return 0; }"
    result = disprove_integer_overflow(hypothesis, source, file_path="record.c", function_name="Read", integer_abi="ilp32")
    assert result.disproved is None
    assert not result.error


@pytest.mark.parametrize("text", ["ΩValue + size", "Value + sizeΩ", "$Value + size", "Value + size$",
                                  "١Value + size", "Value + size\u0301"])
def test_non_ascii_and_extended_identifiers_are_not_reduced_to_ascii_suffixes(text):
    assert claims.parse_arithmetic_claim(text) is None
