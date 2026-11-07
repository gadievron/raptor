"""Source-bound proofs retain case-sensitive parameters resembling NULL."""

import pytest

from core.audit import sweep
from core.audit.array_bounds import check_array_bounds
from core.audit.condition_smt import disprove_integer_overflow

pytestmark = pytest.mark.usefixtures("overflow_disproof_unit_worker")


@pytest.fixture(autouse=True)
def require_parsers_and_solver():
    pytest.importorskip("z3")
    pytest.importorskip("tree_sitter_c")


@pytest.mark.parametrize("name", ["Null", "null", "nUlL"])
@pytest.mark.parametrize("guard,outcome", [("{name}>=0 && {name}<=4 && Step>=0 && Step<=4", "refuted"),
                                          ("{name}==2147483647 && Step>1", "confirmed")])
def test_source_overflow_keeps_null_like_parameters(name, guard, outcome):
    source = f"int Read(int {name},int Step){{if({guard.format(name=name)}) return {name} * Step; return 0;}}"
    hypothesis = f"integer overflow in `{name} * Step`"
    result = sweep._run_smt_verb_inner(file_path="unit.c", function_name="Read", verb="check-overflow",
                                     source=source, hypothesis=hypothesis, integer_abi="lp64")
    assert result.outcome == outcome, result.details
    assert dict(result.details["source_operation"]["types"])[name] == "int"
    auxiliary = disprove_integer_overflow(hypothesis, source, file_path="unit.c", function_name="Read", integer_abi="lp64")
    assert auxiliary.disproved is (outcome == "refuted")
    if outcome == "confirmed":
        assert result.details["model"][name] == 2147483647
        assert result.details["witness_validated"] is True


@pytest.mark.parametrize("name", ["Null", "null", "nUlL"])
@pytest.mark.parametrize("upper,violation", [(3, False), (4, True)])
def test_array_index_keeps_its_declared_domain(name, upper, violation):
    source = f"int Read(int {name}){{int Data[4]={{0}}; if({name}>=0 && {name}<={upper}) return Data[{name}]; return 0;}}"
    result = check_array_bounds(source, f"Data[{name}] out-of-bounds read", language="c", integer_abi="lp64")
    assert result["violation"] is violation, result
    if violation:
        assert result["witness_index"] == 4 and result["model"][name] == 4


@pytest.mark.slow
@pytest.mark.parametrize("name", ["Null", "null"])
def test_confined_worker_checks_the_named_parameter(name):
    source = f"int Read(int {name},int Step){{if({name}==2147483647 && Step>1) return {name} * Step; return 0;}}"
    result = sweep.run_smt_verb_direct(file_path="unit.c", function_name="Read", verb="check-overflow",
                                      source=source, hypothesis=f"integer overflow in `{name} * Step`", integer_abi="lp64")
    assert result.outcome == "confirmed", result.details
    assert result.details["model"][name] == 2147483647 and result.details["witness_validated"] is True


@pytest.mark.parametrize("name", ["Null", "null", "nUlL"])
@pytest.mark.parametrize("value,verdict", [(2, "safe"), (2147483647, "violation")])
def test_literal_caller_frames_keep_case_sensitive_parameters(name, value, verdict):
    from core.audit.literal_call import check_literal_calls

    source = (f"int Read(int {name},int Step){{return {name} * Step;}}\n"
              f"int Drive(void){{return Read({value},2);}}")
    result = check_literal_calls(source, "Read", "check-overflow", f"integer overflow in `{name} * Step`", "lp64", [2])
    assert result["status"] == "checked", result
    assert result["calls"][0]["verdict"] == verdict
