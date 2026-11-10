"""Constant comparison proofs preserve source types, domains and entry facts."""

import pytest

from core.audit.integer_comparison import check_integer_comparison


@pytest.mark.parametrize("language", ["c", "cpp"])
@pytest.mark.parametrize("spelling,expression,truth", [
    ("unsigned", "Value < 0", False),
    ("unsigned", "Value >= 0", True),
    ("unsigned char", "Value < 0", False),
    ("signed char", "Value < 128", True),
    ("signed char", "Value >= -128", True),
    ("unsigned short", "Value <= 65535", True),
    ("int", "Value == Value", True),
    ("int", "Value != Value", False),
])
def test_source_types_and_promotions_bound_constant_truth(language, spelling, expression, truth):
    source = f"int Read({spelling} Value) {{ if ({expression}) return 1; return 0; }}"
    claim = f"comparison is always {'true' if truth else 'false'}: `{expression}`"
    result = check_integer_comparison(source, claim, language=language, integer_abi="lp64")
    assert result["matches_claim"] is True, result
    assert result["constant_truth"] is truth
    assert result["entry_witness_validated"] is True
    assert result["source_operation"]["comparison_width"] == 32


@pytest.mark.parametrize("abi,width,signed", [("lp64", 32, True), ("i16", 16, False)])
def test_unsigned_short_promotion_depends_on_target_int(abi, width, signed):
    result = check_integer_comparison("int Read(unsigned short Value){if(Value < 0)return 1;return 0;}",
                                      "comparison is always false: `Value < 0`", language="c", integer_abi=abi)
    assert result["matches_claim"] is True, result
    assert result["source_operation"]["comparison_width"] == width
    assert result["source_operation"]["comparison_signed"] is signed


@pytest.mark.parametrize("truth", [True, False])
def test_signed_input_retains_both_truth_values(truth):
    result = check_integer_comparison("int Read(int Value){if(Value < 0)return 1;return 0;}",
                                      f"comparison is always {'true' if truth else 'false'}: `Value < 0`",
                                      language="c", integer_abi="lp64")
    assert result["matches_claim"] is False
    assert not result["entry_witness_validated"]


def test_selected_condition_does_not_become_its_own_premise():
    result = check_integer_comparison("int Read(int Value){if(Value < 10)return 1;return 0;}",
                                      "comparison is always true: `Value < 10`", language="c", integer_abi="lp64")
    assert result["matches_claim"] is False
    assert result["source_operation"]["premises"] == []


def test_reaching_guard_can_make_a_later_test_constant():
    result = check_integer_comparison("int Read(int Value){if(Value < 10){if(Value <= 20)return 1;}return 0;}",
                                      "comparison is always true: `Value <= 20`", language="c", integer_abi="lp64")
    assert result["matches_claim"] is True, result
    assert result["source_operation"]["premises"] == ["Value < 10"]
    assert result["entry_witness"]["Value"] < 10


@pytest.mark.parametrize("source", [
    "int Read(int Value){if(Value<0 && Value>=0){if(Value<10)return 1;}return 0;}",
    "int Read(int Value){Value=0;if(Value<0)return 1;return 0;}",
    "int Read(int Value){Other();if(Value<0)return 1;return 0;}",
    "int Read(int Value){int *p=&Value;if(Value<0)return 1;return 0;}",
    "int Read(int Value){if(Value<0)return 1;if(Value<0)return 2;return 0;}",
    "int Read(int Value,int Flag){if(Value<0 && Flag)return 1;return 0;}",
    "int Read(volatile int Value){if(Value<0)return 1;return 0;}",
    "int Read(int Value){return sizeof(Value<0);}",
    "int Read(int Value){return (Value+1)<0;}",
    "int Unrelated;",
])
def test_unsupported_unreachable_or_stale_frames_never_prove_a_constant(source):
    result = check_integer_comparison(source, "comparison is always true: `Value < 0`", language="c", integer_abi="lp64")
    assert result["matches_claim"] is not True, result
    assert not result["entry_witness_validated"]


@pytest.mark.parametrize("claim", [
    "comparison is sometimes false: `Value < 0`",
    "comparison is always true and always false: `Value < 0`",
    "comparison is not always false: `Value < 0`",
    "it is not true that comparison is always false: `Value < 0`",
    "comparison is always false: `Value < = 0`",
    "comparison is always false: `Value < 0 && Other > 1`",
    "comparison is always false: `Value < 0` and `Value > 0`",
])
def test_unknown_subject_or_compound_claim_declines(claim):
    result = check_integer_comparison("int Read(unsigned Value){return Value<0;}", claim, language="c", integer_abi="lp64")
    assert result["matches_claim"] is None


@pytest.mark.parametrize("source,expression", [
    ("int Read(unsigned Value){return Value==-1;}", "Value == -1"),
    ("int Read(long Value,unsigned Limit){return Value<Limit;}", "Value < Limit"),
])
def test_unconstrained_mixed_signed_comparisons_do_not_invent_constancy(source, expression):
    result = check_integer_comparison(source, f"comparison is always false: `{expression}`", language="c", integer_abi="lp64")
    assert result["matches_claim"] is False


@pytest.mark.parametrize("phase", ["entry", "contrary"])
def test_unknown_cannot_publish_constant_truth(monkeypatch, phase):
    from core.audit import integer_comparison as checker
    from core.smt_solver import z3

    real_check, calls = checker.check_solver, []
    def check(solver):
        calls.append(1)
        if phase == "entry" or len(calls) == 2:
            return z3.unknown
        return real_check(solver)
    monkeypatch.setattr(checker, "check_solver", check)
    result = checker.check_integer_comparison("int Read(unsigned Value){return Value<0;}",
                                              "comparison is always false: `Value < 0`", language="c", integer_abi="lp64")
    assert result["matches_claim"] is None
    assert not result["entry_witness_validated"]


def test_independent_entry_replay_rejects_bad_storage_witness(monkeypatch):
    from core.audit import integer_comparison as checker

    monkeypatch.setattr(checker, "format_vars", lambda *a, **kw: {"Value": -1})
    result = checker.check_integer_comparison("int Read(unsigned Value){return Value<0;}",
                                              "comparison is always false: `Value < 0`", language="c", integer_abi="lp64")
    assert result["matches_claim"] is None
    assert not result["entry_witness_validated"]


def test_comparison_cannot_extend_an_expired_shared_query_budget():
    from core.smt_solver.session import query_budget

    with query_budget(0):
        result = check_integer_comparison("int Read(unsigned Value){return Value<0;}",
                                          "comparison is always false: `Value < 0`", language="c", integer_abi="lp64")
    assert result["matches_claim"] is None
    assert not result["entry_witness_validated"]


@pytest.mark.parametrize("abi,language,truth", [
    pytest.param("lp64", "c", True, id="lp64-c"),
    pytest.param("llp64", "c", False, id="llp64-c"),
    pytest.param("lp64", "cpp", True, id="lp64-cpp"),
    pytest.param("llp64", "cpp", False, id="llp64-cpp"),
])
def test_mixed_signed_comparison_uses_each_target_conversion(abi, language, truth):
    source = "int Read(long Value,unsigned Limit){if(Value == -1 && Limit == 1){if(Value < Limit)return 1;}return 0;}"
    claim = f"comparison is always {'true' if truth else 'false'}: `Value < Limit`"
    result = check_integer_comparison(source, claim, language=language, integer_abi=abi)
    assert result["matches_claim"] is True, result
    assert result["constant_truth"] is truth
    assert result["entry_witness_validated"] is True
    assert result["entry_witness"] == {"Value": -1, "Limit": 1}
    assert result["source_operation"]["comparison_width"] == (64 if abi == "lp64" else 32)
    assert result["source_operation"]["comparison_signed"] is truth


@pytest.mark.parametrize("relation,expected", [(">", True), ("<", None)])
def test_entry_guards_use_c_conversions_and_never_admit_an_infeasible_prefix(relation, expected):
    source = f"int Read(int Value,unsigned Limit){{if(Value {relation} Limit && Value == -1 && Limit == 1){{if(Value < 0)return 1;}}return 0;}}"
    result = check_integer_comparison(source, "comparison is always true: `Value < 0`", language="c", integer_abi="lp64")
    assert result["matches_claim"] is expected, result
    assert result["entry_witness_validated"] is (expected is True)
    if expected:
        assert result["entry_witness"] == {"Value": -1, "Limit": 1}


@pytest.mark.parametrize("language", ["c", "cpp"])
def test_negative_int_literal_converts_to_unsigned_for_the_comparison(language):
    result = check_integer_comparison("int Read(unsigned Value){if(Value > -1)return 1;return 0;}",
                                      "comparison is always false: `Value > -1`", language=language, integer_abi="lp64")
    assert result["matches_claim"] is True, result
    assert result["source_operation"]["comparison_signed"] is False


def test_wider_guard_parameter_does_not_widen_the_selected_comparison():
    result = check_integer_comparison("int Read(unsigned Value,long Wide){if(Wide==1){if(Value<0)return 1;}return 0;}",
                                      "comparison is always false: `Value < 0`", language="c", integer_abi="lp64")
    assert result["matches_claim"] is True, result
    assert result["source_operation"]["comparison_width"] == 32
    assert result["source_operation"]["parameter_promotions"]["Wide"] == {"width": 64, "signed": True}
    assert result["entry_witness"]["Wide"] == 1


def test_independent_conversion_replay_rejects_a_forged_entry_guard(monkeypatch):
    from core.audit import integer_comparison as checker

    monkeypatch.setattr(checker, "format_vars", lambda *a, **kw: {"Value": -1, "Limit": 0})
    source = "int Read(long Value,unsigned Limit){if(Value==-1 && Limit==1){if(Value<Limit)return 1;}return 0;}"
    result = checker.check_integer_comparison(source, "comparison is always false: `Value < Limit`",
                                              language="c", integer_abi="llp64")
    assert result["matches_claim"] is None
    assert not result["entry_witness_validated"]
