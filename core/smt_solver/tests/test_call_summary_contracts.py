"""Optional call theory must obey arity, bit widths, and argument values."""

import pytest

from core.smt_solver import BV_C_INT8, BV_C_UINT8
from core.smt_solver.call_arguments import split_call_arguments
from core.smt_solver import path_feasibility as paths


@pytest.mark.parametrize("text,expected", [
    ("", ()), ("  ", ()), ("Data", ("Data",)),
    ("Data, 4", ("Data", "4")), ("inner(A,B), 4", ("inner(A,B)", "4")),
    ('"a,b", 4', ('"a,b"', "4")), ("Data[Other, Index], 4", ("Data[Other, Index]", "4")),
    ("(Value, Flag)", ("(Value, Flag)",)), ('"\\\"a,b", 4', ('"\\\"a,b"', "4")),
    ("Data,", None), (",4", None), ("Data,,4", None), ("Data[)", None),
    ("inner(Data", None), ('"unfinished', None), ("Data)", None),
], ids=["empty", "spaces", "one", "two", "nested", "quoted-comma", "index", "group", "escaped-quote",
        "trailing-comma", "leading-comma", "empty-slot", "mismatch", "unclosed", "unclosed-quote", "extra-close"])
def test_argument_boundaries(text, expected):
    assert split_call_arguments(text) == expected


@pytest.fixture
def solve():
    pytest.importorskip("z3")

    def query(texts, profile=BV_C_INT8, reduce=False):
        return paths.check_path_feasibility([paths.PathCondition(text, n) for n, text in enumerate(texts)],
                                            profile=profile, reduce_constraints=reduce)
    return query


@pytest.mark.parametrize("call", ["strlen()", "strlen(Data,Flag)", "wcslen()", "abs()", "labs(A,B)",
                                  "llabs(A,B)", "sizeof()", "min(Value)", "max(A,B,C)", "strnlen(Data)"])
@pytest.mark.parametrize("reduce", [True, False])
def test_wrong_arity_cannot_assert_theory(solve, call, reduce):
    result = solve([f"{call} == -1"], reduce=reduce)
    assert result.feasible is True
    assert result.summary_axioms == []
    assert result.anon_var_map == {"_anon_0": call}


@pytest.mark.parametrize("callee", ["abs", "labs", "llabs"])
@pytest.mark.parametrize("value", [-128, -127, -1, 0, 1, 127])
def test_absolute_value_is_bound_to_its_argument(solve, callee, value):
    # INT_MIN retains the existing conservative two's-complement behavior.
    expected = -128 if value == -128 else abs(value)
    good = solve([f"Value == {value}", f"{callee}(Value) == {expected}"])
    assert good.feasible is True
    assert good.model["Value"] == value
    bad = solve([f"Value == {value}", f"{callee}(Value) == {(expected + 1) % 128}"])
    assert bad.feasible is False
    assert good.summary_axioms == [f"summary: {callee}(Value)"]


@pytest.mark.parametrize("bound", [0, 4, 127, 128, 255])
@pytest.mark.parametrize("profile", [BV_C_INT8, BV_C_UINT8], ids=["signed", "unsigned"])
def test_bounded_length_uses_unsigned_result_bits(solve, bound, profile):
    literal = f"0x{bound:x}"
    valid = solve([f"strnlen(Data, {literal}) == {literal}"], profile=profile)
    assert valid.feasible is True
    assert valid.summary_axioms == [f"summary: strnlen(Data, {literal})"]
    placeholder, = valid.anon_var_map
    expected = bound - 256 if profile.signed and bound >= 128 else bound
    assert valid.model[placeholder] == expected
    if bound < 255:
        too_large = solve([f"strnlen(Data, {literal}) == 0x{bound + 1:x}"], profile=profile)
        assert too_large.feasible is False


@pytest.mark.parametrize("bound", ["Limit", "-1", "256", "04", "0x100", "Limit + 1"])
def test_unestablished_length_bound_does_not_invent_a_signed_range(solve, bound):
    result = solve([f"strnlen(Data, {bound}) == -1"])
    assert result.feasible is True and result.summary_axioms == []


def test_unsupported_abs_argument_keeps_only_conservative_range(solve):
    result = solve(["abs(probe(Data)) == 7"])
    assert result.feasible is True and result.summary_axioms
    assert "probe" not in result.model


def test_pure_arithmetic_abs_arguments_are_encoded(solve):
    result = solve(["Value == 2", "abs(Value - 7) == 5"])
    assert result.feasible is True and result.model["Value"] == 2
    assert solve(["Value == 2", "abs(Value - 7) == 6"]).feasible is False
