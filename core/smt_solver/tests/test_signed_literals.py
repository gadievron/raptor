"""Signed decimal atoms use the shared literal range validator end to end."""

import pytest

from core.smt_solver import BVProfile, RejectionKind
from core.smt_solver.path_feasibility import PathCondition, check_path_feasibility


@pytest.mark.parametrize("width", [8, 16, 32, 64])
@pytest.mark.parametrize("value_kind", ["minus-one", "minimum"])
def test_signed_literals_reach_the_solver_and_preserve_their_value(width, value_kind):
    pytest.importorskip("z3")
    value = -1 if value_kind == "minus-one" else -(1 << (width - 1))
    result = check_path_feasibility([PathCondition(f"Value == {value}", 0)], profile=BVProfile(width, True))
    assert result.feasible is True
    assert not result.unknown
    assert result.model["Value"] == value


@pytest.mark.parametrize("width", [8, 16, 32, 64])
def test_out_of_range_negative_literals_are_not_wrapped(width):
    pytest.importorskip("z3")
    value = -(1 << (width - 1)) - 1
    result = check_path_feasibility([PathCondition(f"Value == {value}", 0)], profile=BVProfile(width, True))
    assert result.feasible is None
    assert result.unknown_reasons[0].kind == RejectionKind.LITERAL_OUT_OF_RANGE


@pytest.mark.parametrize("expression", ["Value == -1", "Value > (-1)", "Value + (-1) == 0"])
def test_negative_values_do_not_become_unsigned_bit_patterns(expression):
    pytest.importorskip("z3")
    result = check_path_feasibility([PathCondition(expression, 0)], profile=BVProfile(32, False))
    assert result.feasible is None
    assert result.unknown_reasons[0].kind == RejectionKind.LITERAL_OUT_OF_RANGE


@pytest.mark.parametrize("expression", ["Value == -01", "Value == -Value", "Value == -(1 + 1)", "Value--1 == 0"])
def test_ambiguous_or_nonliteral_negation_remains_unencoded(expression):
    pytest.importorskip("z3")
    result = check_path_feasibility([PathCondition(expression, 0)], profile=BVProfile(32, True))
    assert result.feasible is None
    assert result.unknown


def test_negative_guard_contradiction_and_grouped_arithmetic():
    pytest.importorskip("z3")
    result = check_path_feasibility([PathCondition("Value >= -1", 0), PathCondition("Value < -1", 1)], profile=BVProfile(32, True))
    assert result.feasible is False and not result.unknown
    result = check_path_feasibility([PathCondition("Value + (-1) == 0", 0)], profile=BVProfile(32, True))
    assert result.feasible is True and result.model["Value"] == 1


@pytest.mark.parametrize("width", [True, False, 1.0, "32", None])
def test_invalid_width_types_fail_before_native_solver_work(width):
    with pytest.raises(ValueError, match="width must be positive"):
        BVProfile(width, False)


@pytest.mark.parametrize("signed", [0, 1, "false", None, []])
def test_truthy_non_boolean_signedness_is_not_a_profile(signed):
    with pytest.raises(ValueError, match="signed must be a boolean"):
        BVProfile(32, signed)
