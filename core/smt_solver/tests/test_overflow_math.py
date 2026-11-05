"""Exhaustive small-width differential checks against unbounded integer math."""

import operator

import pytest

z3 = pytest.importorskip("z3")

from core.smt_solver import csem  # noqa: E402


@pytest.mark.parametrize("width", [2, 3, 4])
@pytest.mark.parametrize("signed", [False, True])
@pytest.mark.parametrize("op", ["+", "-", "*"])
def test_overflow_predicates_match_integer_math_for_every_small_input(width, signed, op):
    functions = {
        (False, "+"): csem.uadd_overflows, (True, "+"): csem.sadd_overflows,
        (False, "-"): csem.usub_underflows, (True, "-"): csem.ssub_overflows,
        (False, "*"): csem.umul_overflows, (True, "*"): csem.smul_overflows,
    }
    arithmetic = {"+": operator.add, "-": operator.sub, "*": operator.mul}[op]
    low = -(1 << (width - 1)) if signed else 0
    high = (1 << (width - int(signed))) - 1
    for a in range(low, high + 1):
        for b in range(low, high + 1):
            expected = not low <= arithmetic(a, b) <= high
            actual = z3.simplify(functions[signed, op](z3.BitVecVal(a, width), z3.BitVecVal(b, width)))
            assert z3.is_true(actual) == expected, (width, signed, op, a, b)
