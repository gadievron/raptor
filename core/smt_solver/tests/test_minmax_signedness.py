"""Optional min/max theory must retain argument comparison signedness."""

import pytest

z3 = pytest.importorskip("z3")

from core.smt_solver import BVProfile  # noqa: E402
from core.smt_solver import path_feasibility as paths  # noqa: E402


@pytest.mark.parametrize("callee,expected,wrong", [
    ("min", "1", "0x80"), ("MIN", "1", "0x80"),
    ("max", "0x80", "1"), ("MAX", "0x80", "1"),
])
@pytest.mark.parametrize("reduce", [False, True])
def test_unsigned_argument_controls_summary_ordering(callee, expected, wrong, reduce):
    def solve(value):
        return paths.check_path_feasibility(
            [paths.PathCondition(f"{callee}(0x80, 1) == {value}", 0)],
            profile=BVProfile(8, True), reduce_constraints=reduce,
        )
    valid = solve(expected)
    assert valid.feasible is True
    assert valid.summary_axioms == [f"summary: {callee}(0x80, 1)"]
    assert solve(wrong).feasible is False


@pytest.mark.parametrize("pick_smaller", [False, True])
@pytest.mark.parametrize("arguments,unsigned", [
    (("Left", "Right"), False),
    (("Left + 0x8", "Right"), True),
    (("Left", "Right + 0x8"), True),
    (("Left >> 0x1", "Right"), False),
])
def test_all_small_inputs_match_independent_argument_order(pick_smaller, arguments, unsigned):
    profile = BVProfile(4, True)
    left, right, result = z3.BitVecs("Left Right Result", 4)
    summary = paths._minmax_summary(pick_smaller)(
        result, ", ".join(arguments), {"Left": left, "Right": right}, profile,
    )
    assert summary is not None
    for a in range(16):
        for b in range(16):
            lhs = (a + 8) % 16 if "+" in arguments[0] else a
            rhs = (b + 8) % 16 if "+" in arguments[1] else b
            if ">>" in arguments[0]:
                lhs = ((a - 16 if a >= 8 else a) >> 1) % 16
            ordered = [lhs, rhs] if unsigned else [v - 16 if v >= 8 else v for v in (lhs, rhs)]
            expected = (min(ordered) if pick_smaller else max(ordered)) % 16
            substituted = z3.substitute(summary, (left, z3.BitVecVal(a, 4)),
                                        (right, z3.BitVecVal(b, 4)), (result, z3.BitVecVal(expected, 4)))
            assert z3.is_true(z3.simplify(substituted)), (a, b, arguments, expected)
