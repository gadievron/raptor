"""Value-preservation obligations cover widening as well as narrowing."""

import pytest

z3 = pytest.importorskip('z3')

from core.smt_solver.csem import conversion_changes_value  # noqa: E402


@pytest.mark.parametrize('source_signed', [False, True])
@pytest.mark.parametrize('target_signed', [False, True])
def test_all_small_bit_patterns_match_independent_integer_conversions(source_signed, target_signed):
    def integer(raw, width, signed):
        return raw - (1 << width) if signed and raw >= (1 << (width - 1)) else raw
    for width in range(1, 5):
        for target in range(1, 7):
            for raw in range(1 << width):
                source = integer(raw, width, source_signed)
                converted = integer(source % (1 << target), target, target_signed)
                expression = conversion_changes_value(z3.BitVecVal(raw, width), target, target_signed,
                                                       from_signed=source_signed)
                assert z3.is_true(z3.simplify(expression)) is (source != converted)


def test_solver_proves_unsigned_widening_into_a_larger_signed_type_preserves_value():
    ctx = z3.Context()
    value = z3.BitVec('Value', 8, ctx=ctx)
    solver = z3.Solver(ctx=ctx)
    solver.add(conversion_changes_value(value, 16, True, from_signed=False))
    assert solver.check() == z3.unsat


def test_solver_finds_a_value_changing_signed_to_unsigned_widening():
    value = z3.BitVec('Value', 8)
    solver = z3.Solver()
    solver.add(conversion_changes_value(value, 16, False, from_signed=True))
    assert solver.check() == z3.sat
    raw = solver.model().eval(value).as_long()
    assert raw >= 128 and (raw - 256) != ((raw - 256) % 65536)


def test_solver_proves_signed_to_unsigned_widening_changes_exactly_negative_values():
    value = z3.BitVec('Value', 8)
    changed = conversion_changes_value(value, 16, False, from_signed=True)
    solver = z3.Solver()
    solver.add(changed != (value < 0))
    assert solver.check() == z3.unsat


def test_supplied_nonnegative_premise_proves_the_widening_conversion_value_preserving():
    value = z3.BitVec('Value', 8)
    solver = z3.Solver()
    solver.add(value >= 0, conversion_changes_value(value, 16, False, from_signed=True))
    assert solver.check() == z3.unsat
