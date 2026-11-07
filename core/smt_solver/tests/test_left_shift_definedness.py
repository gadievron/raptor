"""Strict signed left shifts use value bounds and independent count types."""

import pytest

z3 = pytest.importorskip('z3')

from core.smt_solver import new_solver  # noqa: E402
from core.smt_solver.csem import left_shift_undefined  # noqa: E402
from core.smt_solver.session import check_solver, query_budget  # noqa: E402


def integer(bits, width, signed):
    return bits - (1 << width) if signed and bits >= (1 << (width - 1)) else bits


@pytest.mark.parametrize('value_width', [1, 2, 3, 4])
@pytest.mark.parametrize('count_width', [1, 2, 3, 4])
@pytest.mark.parametrize('value_signed', [False, True])
@pytest.mark.parametrize('count_signed', [False, True])
def test_exhaustive_small_domains_match_independent_integer_rules(value_width, count_width, value_signed, count_signed):
    for value_bits in range(1 << value_width):
        value = integer(value_bits, value_width, value_signed)
        for count_bits in range(1 << count_width):
            count = integer(count_bits, count_width, count_signed)
            invalid = count < 0 or count >= value_width
            if not invalid and value_signed:
                invalid = value < 0 or value * (2 ** count) > (1 << (value_width - 1)) - 1
            expression = left_shift_undefined(z3.BitVecVal(value_bits, value_width),
                                              z3.BitVecVal(count_bits, count_width),
                                              value_signed=value_signed, count_signed=count_signed)
            assert z3.is_true(z3.simplify(expression)) is invalid, (value_width, count_width, value, count)


@pytest.mark.parametrize('width', [8, 16, 32, 64, 128])
def test_boundaries_and_a_wider_count_remain_in_one_private_context(width):
    context = z3.Context()
    one = z3.BitVecVal(1, width, ctx=context)
    for count, expected in [(0, False), (width - 2, False), (width - 1, True), (width, True),
                            (1 << width, True)]:
        expression = left_shift_undefined(one, z3.BitVecVal(count, width + 1, ctx=context),
                                          value_signed=True, count_signed=False)
        assert expression.ctx == context
        assert z3.is_true(z3.simplify(expression)) is expected


def test_signed_shift_needs_a_value_bound_as_well_as_a_valid_count():
    context = z3.Context()
    value = z3.BitVec('Value', 32, ctx=context)
    count = z3.BitVecVal(3, 64, ctx=context)
    invalid = left_shift_undefined(value, count, value_signed=True, count_signed=False)
    solver = new_solver(ctx=context)
    with query_budget(1000):
        solver.add(value >= 0, invalid)
        assert check_solver(solver) == z3.sat
        assert solver.model().eval(value).as_long() * 8 > (1 << 31) - 1
        solver.add(value <= ((1 << 31) - 1) // 8)
        assert check_solver(solver) == z3.unsat


def test_unsigned_value_wrap_is_not_a_left_shift_fault():
    maximum = z3.BitVecVal(255, 8)
    expression = left_shift_undefined(maximum, z3.BitVecVal(7, 16), value_signed=False, count_signed=True)
    assert z3.is_false(z3.simplify(expression))
    assert z3.simplify(maximum << 7).as_long() == 128


@pytest.mark.parametrize('bad', [True, 1, 1.5, '1', None])
@pytest.mark.parametrize('side', ['value', 'count'])
def test_python_operands_cannot_choose_the_formula(bad, side):
    args = [z3.BitVecVal(1, 8), z3.BitVecVal(1, 8)]
    args[0 if side == 'value' else 1] = bad
    with pytest.raises(ValueError, match='bitvector'):
        left_shift_undefined(*args, value_signed=True, count_signed=True)


@pytest.mark.parametrize('flag', ['value_signed', 'count_signed'])
@pytest.mark.parametrize('bad', [0, 1, None, 'signed'])
def test_signedness_flags_are_exact_booleans(flag, bad):
    flags = {'value_signed': True, 'count_signed': True, flag: bad}
    with pytest.raises(ValueError, match='boolean'):
        left_shift_undefined(z3.BitVecVal(1, 8), z3.BitVecVal(1, 8), **flags)


def test_mixed_contexts_are_refused_before_building_a_shift():
    with pytest.raises(ValueError, match='context'):
        left_shift_undefined(z3.BitVecVal(1, 8), z3.BitVecVal(1, 16, ctx=z3.Context()),
                             value_signed=False, count_signed=False)
