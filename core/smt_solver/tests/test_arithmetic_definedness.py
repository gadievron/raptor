"""Explicit arithmetic fault obligations checked against integer oracles."""

import pytest

z3 = pytest.importorskip('z3')

from core.smt_solver import new_solver  # noqa: E402
from core.smt_solver.csem import division_undefined, shift_count_invalid  # noqa: E402
from core.smt_solver.session import check_solver, query_budget  # noqa: E402


@pytest.mark.parametrize('signed', [False, True])
@pytest.mark.parametrize('width', [1, 2, 3, 4, 5])
def test_division_and_remainder_faults_match_exhaustive_integer_domains(width, signed):
    modulus = 1 << width

    def integer(bits):
        return bits - modulus if signed and bits >= modulus // 2 else bits

    for left in range(modulus):
        for right in range(modulus):
            a, b = integer(left), integer(right)
            expected = b == 0 or (signed and a == -modulus // 2 and b == -1)
            actual = division_undefined(z3.BitVecVal(left, width), z3.BitVecVal(right, width), signed=signed)
            assert z3.is_true(z3.simplify(actual)) is expected, (width, signed, a, b)


@pytest.mark.parametrize('signed', [False, True])
@pytest.mark.parametrize('count_width', [1, 2, 3, 4, 8])
def test_shift_count_bounds_do_not_wrap_in_a_narrow_count_frame(count_width, signed):
    for value_width in (1, 2, 3, 8, 16, 32, 64, 128, 256, 257, 1024):
        for bits in range(1 << count_width):
            count = bits - (1 << count_width) if signed and bits >= (1 << (count_width - 1)) else bits
            actual = shift_count_invalid(z3.BitVecVal(bits, count_width), value_width, signed=signed)
            assert z3.is_true(z3.simplify(actual)) is (count < 0 or count >= value_width), (count_width, signed, value_width, count)


@pytest.mark.parametrize('signed', [False, True])
def test_division_guard_can_be_proved_sufficient_or_shown_insufficient(signed):
    context = z3.Context()
    numerator, divisor = z3.BitVecs('Numerator Divisor', 32, ctx=context)
    invalid = division_undefined(numerator, divisor, signed=signed)
    solver = new_solver(ctx=context)
    with query_budget(1000):
        solver.add(divisor != 0, invalid)
        assert check_solver(solver) == (z3.sat if signed else z3.unsat)
        if signed:
            model = solver.model()
            assert model.eval(numerator).as_long() == 1 << 31
            assert model.eval(divisor).as_long() == (1 << 32) - 1
            solver.add(z3.Or(numerator != -(1 << 31), divisor != -1))
            assert check_solver(solver) == z3.unsat


def test_shift_guard_uses_the_count_type_and_promoted_value_width():
    context = z3.Context()
    count = z3.BitVec('Count', 16, ctx=context)
    invalid = shift_count_invalid(count, 32, signed=True)
    solver = new_solver(ctx=context)
    with query_budget(1000):
        solver.add(count < 32, invalid)
        assert check_solver(solver) == z3.sat  # an upper bound alone permits negative counts
        assert solver.model().eval(count).as_signed_long() < 0
        solver.add(count >= 0)
        assert check_solver(solver) == z3.unsat


@pytest.mark.parametrize('width', [8, 16, 32, 64, 128])
def test_large_width_boundary_cases_in_a_private_context(width):
    context = z3.Context()
    minimum = z3.BitVecVal(1 << (width - 1), width, ctx=context)
    minus_one = z3.BitVecVal(-1, width, ctx=context)
    assert z3.is_true(z3.simplify(division_undefined(minimum, minus_one, signed=True)))
    assert z3.is_false(z3.simplify(division_undefined(minimum, minus_one, signed=False)))
    assert z3.is_true(z3.simplify(shift_count_invalid(z3.BitVecVal(width, width, ctx=context), width, signed=False)))


@pytest.mark.parametrize('bad', [True, 1, 1.5, '1', None])
def test_predicates_require_explicit_bitvectors(bad):
    valid = z3.BitVecVal(1, 8)
    with pytest.raises(ValueError, match='bitvector'):
        division_undefined(valid, bad, signed=False)
    with pytest.raises(ValueError, match='bitvector'):
        division_undefined(bad, valid, signed=False)
    with pytest.raises(ValueError, match='bitvector'):
        shift_count_invalid(bad, 8, signed=False)


@pytest.mark.parametrize('bad', [0, 1, None, 'signed'])
def test_signedness_cannot_be_selected_by_truthiness(bad):
    valid = z3.BitVecVal(1, 8)
    with pytest.raises(ValueError, match='boolean'):
        division_undefined(valid, valid, signed=bad)
    with pytest.raises(ValueError, match='boolean'):
        shift_count_invalid(valid, 8, signed=bad)


@pytest.mark.parametrize('bad', [True, 0, -1, 1.5, '8', None])
def test_shift_value_width_requires_an_explicit_positive_integer(bad):
    with pytest.raises(ValueError, match='value_width'):
        shift_count_invalid(z3.BitVecVal(1, 8), bad, signed=False)


def test_division_operands_must_share_width_and_context():
    valid = z3.BitVecVal(1, 8)
    for other in (z3.BitVecVal(1, 16), z3.BitVecVal(1, 8, ctx=z3.Context())):
        with pytest.raises(ValueError, match='width|context'):
            division_undefined(valid, other, signed=False)


@pytest.mark.parametrize('reduce', [False, True])
@pytest.mark.parametrize('signed', [False, True])
@pytest.mark.parametrize('operation', ['division', 'shift-count'])
def test_new_obligations_use_the_existing_guard_and_verdict_pipeline(operation, signed, reduce):
    from core.smt_solver import BVProfile
    from core.smt_solver.path_feasibility import PathCondition, check_verb_feasibility

    profile = BVProfile(32, signed)
    left, right = z3.BitVecs('Value Count', 32)
    if operation == 'division':
        obligation = division_undefined(left, right, signed=signed)
        insufficient = ['Count != 0']
        sufficient = insufficient + ['Count != -1'] if signed else insufficient
    else:
        obligation = shift_count_invalid(right, 32, signed=signed)
        insufficient = ['Count < 32']
        sufficient = insufficient + ['Count >= 0'] if signed else insufficient
    for guards, expected in ((insufficient, signed), (sufficient, False)):
        result = check_verb_feasibility(
            [(operation + ' is undefined', obligation)],
            [PathCondition(text, index) for index, text in enumerate(guards)],
            {'Value': left, 'Count': right}, profile=profile, reduce_constraints=reduce,
        )
        assert result.feasible is expected, result
        assert not result.unknown
        if not expected:
            assert result.model == {} and result.unsatisfied
        elif operation == 'division':
            assert result.model['Value'] == -(1 << 31) and result.model['Count'] == -1
        else:
            assert result.model['Count'] < 0
