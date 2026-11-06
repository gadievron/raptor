"""Expression type propagation checked against independent integer arithmetic.

Widths below C int are tests of the uniform-width BV convention, not C ABIs.
"""

import pytest

from core.smt_solver import BVProfile
from core.smt_solver.path_feasibility import PathCondition, check_path_feasibility


@pytest.mark.parametrize('width', [8, 32, 64])
@pytest.mark.parametrize('reduce', [False, True])
def test_compound_hex_arithmetic_is_not_falsely_refuted(width, reduce):
    pytest.importorskip('z3')
    high = hex(1 << (width - 1))
    for expression in (f'(Value + {high})', f'(Value | {high})', f'({high})'):
        result = check_path_feasibility(
            [PathCondition('Value == 0', 0), PathCondition(f'{expression} > 0', 1)],
            profile=BVProfile(width, True), reduce_constraints=reduce,
        )
        assert result.feasible is True, (expression, result)
        assert not result.unknown


@pytest.mark.parametrize('width', [8, 32, 64])
def test_unsigned_literal_shift_uses_logical_right_shift(width):
    pytest.importorskip('z3')
    high = 1 << (width - 1)
    result = check_path_feasibility(
        [PathCondition(f'({hex(high)} >> 1) == {hex(high >> 1)}', 0)],
        profile=BVProfile(width, True), reduce_constraints=False,
    )
    assert result.feasible is True


@pytest.mark.parametrize('signed', [False, True])
def test_all_four_bit_inputs_match_integer_expression_reference(signed):
    pytest.importorskip('z3')
    profile = BVProfile(4, signed)

    def shifted(raw):
        value = raw - 16 if signed and raw >= 8 else raw
        return value >> 1

    def shifted_after_left(raw):
        bits = (raw << 1) % 16
        value = bits - 16 if signed and bits >= 8 else bits
        return value >> 1

    # None means the expression retains its variable's profile type.
    examples = [
        ('Value + 0x8', lambda n: n + 8, True),
        ('Value - 0x8', lambda n: n - 8, True),
        ('Value * 0x8', lambda n: n * 8, True),
        ('Value | 0x8', lambda n: n | 8, True),
        ('(Value + 0x8) >> 1', lambda n: ((n + 8) % 16) >> 1, True),
        ('(Value | 0x8) >> 1', lambda n: (n | 8) >> 1, True),
        ('Value >> (0x8 - 0x7)', shifted, None),
        ('Value << (0x8 - 0x7)', lambda n: n << 1, None),
        ('Value + (0x8 << 1)', lambda n: n, True),
        ('Value + 0x8 - 0x8', lambda n: n, True),
        ('Value - (0x8 - 0x8)', lambda n: n, True),
        ('(Value >> 1) + 0x8', lambda n: shifted(n) + 8, True),
        ('(Value << 1) >> 1', shifted_after_left, None),
    ]
    for expression, evaluate, unsigned in examples:
        for raw in range(16):
            source_value = raw - 16 if signed and raw >= 8 else raw
            bits = evaluate(raw) % 16
            result_signed = signed if unsigned is None else not unsigned
            mathematical = bits - 16 if result_signed and bits >= 8 else bits
            for negate in (False, True):
                expected = (mathematical > 0) != negate
                result = check_path_feasibility(
                    [PathCondition(f'Value == {source_value}', 0),
                     PathCondition(f'({expression}) > 0', 1, negated=negate)],
                    profile=profile, reduce_constraints=False,
                )
                assert result.feasible is expected, (signed, expression, raw, negate, result)
                assert not result.unknown


@pytest.mark.parametrize('call', [
    'min(0xc0 >> 1, 100)', 'max(0xc0 >> 1, 0)',
    'MIN(0xc0 >> 1, 100)', 'MAX(0xc0 >> 1, 0)', 'abs(0xc0 >> 1)',
])
def test_call_summary_arguments_keep_expression_shift_semantics(call):
    pytest.importorskip('z3')
    result = check_path_feasibility(
        [PathCondition(f'{call} == 96', 0)],
        profile=BVProfile(8, True), reduce_constraints=False,
    )
    assert result.feasible is True
    assert result.summary_axioms


def test_compatibility_parser_returns_bits_with_correct_shift_semantics():
    z3 = pytest.importorskip('z3')
    from core.smt_solver.path_feasibility import _parse_expr

    result = _parse_expr('0x80 >> 1', {}, profile=BVProfile(8, True))
    assert z3.is_bv(result)
    assert z3.simplify(result).as_long() == 64


@pytest.mark.parametrize(('comparison', 'expected'), [
    ('>', True), ('>=', True), ('<', False), ('<=', False), ('==', False), ('!=', True),
])
def test_each_comparison_uses_the_converted_expression_type(comparison, expected):
    pytest.importorskip('z3')
    result = check_path_feasibility(
        [PathCondition('Value == 0', 0), PathCondition(f'(Value + 0x80) {comparison} 0', 1)],
        profile=BVProfile(8, True), reduce_constraints=False,
    )
    assert result.feasible is expected
