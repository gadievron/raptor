"""Explicit bitvector sorts prevent Python coercions from choosing a model."""

import pytest

z3 = pytest.importorskip('z3')

from core.smt_solver import csem, ge, gt, le, lt, mk_var  # noqa: E402

BINARY = [csem.uadd_overflows, csem.sadd_overflows, csem.usub_underflows,
          csem.ssub_overflows, csem.umul_overflows, csem.smul_overflows, csem.ashr, csem.lshr]
COMPARE = [le, lt, ge, gt]


@pytest.mark.parametrize('action', BINARY + COMPARE, ids=lambda action: action.__name__)
@pytest.mark.parametrize('bad', [True, False, 1.9, '1', 1, None],
                         ids=['true', 'false', 'float', 'string', 'implicit-int', 'none'])
@pytest.mark.parametrize('side', ['left', 'right'])
def test_no_implicit_python_operand_coercion(action, bad, side):
    valid = z3.BitVecVal(8, 8)
    args = (bad, valid) if side == 'left' else (valid, bad)
    with pytest.raises(ValueError, match='bitvector expression'):
        action(*args, signed=True) if action in COMPARE else action(*args)


@pytest.mark.parametrize('action', BINARY + COMPARE, ids=lambda action: action.__name__)
@pytest.mark.parametrize('invalid', ['width', 'context', 'integer-sort', 'boolean-sort'])
def test_operand_width_sort_and_context_are_explicit(action, invalid):
    a = z3.BitVecVal(8, 8)
    b = {'width': lambda: z3.BitVecVal(1, 16),
         'context': lambda: z3.BitVecVal(1, 8, ctx=z3.Context()),
         'integer-sort': lambda: z3.IntVal(1),
         'boolean-sort': lambda: z3.BoolVal(True)}[invalid]()
    with pytest.raises(ValueError, match='width|context|bitvector expression'):
        action(a, b, signed=True) if action in COMPARE else action(a, b)


@pytest.mark.parametrize('action', [csem.cast, csem.truncate, csem.sign_extend, csem.zero_extend])
@pytest.mark.parametrize('invalid', ['sort', 'integer', 'boolean', 'python'])
def test_width_conversion_never_accepts_a_sort_as_an_expression(action, invalid):
    value = {'sort': lambda: z3.BitVecSort(8), 'integer': lambda: z3.Int('Value'),
             'boolean': lambda: z3.Bool('Value'), 'python': lambda: 8}[invalid]()
    with pytest.raises(ValueError, match='bitvector expression'):
        action(value, 8, False) if action is csem.cast else action(value, 8)


@pytest.mark.parametrize('name', [True, 7, 1.5, None])
def test_names_cannot_be_coerced_into_native_numeric_symbols(name):
    with pytest.raises(ValueError, match='name must be a string'):
        mk_var(name, 8)


@pytest.mark.parametrize('width', [1, 2, 3, 4])
def test_overflow_predicates_match_exhaustive_independent_integer_arithmetic(width):
    high = (1 << width) - 1
    low_s, high_s = -(1 << (width - 1)), (1 << (width - 1)) - 1
    def signed(value):
        return value - (1 << width) if value > high_s else value
    for a in range(1 << width):
        for b in range(1 << width):
            av, bv = z3.BitVecVal(a, width), z3.BitVecVal(b, width)
            expected = [a + b > high, not low_s <= signed(a) + signed(b) <= high_s,
                        a < b, not low_s <= signed(a) - signed(b) <= high_s,
                        a * b > high, not low_s <= signed(a) * signed(b) <= high_s]
            for action, reference in zip(BINARY[:6], expected, strict=True):
                assert z3.is_true(z3.simplify(action(av, bv))) is reference, (action.__name__, width, a, b)


def test_explicit_non_default_context_operands_remain_supported():
    ctx = z3.Context()
    a, b = z3.BitVecVal(255, 8, ctx=ctx), z3.BitVecVal(1, 8, ctx=ctx)
    assert z3.is_true(z3.simplify(csem.uadd_overflows(a, b)))
    assert z3.is_true(z3.simplify(lt(a, b, signed=True)))
