"""Witness expression evaluation preserves native identity and caller state."""

import pytest

z3 = pytest.importorskip('z3')

from core.smt_solver.witness import format_vars, format_witness  # noqa: E402


@pytest.mark.parametrize('completion', [False, True])
def test_derived_terms_and_constants_evaluate_in_the_same_assignment(completion):
    ctx = z3.Context()
    value = z3.BitVec('Value', 8, ctx=ctx)
    model = z3.Model(ctx=ctx)
    model.update_value(value, z3.BitVecVal(255, 8, ctx=ctx))
    result = format_vars(model, {'input': value, 'next': value + 1, 'literal': z3.BitVecVal(7, 4, ctx=ctx)},
                         {'input': True}, completion=completion)
    assert result == {'input': -1, 'next': 0, 'literal': 7}


def test_completion_is_private_and_non_completed_terms_stay_unassigned():
    free = z3.BitVec('Free', 8)
    model = z3.Model()
    registry = {'input': free, 'next': free + 1}
    assert format_vars(model, registry, False) == {}
    assert format_vars(model, registry, False, completion=True) == {'input': 0, 'next': 1}
    assert model.decls() == []
    assert format_vars(model, registry, False) == {}


@pytest.mark.parametrize('invalid', ['name', 'context', 'sort', 'none', 'registry'])
def test_invalid_registry_is_rejected_before_any_model_evaluation(monkeypatch, invalid):
    free = z3.BitVec('Free', 8)
    registry = {'Free': free}
    if invalid == 'registry':
        registry = []
    elif invalid == 'name':
        registry[1] = free
    elif invalid == 'context':
        registry['bad'] = z3.BitVec('Free', 8, ctx=z3.Context())
    elif invalid == 'sort':
        registry['bad'] = z3.Int('Other')
    else:
        registry['bad'] = None
    model = z3.Model()
    monkeypatch.setattr(z3.ModelRef, 'eval', lambda *a, **kw: pytest.fail('invalid registry was evaluated'))
    with pytest.raises(ValueError, match='mapping|names|context|bitvector'):
        format_vars(model, registry, False, completion=True)
    assert model.decls() == []


@pytest.mark.parametrize('formatter', [format_vars, format_witness])
def test_model_inputs_are_real_native_models(formatter):
    with pytest.raises(ValueError, match='model must be a Z3 model'):
        formatter(None, {}, False) if formatter is format_vars else formatter(None, False)


def test_same_printed_name_at_different_widths_remains_distinct():
    a, b = z3.BitVec('Value', 8), z3.BitVec('Value', 16)
    model = z3.Model()
    model.update_value(a, z3.BitVecVal(255, 8))
    model.update_value(b, z3.BitVecVal(7, 16))
    assert format_vars(model, {'narrow': a, 'wide': b, 'sum': z3.ZeroExt(8, a) + b},
                       {'narrow': True}) == {'narrow': -1, 'wide': 7, 'sum': 262}


def test_completion_of_function_terms_does_not_install_interpretations_in_the_input_model():
    value = z3.BitVec('Input', 8)
    function = z3.Function('Transform', z3.BitVecSort(8), z3.BitVecSort(8))
    model = z3.Model()
    result = format_vars(model, {'input': value, 'result': function(value)}, False, completion=True)
    assert result == {'input': 0, 'result': 0}
    assert model.decls() == []


def test_a_derived_constant_can_be_concrete_without_completing_its_input():
    value = z3.BitVec('Input', 8)
    model = z3.Model()
    assert format_vars(model, {'input': value, 'difference': value - value}, False) == {'difference': 0}
    assert model.decls() == []
