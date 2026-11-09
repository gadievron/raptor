"""Native solver admission preserves identifiers that resemble English operators."""

import pytest

pytest.importorskip('z3')

from core.smt_solver import BV_C_INT8, BV_C_UINT8
from core.smt_solver.path_feasibility import PathCondition, check_path_feasibility


@pytest.mark.parametrize('name', ['equals', 'exceeds', 'below'])
@pytest.mark.parametrize('template', ['{} == 1', '1 == {}', '{} + 1 == 2', '1 + {} == 2'])
def test_alias_named_operand_has_a_native_witness(name, template):
    result = check_path_feasibility(
        [PathCondition(template.format(name), 0)],
        profile=BV_C_UINT8, reduce_constraints=False,
    )
    assert result.feasible is True
    assert result.unknown == []
    assert result.model[name] == 1


@pytest.mark.parametrize(('alias', 'other'), [
    ('equals', '=='), ('exceeds', '>'), ('below', '<'),
])
def test_english_operator_and_alias_named_operand_remain_consistent(alias, other):
    result = check_path_feasibility(
        [PathCondition(f'equals {alias} 1', 0), PathCondition(f'equals {other} 1', 1)],
        profile=BV_C_UINT8, reduce_constraints=False,
    )
    assert result.feasible is True
    assert result.unknown == []
    assert 'equals' in result.model


def test_alias_named_operand_can_still_prove_a_contradiction():
    result = check_path_feasibility(
        [PathCondition('equals == 1', 0), PathCondition('equals != 1', 1)],
        profile=BV_C_UINT8, reduce_constraints=False,
    )
    assert result.feasible is False
    assert result.unknown == []


@pytest.mark.parametrize('text', ['(Type) equals - 1', '(Type) equals (1)'])
def test_cast_shaped_alias_input_remains_inconclusive(text):
    result = check_path_feasibility(
        [PathCondition(text, 0)],
        profile=BV_C_INT8, reduce_constraints=False,
    )
    assert result.feasible is None
    assert result.unknown == [text]
