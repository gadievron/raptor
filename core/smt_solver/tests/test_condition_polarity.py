"""Branch polarity must be a Boolean, never Python truthiness of metadata."""

import pytest

from core.smt_solver import path_feasibility as paths


@pytest.mark.parametrize('polarity', ['false', 'true', '', 0, 1, None, [], {}],
                         ids=['string-false', 'string-true', 'empty-string', 'zero', 'one', 'null', 'list', 'dict'])
def test_condition_constructor_declines_non_boolean_polarity(polarity):
    with pytest.raises(ValueError, match='negated must be a boolean'):
        paths.PathCondition('Value == 0', 0, negated=polarity)


@pytest.mark.parametrize('entry', [paths.check_path_feasibility, paths.check_path_feasibility_dual])
@pytest.mark.parametrize('polarity', ['false', 0, None])
def test_mutated_polarity_is_revalidated_before_solver_construction(monkeypatch, entry, polarity):
    condition = paths.PathCondition('Value == 0', 0)
    condition.negated = polarity
    monkeypatch.setattr(paths, '_new_solver', lambda *a, **k: pytest.fail('invalid polarity reached Z3'))
    monkeypatch.setattr(paths, '_new_optimizer', lambda *a, **k: pytest.fail('invalid polarity reached Z3'))
    with pytest.raises(ValueError, match='negated must be a boolean'):
        entry([condition], prefer_witness=('Value', 'max'))


def test_verb_guards_obey_the_same_contract_before_solver_construction(monkeypatch):
    condition = paths.PathCondition('Value == 0', 0)
    condition.negated = 'false'
    monkeypatch.setattr(paths, '_new_solver', lambda *a, **k: pytest.fail('invalid polarity reached Z3'))
    with pytest.raises(ValueError, match='negated must be a boolean'):
        paths.check_verb_feasibility([], [condition], {})


@pytest.mark.parametrize('entry', [paths.check_path_feasibility, paths.check_path_feasibility_dual])
@pytest.mark.parametrize('negated', [False, True])
def test_real_boolean_polarity_preserves_joint_verdicts(entry, negated):
    pytest.importorskip('z3')
    conditions = [paths.PathCondition('Value == 0', 0), paths.PathCondition('Value == 0', 1, negated=negated)]
    result = entry(conditions, reduce_constraints=False)
    assert result.feasible is (not negated)
    if negated:
        assert set(result.unsatisfied) == {'Value == 0', 'NOT (Value == 0)'}


def test_bad_polarity_does_not_become_acceptable_without_z3(monkeypatch):
    condition = paths.PathCondition('Value == 0', 0)
    condition.negated = 'false'
    monkeypatch.setattr(paths, '_z3_available', lambda: False)
    with pytest.raises(ValueError, match='negated must be a boolean'):
        paths.check_path_feasibility([condition])
