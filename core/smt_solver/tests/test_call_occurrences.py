"""Call text cannot establish value identity, purity, or unchanged memory."""

import pytest

from core.smt_solver import BV_C_INT8, BV_C_UINT8, z3
from core.smt_solver import path_feasibility as paths


@pytest.fixture(autouse=True)
def require_z3():
    pytest.importorskip('z3')


def intrinsic_query(conditions, **options):
    profile = options.pop('profile')
    return paths.check_verb_feasibility([('true intrinsic', z3.BoolVal(True))], conditions, {},
                                        profile=profile, **options)


ENTRIES = [paths.check_path_feasibility, paths.check_path_feasibility_dual, intrinsic_query]


@pytest.mark.parametrize('entry', ENTRIES)
@pytest.mark.parametrize('profile', [BV_C_INT8, BV_C_UINT8])
@pytest.mark.parametrize('reduce', [False, True])
@pytest.mark.parametrize('texts', [
    ['next_value() == 0', 'next_value() == 1'],
    ['next_value() != next_value()'],
    ['strlen(Data) == 1', 'strlen(Data) == 2'],
    ['next_value(inner()) == 0', 'next_value(inner()) == 1'],
])
def test_unproven_call_identity_cannot_refute(entry, profile, reduce, texts):
    conditions = [paths.PathCondition(text, i) for i, text in enumerate(texts)]
    result = entry(conditions, profile=profile, reduce_constraints=reduce)
    assert result.feasible is True and not result.unknown
    assert len(result.anon_var_map) == 2
    values = [result.model[name] for name in result.anon_var_map]
    assert values[0] != values[1]
    assert result.unsatisfied == []


@pytest.mark.parametrize('entry', ENTRIES)
@pytest.mark.parametrize('reduce', [False, True])
def test_repeated_opaque_call_equality_is_not_a_tautology(entry, reduce):
    result = entry([paths.PathCondition('next_value() == next_value()', 0)],
                   profile=BV_C_UINT8, reduce_constraints=reduce)
    assert result.feasible is True
    assert result.satisfied == []
    assert len(result.anon_var_map) == 2


@pytest.mark.parametrize('entry', ENTRIES)
@pytest.mark.parametrize('reduce', [False, True])
def test_explicitly_shared_result_keeps_real_contradictions(entry, reduce):
    result = entry([paths.PathCondition('Result == 0', 0), paths.PathCondition('Result == 1', 1)],
                   profile=BV_C_UINT8, reduce_constraints=reduce)
    assert result.feasible is False and result.unsatisfied
    assert result.anon_var_map == {}


@pytest.mark.parametrize('entry', [paths.check_path_feasibility, intrinsic_query])
@pytest.mark.parametrize('callee', ['min', 'max'])
@pytest.mark.parametrize('reduce', [False, True])
def test_definition_axioms_can_establish_identity_without_aliasing(entry, callee, reduce):
    result = entry([paths.PathCondition(f'{callee}(Value, 4) != {callee}(Value, 4)', 0)],
                   profile=BV_C_INT8, reduce_constraints=reduce)
    assert result.feasible is False
    assert len(result.anon_var_map) == 2
    assert result.summary_axioms == [f'summary: {callee}(Value, 4)'] * 2


@pytest.mark.parametrize('entry', ENTRIES)
def test_verdict_only_call_separation_needs_no_extra_solver_query(monkeypatch, entry):
    original = paths._new_solver
    checks = []

    def factory(*args, **kwargs):
        solver = original(*args, **kwargs)
        check = solver.check

        def observe(*args, **kwargs):
            checks.append(1)
            return check(*args, **kwargs)
        monkeypatch.setattr(solver, 'check', observe)
        return solver
    monkeypatch.setattr(paths, '_new_solver', factory)
    result = entry([paths.PathCondition('next_value() == 0', 0), paths.PathCondition('next_value() == 1', 1)],
                   profile=BV_C_UINT8, reduce_constraints=False)
    assert result.feasible is True
    assert checks == [1]


@pytest.mark.parametrize('entry', ENTRIES)
@pytest.mark.parametrize('reduce', [False, True])
def test_negated_guard_does_not_borrow_an_earlier_evaluation(entry, reduce):
    result = entry([paths.PathCondition('next_value() == 0', 0),
                    paths.PathCondition('next_value() == 0', 1, negated=True)],
                   profile=BV_C_UINT8, reduce_constraints=reduce)
    assert result.feasible is True and not result.unknown
    first, second = (result.model[name] for name in result.anon_var_map)
    assert first == 0 and second != 0
