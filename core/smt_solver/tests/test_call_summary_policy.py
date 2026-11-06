"""A source consumer can omit unbound callee models before solving."""

from unittest.mock import patch

import pytest

from core.smt_solver import BV_C_INT8, BV_C_UINT8
from core.smt_solver import path_feasibility as paths


def conditions(*texts):
    return [paths.PathCondition(text, index) for index, text in enumerate(texts)]


@pytest.mark.parametrize('reduce', [False, True])
@pytest.mark.parametrize('entry', [paths.check_path_feasibility, paths.check_path_feasibility_dual])
def test_unbound_summary_cannot_refute_a_source_call(entry, reduce):
    pytest.importorskip('z3')
    texts = conditions('min(0, 4) > 4')
    modeled = entry(texts, profile=BV_C_INT8, reduce_constraints=reduce)
    opaque = entry(texts, profile=BV_C_INT8, reduce_constraints=reduce, use_call_summaries=False)
    assert modeled.feasible is False and modeled.summary_axioms
    assert opaque.feasible is True and opaque.summary_axioms == []
    placeholder, = opaque.anon_var_map
    assert opaque.model[placeholder] > 4
    assert opaque.unknown == []
    if reduce:
        assert opaque.wp_conjuncts == ['min(0, 4) > 4']


@pytest.mark.parametrize('callee,summary', list(paths._CALL_SUMMARIES.items()))
def test_disabling_summaries_never_invokes_a_builder(callee, summary):
    pytest.importorskip('z3')
    count, _builder = summary
    arguments = 'Data' if count == 1 else 'Data, 4'
    text = f'{callee}({arguments}) == 0'
    modeled = paths.check_path_feasibility(conditions(text), profile=BV_C_INT8, reduce_constraints=False)
    assert modeled.summary_axioms == [f'summary: {callee}({arguments})']
    with patch.object(paths, '_summarise_call', side_effect=AssertionError('unbound builder invoked')):
        opaque = paths.check_path_feasibility(conditions(text), profile=BV_C_INT8,
                                              use_call_summaries=False, reduce_constraints=False)
    assert opaque.feasible is True and opaque.summary_axioms == []
    assert 'Data' not in opaque.model
    assert list(opaque.anon_var_map.values()) == [f'{callee}({arguments})']


@pytest.mark.parametrize('entry', [paths.check_path_feasibility, paths.check_path_feasibility_dual])
@pytest.mark.parametrize('invalid', [None, 0, 1, 'false', []])
def test_summary_policy_is_strict_boolean_before_native_allocation(entry, invalid):
    with patch.object(paths, '_z3_available', side_effect=AssertionError('native availability accessed')):
        with pytest.raises(ValueError, match='use_call_summaries'):
            entry([], use_call_summaries=invalid)


def test_dual_legs_and_contradiction_probes_preserve_the_policy():
    pytest.importorskip('z3')
    original = paths.check_path_feasibility
    with patch.object(paths, 'check_path_feasibility', wraps=original) as checked:
        result = paths.check_path_feasibility_dual(conditions('Value == 0', 'Value == 1'),
                                                   profile=BV_C_UINT8, reduce_constraints=False,
                                                   use_call_summaries=False)
    assert result.feasible is False
    assert checked.call_count >= 4
    assert all(call.kwargs['use_call_summaries'] is False for call in checked.call_args_list)


@pytest.mark.parametrize('entry', [paths.check_path_feasibility, paths.check_path_feasibility_dual])
def test_opaque_mode_needs_only_one_primary_check_for_sat(monkeypatch, entry):
    pytest.importorskip('z3')
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
    result = entry(conditions('min(0, 4) > 4'), profile=BV_C_INT8,
                   reduce_constraints=False, use_call_summaries=False)
    assert result.feasible is True and checks == [1]


@pytest.mark.parametrize('reduce', [False, True])
def test_real_scalar_contradictions_survive_an_unrelated_opaque_call(reduce):
    pytest.importorskip('z3')
    result = paths.check_path_feasibility_dual(conditions('Value == 0', 'Value == 1', 'min(0, 4) > 4'),
                                               profile=BV_C_INT8, reduce_constraints=reduce,
                                               use_call_summaries=False)
    assert result.feasible is False
    assert result.summary_axioms == []
    assert set(result.unsatisfied) == {'Value == 0', 'Value == 1'}
