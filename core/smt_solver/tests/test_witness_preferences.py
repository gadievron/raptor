"""Witness preferences preserve variable identity and feasibility semantics."""

from unittest.mock import MagicMock, patch

import pytest

from core.smt_solver.condition_syntax import plain_condition_identifiers
from core.smt_solver.witness_preferences import parse_witness_preference


@pytest.mark.parametrize(('text', 'names'), [
    ('Count * 16 < count', ('Count', 'count')),
    ('NULL != Null', ('Null',)),
    ('null + not + and + or > 0', ('null', 'not', 'and', 'or')),
    ('0x10 < Buffer', ('Buffer',)),
    ('strlen("Count") < Limit', ('Limit',)),
    ('probe(nested(Count), "x\\\"y") < Limit', ('Limit',)),
    ('probe(Count < Limit', ()),
    ('"unterminated Count', ()),
    ('NULL is equal to Count', ('Count',)),
    ('A' * 2049, ()),
])
def test_plain_identifiers(text, names):
    assert plain_condition_identifiers(text) == names


@pytest.mark.parametrize('spec', [('Count', 1), (None, 'max'), ('Count',),
                                  ('Count', 'sideways'), ('', 'max')])
def test_invalid_preferences_before_native_allocation(spec):
    from core.smt_solver.path_feasibility import (
        check_path_feasibility, check_path_feasibility_dual,
    )
    for check in (check_path_feasibility, check_path_feasibility_dual):
        with patch('core.smt_solver.path_feasibility._z3_available', side_effect=AssertionError):
            with pytest.raises(ValueError):
                check([], prefer_witness=spec)


def test_preference_normalisation_preserves_source_case():
    assert parse_witness_preference(' MAX: Count ') == ('Count', 'max')
    assert parse_witness_preference((' Count ', ' MIN ')) == ('Count', 'min')
    with pytest.raises(TypeError):
        parse_witness_preference(42)


@pytest.mark.parametrize(('signed', 'direction', 'expected'), [
    (False, 'max', 255), (False, 'min', 0),
    (True, 'max', 127), (True, 'min', -128),
])
def test_tautological_target_still_has_extreme_witness(signed, direction, expected):
    pytest.importorskip('z3')
    from core.smt_solver import BVProfile
    from core.smt_solver.path_feasibility import PathCondition, check_path_feasibility
    result = check_path_feasibility(
        [PathCondition('Count == Count', 0)], profile=BVProfile(8, signed),
        prefer_witness=f'{direction}:Count',
    )
    assert result.feasible is True
    assert result.model['Count'] == expected


def test_case_distinct_targets_and_unknown_only_verdict():
    pytest.importorskip('z3')
    from core.smt_solver import BV_C_UINT8
    from core.smt_solver.path_feasibility import PathCondition, check_path_feasibility
    conditions = [PathCondition('Count <= 9', 0), PathCondition('count == 2', 1)]
    result = check_path_feasibility(conditions, profile=BV_C_UINT8,
                                   prefer_witness=('Count', 'max'), reduce_constraints=False)
    assert result.feasible is True
    assert result.model == {'Count': 9, 'count': 2}
    unknown = check_path_feasibility(
        [PathCondition('Count == Count', 0), PathCondition('unsupported @ syntax', 1)],
        prefer_witness=('Count', 'max'),
    )
    assert unknown.feasible is None
    assert unknown.model == {}


def test_unsteered_tautology_keeps_no_check_fast_path():
    pytest.importorskip('z3')
    from core.smt_solver.path_feasibility import PathCondition, check_path_feasibility
    import core.smt_solver.path_feasibility as paths
    real_factory = paths._new_solver
    solvers = []

    def factory(*args, **kwargs):
        solver = real_factory(*args, **kwargs)
        solver.check = MagicMock(wraps=solver.check)
        solvers.append(solver)
        return solver

    with patch.object(paths, '_new_solver', side_effect=factory):
        result = check_path_feasibility([PathCondition('Count == Count', 0)])
    assert result.feasible is True
    assert result.model == {}
    assert solvers[-1].check.call_count == 0
    assert sum(solver.check.call_count for solver in solvers) == 1
