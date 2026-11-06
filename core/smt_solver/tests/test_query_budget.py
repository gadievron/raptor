"""One soft deadline covers repeated and nested managed solver queries."""

import pytest

z3 = pytest.importorskip('z3')

from core.smt_solver import session, path_feasibility as paths  # noqa: E402
from core.smt_solver.assertion_frames import track_frames  # noqa: E402
from core.smt_solver.rejection import RejectionKind, classify_solver_unknown  # noqa: E402


@pytest.fixture
def clock(monkeypatch):
    now = [10.0]
    monkeypatch.setattr(session, 'monotonic', lambda: now[0])
    return now


@pytest.mark.parametrize('factory', [session.new_solver, session.new_optimizer])
def test_repeated_checks_share_the_budget_and_preserve_the_factory_cap(clock, monkeypatch, factory):
    solver = factory(100)
    settings, checks = [], []
    native_set, native_check = solver.set, solver.check
    def set_parameter(name, value):
        settings.append((name, value))
        native_set(name, value)
    def check():
        checks.append(1)
        return native_check()
    monkeypatch.setattr(solver, 'set', set_parameter)
    monkeypatch.setattr(solver, 'check', check)
    with session.query_budget(1000):
        assert session.check_solver(solver) == z3.sat
        clock[0] += 0.95
        assert session.check_solver(solver) == z3.sat
        clock[0] += 0.1
        assert session.check_solver(solver) == z3.unknown
        assert classify_solver_unknown(solver) is RejectionKind.SOLVER_TIMEOUT
        assert 'budget exhausted' in session.solver_reason_unknown(solver)
    assert len(checks) == 2
    assert settings[0] == settings[1] == ('timeout', 100)
    assert 1 <= settings[2][1] <= 51
    assert settings[3] == ('timeout', 100)
    assert session.check_solver(solver) == z3.sat  # deadline and stale reason were reset
    assert solver._raptor_budget_exhausted is False


def test_nested_budget_cannot_extend_the_outer_deadline(clock):
    solver = session.new_solver()
    with session.query_budget(100):
        clock[0] += 0.2
        with session.query_budget(10000):
            assert session.check_solver(solver) == z3.unknown
    assert session.check_solver(solver) == z3.sat


def test_nested_budget_restores_the_outer_context_on_failure(clock):
    solver = session.new_solver()
    with session.query_budget(1000):
        with pytest.raises(RuntimeError, match='owned failure'):
            with session.query_budget(0):
                assert session.check_solver(solver) == z3.unknown
                raise RuntimeError('owned failure')
        assert session.check_solver(solver) == z3.sat
    assert session.check_solver(solver) == z3.sat


@pytest.mark.parametrize('factory', [session.new_solver, session.new_optimizer])
def test_expiry_does_not_reuse_an_earlier_native_unsat_core(clock, factory):
    solver = factory()
    frame = track_frames(solver, [([('contradiction', False)], [0])])
    assert frame.check() == z3.unsat and frame.core_indices(solver) == (0,)
    with session.query_budget(0):
        assert frame.check() == z3.unknown
        assert frame.core_indices(solver) is None
        assert frame.single_core_origin(solver) is None


@pytest.mark.parametrize('entry', [paths.check_path_feasibility, paths.check_path_feasibility_dual])
def test_expired_path_budget_is_unknown_not_a_refutation_or_complete_summary(entry):
    with session.query_budget(0):
        result = entry([paths.PathCondition('Value == 0', 0), paths.PathCondition('Value != 0', 1)])
    assert result.feasible is None and result.model == {} and result.wp_complete is False
    assert result.unknown_reasons and all(reason.kind is RejectionKind.SOLVER_TIMEOUT for reason in result.unknown_reasons)
    assert 'budget exhausted' in result.reasoning


def test_expiry_after_tautology_classification_cannot_reuse_its_sat_result(clock, monkeypatch):
    real = paths._new_solver
    def solver_factory(*args, **kwargs):
        solver = real(*args, **kwargs)
        native = solver.check
        def check():
            result = native()
            clock[0] += 1
            return result
        monkeypatch.setattr(solver, 'check', check)
        return solver
    monkeypatch.setattr(paths, '_new_solver', solver_factory)
    with session.query_budget(500):
        result = paths.check_path_feasibility([paths.PathCondition('Value == 7', 0)])
    # The first query was only tautology classification, so the actual
    # conjunction never got a SAT verdict after the budget expired.
    assert result.feasible is None and result.wp_complete is False


@pytest.mark.parametrize('factory', [session.new_solver, session.new_optimizer])
def test_budgeted_contexts_preserve_models_and_native_core_ownership(factory):
    context = z3.Context()
    solver = factory(ctx=context)
    value = z3.BitVec('Value', 8, ctx=context)
    frame = track_frames(solver, [([('seven', value == 7), ('eight', value == 8)], [2, 2])])
    with session.query_budget(500):
        assert frame.check() == z3.unsat
        assert frame.single_core_origin(solver) == 2
    assert frame.core_indices(solver) is not None


@pytest.mark.parametrize('value', [-1, True, '5', None, 0.5])
def test_invalid_budget_cannot_change_the_active_context(value):
    with pytest.raises(ValueError, match='nonnegative integer'):
        with session.query_budget(value):
            pytest.fail('invalid budget entered')
    assert session.check_solver(session.new_solver()) == z3.sat


def test_untracked_solver_caps_are_not_guessed_or_silently_increased():
    with session.query_budget(1000):
        with pytest.raises(ValueError, match='factory solver'):
            session.check_solver(z3.Solver())


def test_primary_sat_survives_expiry_during_optional_summary_reduction(clock, monkeypatch):
    real = paths._new_solver
    queries = []
    def solver_factory(*args, **kwargs):
        solver = real(*args, **kwargs)
        native = solver.check
        def check():
            result = native()
            queries.append(1)
            clock[0] += 0.1 if len(queries) == 1 else 1
            return result
        monkeypatch.setattr(solver, 'check', check)
        return solver
    monkeypatch.setattr(paths, '_new_solver', solver_factory)
    with session.query_budget(500):
        result = paths.check_path_feasibility([paths.PathCondition('Value == 7', 0)])
    assert result.feasible is True and result.model == {'Value': 7}
    assert result.wp_complete is False and len(queries) == 2


def test_failure_to_restore_timeout_is_visible_and_resets_the_budget_context(clock, monkeypatch):
    solver = session.new_solver()
    original = solver.set
    settings = []
    def set_parameter(name, value):
        settings.append(value)
        if len(settings) == 2:
            raise z3.Z3Exception('owned timeout restore failed')
        original(name, value)
    monkeypatch.setattr(solver, 'set', set_parameter)
    with pytest.raises(z3.Z3Exception, match='owned timeout restore failed'):
        with session.query_budget(500):
            session.check_solver(solver)
    assert session.check_solver(session.new_solver()) == z3.sat


def test_inconclusive_results_cannot_advertise_a_complete_summary():
    result = paths.PathSMTResult(None, [], [], [], {}, True, 'undecided', wp_complete=True)
    assert result.wp_complete is False


@pytest.mark.parametrize('factory', [session.new_solver, session.new_optimizer])
@pytest.mark.parametrize('ctx', [False, 1, 'default'])
def test_factory_contexts_are_not_coerced(factory, ctx):
    with pytest.raises(ValueError, match='Z3 context'):
        factory(ctx=ctx)
