"""A failed rollback cannot masquerade as a successfully restored solver."""

import pytest

z3 = pytest.importorskip("z3")

from core.smt_solver import scoped  # noqa: E402
from core.smt_solver import session  # noqa: E402


def fail_pop():
    raise z3.Z3Exception("owned rollback failure")


def test_failed_rollback_is_visible_before_a_later_query_can_use_leaked_facts(monkeypatch):
    solver = z3.Solver()
    value = z3.Int("Value")
    solver.add(value == 0)
    monkeypatch.setattr(solver, "pop", fail_pop)
    with pytest.raises(RuntimeError, match="state was not restored") as failure:
        with scoped(solver):
            solver.add(value == 1)
    assert isinstance(failure.value.__cause__, z3.Z3Exception)
    assert solver.num_scopes() == 1
    assert solver.check() == z3.unsat  # demonstrates the contaminated state, not a valid later proof


def test_body_and_cleanup_failures_are_both_retained(monkeypatch):
    solver = z3.Solver()
    monkeypatch.setattr(solver, "pop", fail_pop)
    body = ValueError("owned body failure")
    with pytest.raises(ExceptionGroup) as failure:
        with scoped(solver):
            raise body
    assert failure.value.exceptions[0] is body
    cleanup = failure.value.exceptions[1]
    assert isinstance(cleanup, RuntimeError)
    assert isinstance(cleanup.__cause__, z3.Z3Exception)


@pytest.mark.parametrize("control", [KeyboardInterrupt(), SystemExit(3), GeneratorExit()])
def test_cleanup_failure_does_not_hide_control_flow_exceptions(monkeypatch, control):
    solver = z3.Solver()
    monkeypatch.setattr(solver, "pop", fail_pop)
    with pytest.raises(BaseExceptionGroup) as failure:
        with scoped(solver):
            raise control
    assert not isinstance(failure.value, Exception)
    assert failure.value.exceptions[0] is control


def test_failed_setup_does_not_run_body_or_attempt_cleanup(monkeypatch):
    solver = z3.Solver()
    def fail_push():
        raise z3.Z3Exception("owned setup failure")
    monkeypatch.setattr(solver, "push", fail_push)
    monkeypatch.setattr(solver, "pop", lambda: pytest.fail("no successful push to undo"))
    with pytest.raises(RuntimeError, match="push.*failed"):
        with scoped(solver):
            pytest.fail("body ran after failed setup")


@pytest.mark.parametrize("factory_name", ["new_solver", "new_optimizer"])
@pytest.mark.parametrize("timeout", [False, True, 0.5, -1.5, "5", None])
def test_invalid_timeout_types_never_reach_z3(monkeypatch, factory_name, timeout):
    def forbidden(*args, **kwargs):
        pytest.fail("invalid timeout reached the native backend")
    monkeypatch.setattr(session.z3, "Solver" if factory_name == "new_solver" else "Optimize", forbidden)
    with pytest.raises(ValueError, match="timeout_ms must be an integer"):
        getattr(session, factory_name)(timeout)


@pytest.mark.parametrize("factory_name,backend", [("new_solver", "Solver"), ("new_optimizer", "Optimize")])
@pytest.mark.parametrize("supplied,expected", [(0, 1), (-10, 1), (17, 17), (1 << 40, (1 << 31) - 1)])
def test_valid_integer_timeout_clamps_are_still_applied(monkeypatch, factory_name, backend, supplied, expected):
    constructor = getattr(z3, backend)
    seen = []
    def recording():
        solver = constructor()
        original = solver.set
        def set_parameter(name, value):
            seen.append((name, value))
            original(name, value)
        monkeypatch.setattr(solver, "set", set_parameter)
        return solver
    monkeypatch.setattr(session.z3, backend, recording)
    getattr(session, factory_name)(supplied)
    assert seen == [("timeout", expected)]
