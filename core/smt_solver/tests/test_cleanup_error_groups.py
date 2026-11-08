"""A second cleanup failure must not replace a pending solver interruption."""

import pytest

z3 = pytest.importorskip("z3")

from core.smt_solver import session  # noqa: E402


def capture_failure(action):
    # Catch the baseline interruption too: a missing group must fail an
    # assertion rather than interrupting the pytest worker itself.
    try:
        action()
    except BaseException as error:
        return error
    pytest.fail("the injected failure was not reached")


@pytest.mark.parametrize("factory", ["new_solver", "new_optimizer"])
@pytest.mark.parametrize("body_kind", [ValueError, KeyboardInterrupt])
@pytest.mark.parametrize("cleanup_kind", [KeyboardInterrupt, SystemExit, GeneratorExit])
def test_scope_groups_body_failure_with_interrupting_rollback(monkeypatch, factory, body_kind, cleanup_kind):
    solver = getattr(session, factory)()
    body = body_kind("owned body failure")
    cleanup = cleanup_kind("owned rollback interruption")
    events = []

    def pop():
        events.append("pop")
        raise cleanup

    def action():
        with session.scoped(solver):
            events.append("body")
            raise body

    monkeypatch.setattr(solver, "pop", pop)
    failure = capture_failure(action)
    assert events == ["body", "pop"]
    assert isinstance(failure, BaseExceptionGroup)
    assert not isinstance(failure, Exception)
    assert failure.exceptions == (body, cleanup)


@pytest.mark.parametrize("factory", ["new_solver", "new_optimizer"])
@pytest.mark.parametrize("cleanup_kind", [KeyboardInterrupt, SystemExit, GeneratorExit])
def test_lone_rollback_interruption_propagates_unchanged(monkeypatch, factory, cleanup_kind):
    solver = getattr(session, factory)()
    cleanup = cleanup_kind("owned rollback interruption")
    events = []

    def pop():
        events.append("pop")
        raise cleanup

    def action():
        with session.scoped(solver):
            events.append("body")

    monkeypatch.setattr(solver, "pop", pop)
    assert capture_failure(action) is cleanup
    assert events == ["body", "pop"]


def managed_failure(monkeypatch, factory, body, cleanup):
    solver = getattr(session, factory)(timeout_ms=50)
    original_set = solver.set
    events = []
    assumption = z3.Bool("owned_assumption")
    # Pin only the consumer's clock; host load cannot expire this injected query.
    monkeypatch.setattr(session, "monotonic", lambda: 1000.0)

    def set_parameter(*args):
        events.append(("set", args))
        if len(events) == 3 and cleanup is not None:
            raise cleanup
        return original_set(*args)

    def check(*assumptions):
        events.append(("check", assumptions))
        if body is not None:
            raise body
        return z3.sat

    def action():
        with session.query_budget(10000):
            return session.check_solver(solver, assumption)

    monkeypatch.setattr(solver, "set", set_parameter)
    monkeypatch.setattr(solver, "check", check)
    failure = capture_failure(action)
    assert events == [("set", ("timeout", 50)), ("check", (assumption,)), ("set", ("timeout", 50))]
    assert session._QUERY_DEADLINE.get() is None
    return failure


@pytest.mark.parametrize("factory", ["new_solver", "new_optimizer"])
@pytest.mark.parametrize("body_kind", [ValueError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("cleanup_kind", [RuntimeError, KeyboardInterrupt])
def test_query_and_timeout_restoration_failures_are_both_preserved(monkeypatch, factory, body_kind, cleanup_kind):
    body = body_kind("owned query failure")
    cleanup = cleanup_kind("owned timeout restoration failure")
    failure = managed_failure(monkeypatch, factory, body, cleanup)
    assert isinstance(failure, BaseExceptionGroup)
    assert failure.exceptions == (body, cleanup)
    if not isinstance(body, Exception) or not isinstance(cleanup, Exception):
        assert not isinstance(failure, Exception)


@pytest.mark.parametrize("factory", ["new_solver", "new_optimizer"])
@pytest.mark.parametrize("body_kind", [ValueError, KeyboardInterrupt, SystemExit])
def test_query_failure_with_successful_restoration_propagates_unchanged(monkeypatch, factory, body_kind):
    body = body_kind("owned query failure")
    assert managed_failure(monkeypatch, factory, body, None) is body


@pytest.mark.parametrize("factory", ["new_solver", "new_optimizer"])
@pytest.mark.parametrize("cleanup_kind", [RuntimeError, KeyboardInterrupt, SystemExit])
def test_restoration_failure_does_not_return_the_completed_query(monkeypatch, factory, cleanup_kind):
    cleanup = cleanup_kind("owned timeout restoration failure")
    assert managed_failure(monkeypatch, factory, None, cleanup) is cleanup


def test_invariant_second_regime_preserves_query_and_rollback_failures(monkeypatch):
    from core.audit import invariant_smt

    body = KeyboardInterrupt("owned nonnegative-query interruption")
    cleanup = SystemExit("owned nonnegative-scope rollback interruption")
    original_check = invariant_smt.check_solver
    solvers = []
    checks = []

    def pop():
        raise cleanup

    def factory(timeout):
        solver = session.new_solver(timeout)
        monkeypatch.setattr(solver, "pop", pop)
        solvers.append(solver)
        return solver

    def check(solver):
        checks.append(solver)
        if len(checks) == 2:
            raise body
        return original_check(solver)

    def action():
        return invariant_smt._check_one_site(
            z3, ("var", "length"), "<=", ("var", "size"),
            {"length", "size", "delta"}, 1, "length += delta;",
            "length", "+=", "delta", 5000,
        )

    monkeypatch.setattr(invariant_smt, "new_solver", factory)
    monkeypatch.setattr(invariant_smt, "check_solver", check)
    failure = capture_failure(action)
    assert len(solvers) == 1
    assert checks == [solvers[0], solvers[0]]
    assert isinstance(failure, BaseExceptionGroup)
    assert failure.exceptions == (body, cleanup)
