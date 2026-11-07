"""Solver construction with a default timeout.

The harness caps solver queries at 5 s by default so a pathological
encoding from one finding can't stall an entire validation pass. Override
per-call via ``new_solver(timeout_ms=...)``.
"""
from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from time import monotonic
from typing import Any, TYPE_CHECKING

from .availability import z3

if TYPE_CHECKING:
    from collections.abc import Iterator

DEFAULT_TIMEOUT_MS = 5000

# Z3 stores the timeout as an unsigned 32-bit value internally;
# anything larger silently wraps. Cap at 2^31 - 1 ms (~24.8 days)
# which is comfortably bigger than any sane cap and safely below
# the wraparound boundary on every Z3 build.
_MAX_TIMEOUT_MS = 2 ** 31 - 1


_QUERY_DEADLINE: ContextVar[float | None] = ContextVar("smt_query_deadline", default=None)


@contextmanager
def query_budget(timeout_ms: int) -> Iterator[float]:
    """Share a soft query budget across path/verb checks and their subqueries.

    Time spent parsing or between queries also consumes the budget. Nested
    scopes cannot extend an outer deadline. This is not a process wall-time
    limit: native solver timeouts are cooperative. Use check_solver with
    factory-created solvers; direct native check() calls are outside it.
    Yields the effective monotonic deadline for same-host worker handoff;
    process startup must consume the budget rather than restart it.
    """
    if type(timeout_ms) is not int or timeout_ms < 0:
        raise ValueError("query budget must be a nonnegative integer in milliseconds")
    deadline = monotonic() + min(timeout_ms, _MAX_TIMEOUT_MS) / 1000
    outer = _QUERY_DEADLINE.get()
    deadline = min(deadline, outer) if outer is not None else deadline
    token = _QUERY_DEADLINE.set(deadline)
    try:
        yield deadline
    finally:
        _QUERY_DEADLINE.reset(token)


def check_solver(solver: Any) -> Any:
    """Check once, capping the native query by its shared remaining budget.

    Expiry returns unknown without consulting stale native query state.
    Preserve the factory's per-query cap and restore it after the query.
    Native models/cores survive timeout-parameter changes. A restoration
    failure propagates instead of presenting a cleanly completed query.
    """
    deadline = _QUERY_DEADLINE.get()
    if deadline is None:
        if getattr(solver, "_raptor_budget_exhausted", False) is True:
            solver._raptor_budget_exhausted = False
        return solver.check()
    timeout = getattr(solver, "_raptor_timeout_ms", None)
    if type(timeout) is not int or timeout <= 0:
        raise ValueError("budgeted checks require a core SMT factory solver")
    remaining = int((deadline - monotonic()) * 1000)
    solver._raptor_budget_exhausted = remaining <= 0
    if remaining <= 0:
        return z3.unknown
    solver.set("timeout", min(timeout, remaining))
    try:
        return solver.check()
    finally:
        solver.set("timeout", timeout)


def solver_reason_unknown(solver: Any) -> str:
    """Reason for the last managed check, including skipped expired queries."""
    if getattr(solver, "_raptor_budget_exhausted", False) is True:
        return "shared query budget exhausted (timeout)"
    return solver.reason_unknown()


def _timeout_value(timeout_ms):
    if type(timeout_ms) is not int:
        raise ValueError("timeout_ms must be an integer")
    return min(_MAX_TIMEOUT_MS, max(1, timeout_ms))


def new_solver(timeout_ms: int = DEFAULT_TIMEOUT_MS, *, ctx: Any = None) -> Any:
    """Return a fresh ``z3.Solver()`` with the given timeout applied.

    Caller-supplied ``timeout_ms`` must be an integer and is clamped to
    ``[1, _MAX_TIMEOUT_MS]``.

    Pre-fix:
      * `timeout_ms=0` was forwarded verbatim. Z3 interprets `timeout=0`
        as "no timeout" — exactly the OPPOSITE of what a caller passing
        0 (intent: "fail immediately") expects. A zero-timeout query
        then ran to completion, blowing the harness's 5s overall budget
        on a single pathological encoding.
      * Negative values: Z3 silently coerces via unsigned cast so
        `timeout_ms=-1` became 4294967295 (~49 days) — effectively
        no timeout, same harm.
      * Values > 2^32 ms: wrap around to small numbers (4_294_967_300
        becomes 4 ms).

    Clamp to a sensible range so each of those pathological inputs
    becomes a usable per-call timeout.
    """
    timeout_ms = _timeout_value(timeout_ms)
    if ctx is not None and (z3 is None or not isinstance(ctx, z3.Context)):
        raise ValueError("ctx must be a Z3 context or None")
    s = z3.Solver() if ctx is None else z3.Solver(ctx=ctx)
    s.set("timeout", timeout_ms)
    s._raptor_timeout_ms = timeout_ms
    return s


def new_optimizer(timeout_ms: int = DEFAULT_TIMEOUT_MS, *, ctx: Any = None) -> Any:
    """Return a fresh ``z3.Optimize()`` with the given timeout applied.

    Same clamping behaviour as :func:`new_solver`.  Use when the caller
    wants to drive the witness toward a maximal or minimal value of some
    variable (typically to produce an *exploit* witness rather than the
    trivial smallest-model assignment that ``z3.Solver`` returns by
    default).  Add objectives via ``opt.maximize(var)`` /
    ``opt.minimize(var)`` after construction.

    ``z3.Optimize`` shares the ``add``/``check``/``model``/``push``/
    ``pop``/``assert_and_track``/``unsat_core`` interface with
    ``z3.Solver`` so existing helpers (the explain.py unsat-core
    tracker, the scoped context-manager, the witness formatter) all
    work without modification — verified empirically on the Z3 builds
    we ship.
    """
    timeout_ms = _timeout_value(timeout_ms)
    if ctx is not None and (z3 is None or not isinstance(ctx, z3.Context)):
        raise ValueError("ctx must be a Z3 context or None")
    o = z3.Optimize() if ctx is None else z3.Optimize(ctx=ctx)
    o.set("timeout", timeout_ms)
    o._raptor_timeout_ms = timeout_ms
    return o


def _pop_scope(solver):
    try:
        solver.pop()
    except Exception as exc:
        raise RuntimeError("scoped: solver.pop() failed; solver state was not restored") from exc


@contextmanager
def scoped(solver: Any) -> Iterator[Any]:
    """Push a temporary assertion scope and require successful rollback.

    Failed setup never executes the body. Failed cleanup raises an
    integrity error: callers must not continue assuming temporary facts
    were removed. If both body and cleanup fail, preserve both failures
    in an exception group, including cancellation/control-flow exceptions.
    """
    try:
        solver.push()
    except Exception as exc:
        raise RuntimeError(f"scoped: solver.push() failed: {exc}") from exc
    try:
        yield solver
    except BaseException as body_error:
        try:
            _pop_scope(solver)
        except RuntimeError as cleanup_error:
            raise BaseExceptionGroup("scoped: body and rollback both failed", [body_error, cleanup_error]) from None
        raise
    else:
        _pop_scope(solver)
