"""Solver construction with a default timeout.

The harness caps solver queries at 5 s by default so a pathological
encoding from one finding can't stall an entire validation pass. Override
per-call via ``new_solver(timeout_ms=...)``.
"""
from __future__ import annotations

from contextlib import contextmanager
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


def _timeout_value(timeout_ms):
    if type(timeout_ms) is not int:
        raise ValueError("timeout_ms must be an integer")
    return min(_MAX_TIMEOUT_MS, max(1, timeout_ms))


def new_solver(timeout_ms: int = DEFAULT_TIMEOUT_MS) -> Any:
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
    s = z3.Solver()
    s.set("timeout", timeout_ms)
    return s


def new_optimizer(timeout_ms: int = DEFAULT_TIMEOUT_MS) -> Any:
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
    o = z3.Optimize()
    o.set("timeout", timeout_ms)
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
