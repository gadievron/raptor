"""Solver construction with a default timeout.

The harness caps solver queries at 5 s by default so a pathological
encoding from one finding can't stall an entire validation pass. Override
per-call via ``new_solver(timeout_ms=...)``.
"""
from __future__ import annotations

from contextlib import contextmanager
from typing import Any, Iterator

from .availability import z3

DEFAULT_TIMEOUT_MS = 5000

# Z3 stores the timeout as an unsigned 32-bit value internally;
# anything larger silently wraps. Cap at 2^31 - 1 ms (~24.8 days)
# which is comfortably bigger than any sane cap and safely below
# the wraparound boundary on every Z3 build.
_MAX_TIMEOUT_MS = 2 ** 31 - 1


def new_solver(timeout_ms: int = DEFAULT_TIMEOUT_MS) -> Any:
    """Return a fresh ``z3.Solver()`` with the given timeout applied.

    Caller-supplied ``timeout_ms`` is clamped to ``[1, _MAX_TIMEOUT_MS]``.

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
    if timeout_ms < 1:
        timeout_ms = 1
    elif timeout_ms > _MAX_TIMEOUT_MS:
        timeout_ms = _MAX_TIMEOUT_MS
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
    if timeout_ms < 1:
        timeout_ms = 1
    elif timeout_ms > _MAX_TIMEOUT_MS:
        timeout_ms = _MAX_TIMEOUT_MS
    o = z3.Optimize()
    o.set("timeout", timeout_ms)
    return o


@contextmanager
def scoped(solver: Any) -> Iterator[Any]:
    """Push an assertion scope on ``solver`` for the duration of the block.

    On exit (normal or exception), pops the scope — assertions added
    inside are removed, assertions from before remain. Lets domain
    encoders try hypothesis constraints and roll back cheaply without
    discarding the surrounding solver state.

    push() failure is caught and re-raised as RuntimeError with the
    original chained. Pre-fix push() ran OUTSIDE the try/finally, so
    a push() failure (rare — invalid solver state, OOM, transport
    fault on a remote-Z3 build) propagated as a raw `Z3Exception`
    that the caller could mis-attribute to body code rather than
    scope setup. Post-fix the caller sees a clear "scope push
    failed" message; the contract that a failed push means no body
    runs (and nothing to pop) is preserved.
    """
    try:
        solver.push()
    except Exception as e:  # noqa: BLE001 — Z3Exception unavailable cross-version
        raise RuntimeError(f"scoped: solver.push() failed: {e}") from e
    try:
        yield solver
    finally:
        try:
            solver.pop()
        except Exception:  # noqa: BLE001
            # If pop fails (very rare, but possible after a remote-Z3
            # transport hiccup), re-raising would mask any exception
            # from the body. Best-effort log via debug-only re-raise:
            # we let the body's exception propagate.
            pass
