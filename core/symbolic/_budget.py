"""Solver budget enforcement for the symbolic substrate.

The primitives' wall-clock deadlines are checked between exploration
steps — which bounds nothing when a SINGLE solver call runs long. A
ten-line target whose branch guard encodes a hard SMT instance (e.g.
an UNSAT primality-flavoured modulus check) makes one ``dumps()`` or
``satisfiable()`` call sit inside native z3 indefinitely, deferring
even SIGTERM. claripy's per-frontend ``timeout`` does not reach that
hot path in the pinned version (verified live), so the working lever
is z3's process-global ``timeout`` parameter.

:func:`z3_call_budget` sets it for the duration of a primitive call
and restores the "no timeout" default after. Scope caveat: the
parameter is process-global, but z3 treats globals as DEFAULTS —
solvers that set their own timeout (``core/smt_solver`` constructs
every solver via ``new_solver(timeout_ms=...)``) override it and are
unaffected. Only same-process z3 users relying on the global default
see the tightened ceiling while a primitive runs. Consumers that
analyse hostile binaries at scale should additionally isolate the
whole analysis in a subprocess/sandbox (see the package docstring's
trust contract).

With the budget applied, a primitive's total wall time is bounded by
(deadline between steps) + (one z3 timeout) rather than by nothing.
"""
from __future__ import annotations

import contextlib
import time

#: z3's "no timeout" sentinel (uint32 max) — what we restore when the
#: previous value cannot be read.
_Z3_NO_TIMEOUT = 4294967295


@contextlib.contextmanager
def z3_call_budget(deadline: float):
    """Cap every z3 call at the time remaining until *deadline*.

    Best-effort: when z3 is absent (angr not installed) this is a
    no-op — callers are already availability-gated. A floor of one
    second keeps a nearly-expired deadline from turning every solve
    into an instant unknown while the between-steps check is about
    to end the loop anyway.
    """
    try:
        import z3
    except ImportError:
        yield
        return
    remaining_ms = max(1000, int((deadline - time.monotonic()) * 1000))
    z3.set_param("timeout", remaining_ms)
    try:
        yield
    finally:
        z3.set_param("timeout", _Z3_NO_TIMEOUT)
