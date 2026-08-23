"""Hard-budget process isolation for symbolic primitives.

Why this exists: a hostile binary can steer one claripy/z3 call into
work that ignores every cooperative bound we set — the wall-clock
deadline is only polled between exploration steps, claripy's
per-frontend timeout never reaches its backend solver in the pinned
version, and the z3 global parameter proved unreliable once the
backend context pre-exists (all verified live; the failing call sits
in native ``Z3_solver_check_assumptions``, where even SIGTERM is
deferred). The only enforcement that cannot be argued with is a
separate process and SIGKILL.

Every public primitive therefore runs its implementation in a
spawned child; the parent waits until ``timeout`` plus a grace
window, then escalates terminate → kill and returns an honest
timeout :class:`SymbolicResult`. Cost: a process spawn + angr import
per call (seconds) and no cross-call project cache — acceptable for
a verification substrate whose alternative failure mode is an
unkillable analysis thread. The in-child z3 budget (``_budget``)
still applies as the soft layer so well-behaved solves end early
with precise diagnostics; isolation is the backstop.

The child receives (module, function, kwargs) by name and returns
the primitive's result via a pipe. Spawn (not fork): angr's native
state does not survive forks reliably, and spawn gives the child a
clean interpreter.
"""
from __future__ import annotations

import importlib
import multiprocessing as mp
import time
from typing import Any

from core.symbolic._types import SymbolicResult

#: Extra seconds past the caller's timeout before terminate/kill.
#: Covers child interpreter start + angr import (~3-5s measured) +
#: result pickling.
GRACE_SECONDS = 15.0

#: terminate → kill escalation gap.
_KILL_GRACE_SECONDS = 5.0


def _child_entry(conn, module_name: str, func_name: str, kwargs: dict) -> None:
    """Child-side runner. Everything heavyweight imports here."""
    import logging

    # angr logs an ERROR at import when optional acceleration is
    # missing; that is operator noise, not a result channel.
    for name in ("angr", "claripy", "cle", "pyvex"):
        logging.getLogger(name).setLevel(logging.CRITICAL)
    try:
        module = importlib.import_module(module_name)
        result = getattr(module, func_name)(**kwargs)
        conn.send(result)
    except BaseException as exc:  # noqa: BLE001 — one channel out
        try:
            conn.send(SymbolicResult(
                succeeded=False,
                reason=f"primitive raised: {type(exc).__name__}: {exc}",
                wall_seconds=0.0,
                states_explored=0,
                metadata={},
            ))
        except Exception:  # noqa: BLE001 — pipe gone; parent times out
            pass
    finally:
        conn.close()


def run_isolated(
    module_name: str,
    func_name: str,
    kwargs: dict[str, Any],
    *,
    timeout: float,
) -> SymbolicResult:
    """Run ``module_name.func_name(**kwargs)`` in a spawned child with
    a hard kill at ``timeout + GRACE_SECONDS``."""
    t0 = time.monotonic()
    ctx = mp.get_context("spawn")
    parent_conn, child_conn = ctx.Pipe(duplex=False)
    proc = ctx.Process(
        target=_child_entry,
        args=(child_conn, module_name, func_name, kwargs),
        daemon=True,
    )
    proc.start()
    child_conn.close()

    budget = timeout + GRACE_SECONDS
    result: SymbolicResult | None = None
    if parent_conn.poll(budget):
        try:
            result = parent_conn.recv()
        except (EOFError, OSError):
            result = None
    parent_conn.close()

    proc.join(timeout=0.5)
    if proc.is_alive():
        proc.terminate()
        proc.join(timeout=_KILL_GRACE_SECONDS)
        if proc.is_alive():
            proc.kill()
            proc.join(timeout=_KILL_GRACE_SECONDS)

    if result is not None:
        return result
    return SymbolicResult(
        succeeded=False,
        reason=(
            f"hard-killed after exceeding the {timeout:.0f}s budget "
            f"(+{GRACE_SECONDS:.0f}s grace) — solver work ignored "
            "every cooperative bound (hostile or pathological target)"
        ),
        wall_seconds=time.monotonic() - t0,
        states_explored=0,
        metadata={"isolated": True, "killed": True},
    )
