"""Shared scaffolding for the five symbolic engines.

Extracted from ``_reach`` / ``_overflow`` / ``_constraints`` /
``_fmtstr`` / ``_heap_mismatch``: each repeated the same public-
wrapper isolation dispatch, impl-side availability re-gate,
binary/mapped-address prologue, entry-state construction, budget-
bounded step function, and failure-result plumbing. The ANALYTICAL
core of every engine — what it explores for, how it solves, what
evidence it extracts — stays in the engine module; this module owns
only the scaffolding, parameterized exactly where the engines
genuinely diverge (reason texts, metadata keys, hook installers,
stash-policy extensions).

Behavior contract: byte-equivalent with the pre-extraction engines.
Same reason strings, same result shapes, same availability semantics
(the gate answers in-process without spawning when angr is absent —
the impl's re-gate produces the descriptive unavailable result), and
the same isolation dispatch (impl module + function BY NAME into
:func:`core.symbolic._isolate.run_isolated`, kwargs verbatim, the
caller's timeout). The dispatch names come from the impl function
object itself (``__module__`` / ``__name__``), so the strings the
child imports can never drift from the code.

Trust contract: unchanged from the package docstring — targets are
attacker-supplied binaries, the heavy work runs in the isolated
child (:mod:`core.symbolic._isolate`), and every helper here runs
INSIDE that child except :func:`dispatch_isolated`, which is the
parent-side wrapper body.
"""
from __future__ import annotations

import time
from pathlib import Path
from typing import Any, Callable, Optional

from core.symbolic._project import _open_project
from core.symbolic._types import SymbolicResult

#: Active-stash ceiling shared by the exploration step functions —
#: a branch-per-byte target allocates heavyweight states freely
#: inside the timeout window otherwise (RAM bound, not a wall bound).
MAX_ACTIVE_STATES = 512


def dispatch_isolated(
    impl: Callable[..., SymbolicResult],
    kwargs: dict[str, Any],
    *,
    timeout: float,
) -> SymbolicResult:
    """Public-wrapper body: availability gate + isolation dispatch.

    The implementation runs in a spawned child with a hard kill at
    ``timeout`` plus a grace window: hostile targets can drive one
    native solver call past every cooperative bound (verified live),
    so the budget is enforced by process isolation, not cooperation.
    When angr is unavailable the availability guard answers directly
    (no child is spawned) — ``impl`` runs in-process and its own
    re-gate returns the descriptive unavailable result.
    """
    from core.symbolic._availability import angr_available
    from core.symbolic._isolate import run_isolated
    if not angr_available():
        return impl(**kwargs)
    return run_isolated(
        impl.__module__, impl.__name__, kwargs, timeout=timeout,
    )


def availability_gate(primitive: str) -> Optional[SymbolicResult]:
    """Impl-side re-gate. The child re-checks availability itself
    rather than trusting the parent's probe — ``import angr`` can
    fail in-child (e.g. under the symex sandbox) even when the
    parent's probe passed. Returns the unavailable result to hand
    back, or None when angr is importable."""
    from core.symbolic._availability import (
        angr_available, unavailable_result,
    )
    if not angr_available():
        return unavailable_result("angr", primitive)
    return None


def check_binary(binary_path: Path) -> tuple[Path, Optional[SymbolicResult]]:
    """Normalise ``binary_path`` and verify it is a file. Returns the
    normalised path plus the failure result to hand back (or None)."""
    binary_path = Path(binary_path)
    if not binary_path.is_file():
        return binary_path, SymbolicResult(
            succeeded=False,
            reason=f"binary not found: {binary_path}",
            wall_seconds=0.0,
        )
    return binary_path, None


def size_concretization_hooks(project: Any) -> None:
    """Hook installer for :func:`open_gated_project`: declared-length
    copies (symbolic size args) otherwise build per-byte conditional
    ASTs that wedge z3 at assert time — concretize adversarially (max
    satisfiable length) instead. Installed inside the isolated child:
    the per-process project cache never leaks hooks to other
    consumers."""
    from core.symbolic._concretize import install_adversarial_size_hooks
    install_adversarial_size_hooks(project)


def open_gated_project(
    binary_path: Path,
    t0: float,
    *,
    install_hooks: Optional[Callable[[Any], Any]] = None,
) -> tuple[Any, Optional[SymbolicResult]]:
    """Open the cached angr project and run the engine's hook
    installer (both inside one try — a hook-install failure reads as
    a load failure, exactly as before extraction). Returns
    ``(project, None)`` or ``(None, failure_result)``."""
    try:
        project = _open_project(binary_path)
        if install_hooks is not None:
            install_hooks(project)
    except Exception as exc:  # noqa: BLE001
        return None, SymbolicResult(
            succeeded=False,
            reason=f"angr load failed: {type(exc).__name__}: {exc}",
            wall_seconds=time.monotonic() - t0,
        )
    return project, None


def check_mapped(
    project: Any,
    addr: int,
    t0: float,
    *,
    addr_key: str = "target_address",
    reason: Optional[str] = None,
) -> Optional[SymbolicResult]:
    """Bounds check: the address must fall inside a mapped segment.
    Cheap sanity — an out-of-range target guarantees exploration
    failure. Returns the failure result to hand back, or None."""
    if is_mapped(project, addr):
        return None
    if reason is None:
        reason = (
            f"target 0x{addr:x} not in a mapped segment "
            "(check base address / PIE offset)"
        )
    return SymbolicResult(
        succeeded=False,
        reason=reason,
        wall_seconds=time.monotonic() - t0,
        metadata={addr_key: addr},
    )


def make_entry_state(project: Any) -> Any:
    """Entry state with symbolic stdin — the one shape every engine
    starts from. SimFileStream models stdin as a stream of symbolic
    bytes; callers who need a fixed-size read model would use SimFile
    instead. (Deferred angr import keeps module-load light for
    consumers that only touch the types.)"""
    import angr
    return project.factory.entry_state(
        stdin=angr.SimFileStream,
        add_options={angr.options.LAZY_SOLVES},
    )


class _BudgetStep:
    """Exploration ``step_func`` that records WHY it aborted.

    Deadline and active-cap aborts both flush the active stash, which
    downstream read as "explored fully" — but a cap abort is a
    state-explosion prune, and reporting it as a definitive "no path"
    hands refutation-grade evidence to consumers for an exploration
    that was cut off at ``max_active`` states. ``unfound_result``
    consults :attr:`cap_aborted` to report it honestly (parallel to
    the overflow engine's own "state explosion" reporting).
    """

    def __init__(
        self,
        deadline: float,
        *,
        max_active: int = MAX_ACTIVE_STATES,
        on_continue: Optional[Callable[[Any], Any]] = None,
    ) -> None:
        self.deadline = deadline
        self.max_active = max_active
        self.on_continue = on_continue
        self.cap_aborted = False

    def __call__(self, sg: Any) -> Any:
        if time.monotonic() >= self.deadline:
            return sg.move(from_stash="active", to_stash="deadended")
        if len(sg.active) > self.max_active:
            self.cap_aborted = True
            return sg.move(from_stash="active", to_stash="deadended")
        if self.on_continue is not None:
            return self.on_continue(sg)
        return sg


def budget_step(
    deadline: float,
    *,
    max_active: int = MAX_ACTIVE_STATES,
    on_continue: Optional[Callable[[Any], Any]] = None,
) -> "_BudgetStep":
    """Build the exploration ``step_func``: bail cleanly on deadline
    (angr polls between step batches, so we stop between states, not
    mid-state) and bound RAM via the active-stash ceiling. When the
    budget still has room, ``on_continue`` lets an engine append its
    own per-step work (e.g. the heap engine's mismatch scan). The
    returned object records a cap abort — pass it to
    :func:`unfound_result` so the abort is never reported as a
    definitive negative."""
    return _BudgetStep(
        deadline, max_active=max_active, on_continue=on_continue,
    )


def raised_result(
    exc: BaseException,
    *,
    t0: float,
    simgr: Any,
    metadata: dict[str, Any],
    verb: str = "explore",
) -> SymbolicResult:
    """Failure result for an exception escaping angr's exploration
    (``explore`` for the simgr.explore engines; ``step`` for the
    overflow engine's manual loop)."""
    return SymbolicResult(
        succeeded=False,
        reason=f"angr {verb} raised: {type(exc).__name__}: {exc}",
        wall_seconds=time.monotonic() - t0,
        states_explored=count_states(simgr),
        metadata=metadata,
    )


def unfound_result(
    *,
    deadline: float,
    wall: float,
    states: int,
    timeout_reason: str,
    no_path_reason: str,
    metadata: dict[str, Any],
    step: Optional["_BudgetStep"] = None,
) -> SymbolicResult:
    """Nothing-found result: distinguish "timed out with active
    states remaining", "aborted at the active-state cap", and
    "explored fully and found nothing". The engines supply their own
    reason texts for the first and last (the wording is part of the
    public surface); the cap abort is reported here so no engine can
    mint a pruned exploration as a definitive negative."""
    timed_out = time.monotonic() >= deadline
    if timed_out:
        reason = timeout_reason
    elif step is not None and step.cap_aborted:
        reason = (
            f"state explosion — exploration aborted at "
            f"{step.max_active} active states; not exhaustive"
        )
        metadata = {**metadata, "cap_aborted": True}
    else:
        reason = no_path_reason
    return SymbolicResult(
        succeeded=False,
        reason=reason,
        wall_seconds=wall,
        states_explored=states,
        metadata=metadata,
    )


def dump_stdin_witness(
    found: Any,
    *,
    max_input_bytes: int,
    wall: float,
    states: int,
    metadata: dict[str, Any],
    overcap_hint: str = "",
) -> bytes | SymbolicResult:
    """Concretise the found state's stdin (``posix.dumps(0)`` gives
    the full content the state consumed) under a fresh z3 budget.

    NEVER truncates: a shortened witness will not replay and a false
    success is the one thing a verification substrate must not emit —
    an over-cap witness is refused with its length in the metadata
    (``overcap_hint`` carries an engine's extra guidance text).
    Returns the stdin bytes, or the failure :class:`SymbolicResult`
    to hand back (callers isinstance-branch on the shape).
    """
    from core.symbolic._budget import z3_call_budget
    try:
        with z3_call_budget(time.monotonic() + 30.0):
            concrete = bytes(found.posix.dumps(0))
        if len(concrete) > max_input_bytes:
            return SymbolicResult(
                succeeded=False,
                reason=(
                    f"witness needs {len(concrete)} stdin bytes — over "
                    f"the max_input_bytes cap ({max_input_bytes})"
                    f"{overcap_hint}"
                ),
                wall_seconds=wall,
                states_explored=states,
                metadata={
                    **metadata,
                    "witness_length": len(concrete),
                },
            )
    except Exception as exc:  # noqa: BLE001 — solver can fail
        return SymbolicResult(
            succeeded=False,
            reason=f"solver failed to concretise: {type(exc).__name__}",
            wall_seconds=wall,
            states_explored=states,
            metadata=metadata,
        )
    return concrete


def is_mapped(project: Any, addr: int) -> bool:
    """Return True if ``addr`` falls inside one of the loader's mapped
    segments. Angr's ``project.loader.find_object_containing(addr)``
    returns None for unmapped addresses; use that as the check."""
    try:
        return project.loader.find_object_containing(addr) is not None
    except Exception:  # noqa: BLE001
        return False


def count_states(simgr: Any) -> int:
    """Sum states across all stashes as a diagnostic. simgr may
    have stashes we don't know about; use the ``all_states`` view."""
    try:
        return sum(1 for _ in simgr.stashes.values() for __ in _)
    except Exception:  # noqa: BLE001
        return 0
