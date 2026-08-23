"""Reachability primitive: given a binary + target address, find a
concrete stdin input that drives the target from entry to that
address.

Uses angr's default exploration with a symbolic stdin. Bounded by a
caller-supplied timeout — angr's exploration can be expensive on
larger targets, so this is a hard budget check between steps.

Returns a :class:`SymbolicResult`. On success, ``concrete_input``
is the stdin bytes that reach the target. On failure, ``reason``
describes what went wrong (timeout, no path, unreachable target).

Failure modes deliberately surfaced separately (rather than raising)
so LLM consumers can reason over the result shape without try/except
boilerplate.
"""
from __future__ import annotations

import time
from pathlib import Path
from typing import Optional

from core.symbolic._project import _open_project
from core.symbolic._budget import z3_call_budget
from core.symbolic._types import SymbolicResult

_DEFAULT_TIMEOUT_SECONDS = 30.0
_DEFAULT_MAX_INPUT_BYTES = 4096


def find_reaching_input(
    binary_path: Path,
    target_address: int,
    *,
    timeout: float = _DEFAULT_TIMEOUT_SECONDS,
    max_input_bytes: int = _DEFAULT_MAX_INPUT_BYTES,
    avoid_addresses: Optional[list[int]] = None,
) -> SymbolicResult:
    """Isolated entry point — semantics in :func:`_find_reaching_input_impl`.

    The implementation runs in a spawned child with a hard kill at
    ``timeout`` plus a grace window: hostile targets can drive one
    native solver call past every cooperative bound (verified live),
    so the budget is enforced by process isolation, not cooperation.
    When angr is unavailable the availability guard answers directly
    (no child is spawned).
    """
    from core.symbolic._availability import angr_available
    from core.symbolic._isolate import run_isolated
    if not angr_available():
        return _find_reaching_input_impl(
            binary_path, target_address, timeout=timeout,
            max_input_bytes=max_input_bytes,
            avoid_addresses=avoid_addresses)
    return run_isolated(
        "core.symbolic._reach", "_find_reaching_input_impl",
        {"binary_path": binary_path, "target_address": target_address,
         "timeout": timeout, "max_input_bytes": max_input_bytes,
         "avoid_addresses": avoid_addresses},
        timeout=timeout,
    )


def _find_reaching_input_impl(
    binary_path: Path,
    target_address: int,
    *,
    timeout: float = _DEFAULT_TIMEOUT_SECONDS,
    max_input_bytes: int = _DEFAULT_MAX_INPUT_BYTES,
    avoid_addresses: Optional[list[int]] = None,
) -> SymbolicResult:
    """Symex from binary entry to ``target_address`` with symbolic stdin.

    Args:
        binary_path: ELF to symbolic-execute.
        target_address: rebased address the state must reach. On PIE
            binaries the caller is responsible for adding the load
            base (or resolving via
            :func:`~core.symbolic._project.load_binary` symbols).
        timeout: hard wall-clock budget in seconds. Checked between
            steps; actual wall may exceed by one step's cost.
        max_input_bytes: cap on the symbolic stdin size angr models.
            Larger caps let angr explore more input-shape variation
            at the cost of state explosion.
        avoid_addresses: optional list of addresses to prune states
            through — e.g. an early-exit / abort path.

    Returns:
        SymbolicResult. ``succeeded=True`` + ``concrete_input`` on
        find; ``succeeded=False`` with ``reason`` describing the
        failure mode on miss / timeout / error.
    """
    from core.symbolic._availability import (
        angr_available, unavailable_result,
    )
    if not angr_available():
        return unavailable_result("angr", "find_reaching_input")

    binary_path = Path(binary_path)
    if not binary_path.is_file():
        return SymbolicResult(
            succeeded=False,
            reason=f"binary not found: {binary_path}",
            wall_seconds=0.0,
        )

    t0 = time.monotonic()
    try:
        project = _open_project(binary_path)
    except Exception as exc:  # noqa: BLE001
        return SymbolicResult(
            succeeded=False,
            reason=f"angr load failed: {type(exc).__name__}: {exc}",
            wall_seconds=time.monotonic() - t0,
        )

    # Bounds check: target must fall inside a mapped segment. Cheap
    # sanity — an out-of-range target guarantees exploration failure.
    if not _is_mapped(project, target_address):
        return SymbolicResult(
            succeeded=False,
            reason=(
                f"target 0x{target_address:x} not in a mapped segment "
                "(check base address / PIE offset)"
            ),
            wall_seconds=time.monotonic() - t0,
            metadata={"target_address": target_address},
        )

    # Deferred import to keep the module-load path light for consumers
    # that only touch the types.
    import angr

    # SimFileStream models stdin as a stream of symbolic bytes. Callers
    # who need a fixed-size read model would use SimFile instead.
    state = project.factory.entry_state(
        stdin=angr.SimFileStream,
        add_options={angr.options.LAZY_SOLVES},
    )

    simgr = project.factory.simulation_manager(state)

    # Explore with a timeout callback — angr's ``explore`` polls this
    # between step batches so we bail cleanly rather than mid-state.
    deadline = t0 + timeout

    def _stop_predicate(_simgr) -> bool:
        return time.monotonic() >= deadline

    def _step(sg):
        if _stop_predicate(sg):
            return sg.move(from_stash="active", to_stash="deadended")
        if len(sg.active) > 512:
            # RAM bound (mirrors _overflow): a branch-per-byte target
            # allocates heavyweight states freely inside the timeout
            # window otherwise.
            return sg.move(from_stash="active", to_stash="deadended")
        return sg

    try:
        with z3_call_budget(deadline):
            simgr.explore(
                find=target_address,
                avoid=avoid_addresses or [],
                num_find=1,
                step_func=_step,
            )
    except Exception as exc:  # noqa: BLE001 — angr's exploration may raise
        return SymbolicResult(
            succeeded=False,
            reason=f"angr explore raised: {type(exc).__name__}: {exc}",
            wall_seconds=time.monotonic() - t0,
            states_explored=_count_states(simgr),
            metadata={"target_address": target_address},
        )

    wall = time.monotonic() - t0
    states = _count_states(simgr)

    if not simgr.found:
        # Distinguish "timed out with active states remaining" from
        # "explored fully and found nothing".
        timed_out = time.monotonic() >= deadline
        return SymbolicResult(
            succeeded=False,
            reason=(
                f"timeout after {wall:.1f}s"
                if timed_out
                else "no path to target"
            ),
            wall_seconds=wall,
            states_explored=states,
            metadata={"target_address": target_address},
        )

    found = simgr.found[0]
    # Extract concrete stdin bytes. ``posix.dumps(0)`` gives the
    # full stdin content the state consumed.
    try:
        with z3_call_budget(time.monotonic() + 30.0):
            concrete = bytes(found.posix.dumps(0))
        if len(concrete) > max_input_bytes:
            # NEVER truncate: a shortened witness will not replay and
            # a false success is the one thing a verification
            # substrate must not emit.
            return SymbolicResult(
                succeeded=False,
                reason=(
                    f"witness needs {len(concrete)} stdin bytes — over "
                    f"the max_input_bytes cap ({max_input_bytes}); "
                    f"raise the cap to accept it"
                ),
                wall_seconds=wall,
                states_explored=states,
                metadata={
                    "target_address": target_address,
                    "witness_length": len(concrete),
                },
            )
    except Exception as exc:  # noqa: BLE001 — solver can fail
        return SymbolicResult(
            succeeded=False,
            reason=f"solver failed to concretise: {type(exc).__name__}",
            wall_seconds=wall,
            states_explored=states,
            metadata={"target_address": target_address},
        )

    return SymbolicResult(
        succeeded=True,
        reason="found reaching input",
        wall_seconds=wall,
        concrete_input=concrete,
        states_explored=states,
        metadata={
            "target_address": target_address,
            "input_length": len(concrete),
        },
    )


def _is_mapped(project, addr: int) -> bool:
    """Return True if ``addr`` falls inside one of the loader's mapped
    segments. Angr's ``project.loader.find_object_containing(addr)``
    returns None for unmapped addresses; use that as the check."""
    try:
        return project.loader.find_object_containing(addr) is not None
    except Exception:  # noqa: BLE001
        return False


def _count_states(simgr) -> int:
    """Sum states across all stashes as a diagnostic. simgr may
    have stashes we don't know about; use the ``all_states`` view."""
    try:
        return sum(1 for _ in simgr.stashes.values() for __ in _)
    except Exception:  # noqa: BLE001
        return 0
