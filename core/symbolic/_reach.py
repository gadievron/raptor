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

from core.symbolic import _engine
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

    Hard-budget process isolation via
    :func:`core.symbolic._engine.dispatch_isolated`; when angr is
    unavailable the availability guard answers directly.
    """
    return _engine.dispatch_isolated(
        _find_reaching_input_impl,
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
    gate = _engine.availability_gate("find_reaching_input")
    if gate is not None:
        return gate

    binary_path, missing = _engine.check_binary(binary_path)
    if missing is not None:
        return missing

    t0 = time.monotonic()
    project, load_error = _engine.open_gated_project(
        binary_path, t0,
        install_hooks=_engine.size_concretization_hooks,
    )
    if load_error is not None:
        return load_error

    unmapped = _engine.check_mapped(project, target_address, t0)
    if unmapped is not None:
        return unmapped

    state = _engine.make_entry_state(project)
    simgr = project.factory.simulation_manager(state)

    deadline = t0 + timeout

    step = _engine.budget_step(deadline)
    try:
        with z3_call_budget(deadline):
            simgr.explore(
                find=target_address,
                avoid=avoid_addresses or [],
                num_find=1,
                step_func=step,
            )
    except Exception as exc:  # noqa: BLE001 — angr's exploration may raise
        return _engine.raised_result(
            exc, t0=t0, simgr=simgr,
            metadata={"target_address": target_address},
        )

    wall = time.monotonic() - t0
    states = _engine.count_states(simgr)

    if not simgr.found:
        return _engine.unfound_result(
            deadline=deadline, wall=wall, states=states,
            timeout_reason=f"timeout after {wall:.1f}s",
            no_path_reason="no path to target",
            metadata={"target_address": target_address},
            step=step,
        )

    found = simgr.found[0]
    concrete = _engine.dump_stdin_witness(
        found, max_input_bytes=max_input_bytes, wall=wall, states=states,
        metadata={"target_address": target_address},
        overcap_hint="; raise the cap to accept it",
    )
    if isinstance(concrete, SymbolicResult):
        return concrete

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
