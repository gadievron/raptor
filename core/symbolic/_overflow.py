"""Overflow-witness primitive: verify control-flow-hijack
hypotheses via angr's unconstrained-state stash + post-hoc
PC-constraint solving.

Why this exists (the gap :func:`find_reaching_input` documented):
angr's default ``explore(find=target)`` looks for concrete PC
transitions. When a target function returns via ``ret`` after a
symbolic overflow, PC becomes symbolic — angr moves that state to
the ``unconstrained`` stash and drops it from exploration. That
state IS the memory-safety violation the hypothesis claims (input
reaches the program counter), but the default finder never
enumerates it.

The unlock: opt into ``save_unconstrained=True`` on the simulation
manager, then post-process the ``unconstrained`` stash: for each
state, add the constraint ``PC == target_address`` and ask the
solver if it's satisfiable. When yes, extract concrete stdin bytes
and return them — a concrete witness that input controls PC and
can steer it to the hypothesised target.

Also honours a max_input_bytes cap on the symbolic stdin buffer
(default 4096 bytes) so the symbolic buffer is large enough to
overflow a typical stack frame but not so large it explodes state.

Consumers get a :class:`SymbolicResult` with:
  * succeeded=True + concrete_input on find
  * succeeded=False + descriptive reason on timeout / no PC-
    constraint-solve / target unmapped
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


def find_overflow_reaching_input(
    binary_path: Path,
    target_address: int,
    *,
    timeout: float = _DEFAULT_TIMEOUT_SECONDS,
    max_input_bytes: int = _DEFAULT_MAX_INPUT_BYTES,
    register_constraints: Optional[dict] = None,
) -> SymbolicResult:
    """Isolated entry point — semantics in
    :func:`_find_overflow_reaching_input_impl`.

    Hard-budget process isolation; see :mod:`core.symbolic._isolate`.
    When angr is unavailable the availability guard answers directly.
    """
    from core.symbolic._availability import angr_available
    from core.symbolic._isolate import run_isolated
    if not angr_available():
        return _find_overflow_reaching_input_impl(
            binary_path, target_address, timeout=timeout,
            max_input_bytes=max_input_bytes,
            register_constraints=register_constraints)
    return run_isolated(
        "core.symbolic._overflow", "_find_overflow_reaching_input_impl",
        {"binary_path": binary_path, "target_address": target_address,
         "timeout": timeout, "max_input_bytes": max_input_bytes,
         "register_constraints": register_constraints},
        timeout=timeout,
    )


def _find_overflow_reaching_input_impl(
    binary_path: Path,
    target_address: int,
    *,
    timeout: float = _DEFAULT_TIMEOUT_SECONDS,
    max_input_bytes: int = _DEFAULT_MAX_INPUT_BYTES,
    register_constraints: Optional[dict] = None,
) -> SymbolicResult:
    """Verify an overflow-to-PC hypothesis via unconstrained-state
    analysis.

    Given a binary + a hypothesised control-flow target address,
    symbolic-execute from entry with symbolic stdin, capture states
    whose PC becomes symbolic (the overflow taking effect), and
    solve for stdin bytes that constrain PC to ``target_address``.
    A success is verification-grade evidence for a CWE-121/787-class
    finding: concrete input demonstrating input control of PC.

    Args:
        binary_path: ELF to symbolic-execute.
        target_address: rebased address the hypothesis says PC can
            equal. For non-PIE, this is a static address (nm-visible).
            For PIE, add the load base.
        timeout: hard wall-clock budget in seconds. Bounded via
            explore's ``n`` step limit as a coarse proxy — angr
            checks budget between steps, actual wall may exceed by
            a step's cost.
        max_input_bytes: symbolic stdin cap. Larger caps allow angr
            to overflow bigger buffers at the cost of state
            explosion.
        register_constraints: optional ``{reg_name: value}`` map to
            constrain simultaneously with ``pc == target_address``.
            Handles the arg-checked pattern: the target checks an
            argument register (``rdi=0xc0ffee`` on x86-64 SysV)
            before printing the flag; bare PC-hijack doesn't satisfy
            the check, so replay fails silently. Constraining the
            arg register alongside PC produces a stdin that ACTUALLY
            reaches the flag path, not just the win() prologue.
            Register names are angr archinfo names (``rdi``, ``rsi``,
            ``rdx``, ``rcx``, ``r8``, ``r9`` on amd64;
            ``x0``-``x7`` on aarch64). Values are unsigned integers;
            the width is derived from ``arch.registers[reg]``.

    Returns:
        :class:`SymbolicResult`. ``succeeded=True`` with
        ``concrete_input`` on find; ``succeeded=False`` with
        descriptive reason on timeout / no unconstrained state /
        unsolvable target address.
    """
    from core.symbolic._availability import (
        angr_available, unavailable_result,
    )
    if not angr_available():
        return unavailable_result("angr", "find_overflow_reaching_input")

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

    import angr

    state = project.factory.entry_state(
        stdin=angr.SimFileStream,
        add_options={
            angr.options.LAZY_SOLVES,
        },
    )

    # save_unconstrained=True is the key: without it, angr silently
    # drops states with symbolic PC (which is precisely the condition
    # the hypothesis predicts). With it, those states land in a
    # dedicated stash we post-process below.
    simgr = project.factory.simulation_manager(
        state, save_unconstrained=True,
    )

    deadline = t0 + timeout
    steps = 0
    tried_unconstrained = 0
    overcap_lengths: list = []
    try:
      with z3_call_budget(deadline):
        while time.monotonic() < deadline:
            if simgr.active:
                simgr.step()
                steps += 1
            elif tried_unconstrained >= len(simgr.unconstrained):
                # Exploration exhausted AND every unconstrained state
                # already solver-checked: no future state can appear,
                # so re-solving the same stash until the deadline is
                # pure spin. Decide now.
                return SymbolicResult(
                    succeeded=False,
                    reason=(
                        (
                            f"witness needs {max(overcap_lengths)} "
                            f"stdin bytes — over the max_input_bytes "
                            f"cap ({max_input_bytes}); raise the cap"
                        )
                        if overcap_lengths else
                        (
                            "exhausted — "
                            f"{len(simgr.unconstrained)} unconstrained "
                            "state(s), none satisfy pc == target under "
                            "the given constraints (unsatisfiable)"
                        )
                        if simgr.unconstrained else
                        "exhausted — no unconstrained state reached "
                        "(no overflow-to-PC path found)"
                    ),
                    wall_seconds=time.monotonic() - t0,
                    states_explored=_count_states(simgr),
                    metadata={
                        "target_address": target_address,
                        "steps": steps,
                    },
                )
            # Early exit: if we've collected an unconstrained state
            # AND can constrain PC to target, we're done. Solve
            # inside the loop so we don't waste explore budget
            # after the first viable state.
            solved = _try_solve_pc(
                simgr.unconstrained, target_address, max_input_bytes,
                register_constraints=register_constraints,
                overcap_lengths=overcap_lengths,
            )
            tried_unconstrained = len(simgr.unconstrained)
            if solved is not None:
                return SymbolicResult(
                    succeeded=True,
                    reason="found reaching input via unconstrained-PC solve",
                    wall_seconds=time.monotonic() - t0,
                    concrete_input=solved,
                    states_explored=_count_states(simgr),
                    metadata={
                        "target_address": target_address,
                        "input_length": len(solved),
                        "steps": steps,
                        "stash": "unconstrained",
                    },
                )
            # Defensive cap: some pathological targets branch every
            # step without ever hitting a ret; the deadline check
            # above bounds wall clock but this bounds RAM.
            if len(simgr.active) > 512:
                exploded = len(simgr.active)
                simgr.stash(
                    filter_func=lambda s: True,
                    from_stash="active",
                    to_stash="deadended",
                )
                return SymbolicResult(
                    succeeded=False,
                    reason=(
                        f"state explosion — {exploded} active "
                        f"states after {steps} steps; aborting"
                    ),
                    wall_seconds=time.monotonic() - t0,
                    states_explored=_count_states(simgr),
                    metadata={
                        "target_address": target_address,
                        "steps": steps,
                    },
                )
    except Exception as exc:  # noqa: BLE001
        return SymbolicResult(
            succeeded=False,
            reason=f"angr step raised: {type(exc).__name__}: {exc}",
            wall_seconds=time.monotonic() - t0,
            states_explored=_count_states(simgr),
            metadata={"target_address": target_address, "steps": steps},
        )

    wall = time.monotonic() - t0
    states = _count_states(simgr)
    timed_out = time.monotonic() >= deadline

    # Final attempt on any lingering unconstrained states.
    solved = _try_solve_pc(
        simgr.unconstrained, target_address, max_input_bytes,
        register_constraints=register_constraints,
    )
    if solved is not None:
        return SymbolicResult(
            succeeded=True,
            reason="found reaching input via post-loop unconstrained solve",
            wall_seconds=wall,
            concrete_input=solved,
            states_explored=states,
            metadata={
                "target_address": target_address,
                "input_length": len(solved),
                "steps": steps,
                "stash": "unconstrained",
            },
        )

    reason = (
        f"timeout after {wall:.1f}s with {len(simgr.unconstrained)} "
        f"unconstrained states (none satisfy pc == target)"
        if timed_out else
        f"exhausted exploration ({len(simgr.unconstrained)} unconstrained "
        "states, none satisfy pc == target)"
    )
    return SymbolicResult(
        succeeded=False,
        reason=reason,
        wall_seconds=wall,
        states_explored=states,
        metadata={
            "target_address": target_address,
            "steps": steps,
            "unconstrained_state_count": len(simgr.unconstrained),
        },
    )


def _try_solve_pc(
    unconstrained_states,
    target_address: int,
    max_input_bytes: int,
    *,
    register_constraints: Optional[dict] = None,
    overcap_lengths: list | None = None,
) -> Optional[bytes]:
    """Try each unconstrained state: constrain PC to target_address
    (plus any register_constraints), check satisfiability, extract
    stdin bytes on success.

    Returns the first satisfying state's stdin bytes, or None when
    no state can be constrained to the target under all constraints.
    """
    for state in unconstrained_states:
        # Copy so failed attempts don't pollute state constraints —
        # otherwise a state that fails one target might succeed a
        # later attempt but has a stale contradictory constraint.
        candidate = state.copy()
        try:
            candidate.solver.add(candidate.regs.pc == target_address)
        except Exception:  # noqa: BLE001
            # Some claripy edge cases (concrete-PC states, or PC
            # not a bitvector) raise here — skip and continue.
            continue
        if register_constraints:
            reg_ok = True
            for reg_name, value in register_constraints.items():
                try:
                    reg = getattr(candidate.regs, reg_name)
                    candidate.solver.add(reg == value)
                except Exception:  # noqa: BLE001
                    # Unknown register name for this arch, or
                    # register can't be constrained (concrete /
                    # not-tracked) — skip this state, try the next.
                    reg_ok = False
                    break
            if not reg_ok:
                continue
        try:
            if not candidate.satisfiable():
                continue
        except Exception:  # noqa: BLE001
            continue
        try:
            data = candidate.posix.dumps(0)
        except Exception:  # noqa: BLE001
            continue
        if len(data) > max_input_bytes:
            # NEVER truncate: a shortened witness will not replay.
            # Skip this candidate; an over-cap solve is a failure,
            # not a success with silently broken evidence.
            if overcap_lengths is not None:
                overcap_lengths.append(len(data))
            continue
        return bytes(data)
    return None


def _is_mapped(project, addr: int) -> bool:
    try:
        return project.loader.find_object_containing(addr) is not None
    except Exception:  # noqa: BLE001
        return False


def _count_states(simgr) -> int:
    try:
        return sum(1 for _ in simgr.stashes.values() for __ in _)
    except Exception:  # noqa: BLE001
        return 0
