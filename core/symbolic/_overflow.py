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

from core.symbolic import _engine
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

    Hard-budget process isolation via
    :func:`core.symbolic._engine.dispatch_isolated`; when angr is
    unavailable the availability guard answers directly.
    """
    return _engine.dispatch_isolated(
        _find_overflow_reaching_input_impl,
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
    gate = _engine.availability_gate("find_overflow_reaching_input")
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

    # Entry stack pointer: the boundary between program-written stack
    # (below) and the loader model's argv/env layout (above). The
    # memory snapshot must not report layout artifacts as concrete
    # facts — a real process's environment differs from the model's.
    try:
        entry_sp = int(state.solver.eval(state.regs.sp))
    except Exception:  # noqa: BLE001 — exotic arch: no memory capture
        entry_sp = None

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
                            + _engine.errored_suffix(simgr)
                        )
                        if simgr.unconstrained else
                        "exhausted — no unconstrained state reached "
                        "(no overflow-to-PC path found)"
                        + _engine.errored_suffix(simgr)
                    ),
                    wall_seconds=time.monotonic() - t0,
                    states_explored=_engine.count_states(simgr),
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
                entry_sp=entry_sp,
            )
            tried_unconstrained = len(simgr.unconstrained)
            if solved is not None:
                data, snapshot = solved
                return SymbolicResult(
                    succeeded=True,
                    reason="found reaching input via unconstrained-PC solve",
                    wall_seconds=time.monotonic() - t0,
                    concrete_input=data,
                    states_explored=_engine.count_states(simgr),
                    metadata={
                        "target_address": target_address,
                        "input_length": len(data),
                        "steps": steps,
                        "stash": "unconstrained",
                        "canary_present": _has_canary(project),
                        "register_snapshot": snapshot["registers"],
                        **(
                            {"memory_snapshot": snapshot["memory"]}
                            if "memory" in snapshot else {}
                        ),
                    },
                )
            # Defensive cap: some pathological targets branch every
            # step without ever hitting a ret; the deadline check
            # above bounds wall clock but this bounds RAM. Same
            # ceiling as the sibling engines' budget_step, but this
            # loop REPORTS the explosion instead of silently pruning
            # — the manual stepper owes the caller a diagnosis.
            if len(simgr.active) > _engine.MAX_ACTIVE_STATES:
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
                    states_explored=_engine.count_states(simgr),
                    metadata={
                        "target_address": target_address,
                        "steps": steps,
                    },
                )
    except Exception as exc:  # noqa: BLE001
        return _engine.raised_result(
            exc, t0=t0, simgr=simgr, verb="step",
            metadata={"target_address": target_address, "steps": steps},
        )

    wall = time.monotonic() - t0
    states = _engine.count_states(simgr)
    timed_out = time.monotonic() >= deadline

    # Final attempt on any lingering unconstrained states.
    solved = _try_solve_pc(
        simgr.unconstrained, target_address, max_input_bytes,
        register_constraints=register_constraints,
        entry_sp=entry_sp,
    )
    if solved is not None:
        data, snapshot = solved
        return SymbolicResult(
            succeeded=True,
            reason="found reaching input via post-loop unconstrained solve",
            wall_seconds=wall,
            concrete_input=data,
            states_explored=states,
            metadata={
                "target_address": target_address,
                "input_length": len(data),
                "steps": steps,
                "stash": "unconstrained",
                "canary_present": _has_canary(project),
                "register_snapshot": snapshot["registers"],
                **(
                    {"memory_snapshot": snapshot["memory"]}
                    if "memory" in snapshot else {}
                ),
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
    entry_sp: Optional[int] = None,
) -> Optional[tuple]:
    """Try each unconstrained state: constrain PC to target_address
    (plus any register_constraints), check satisfiability, extract
    stdin bytes on success.

    Returns ``(stdin_bytes, register_snapshot)`` for the first
    satisfying state, or None when no state can be constrained to
    the target under all constraints. The snapshot captures each
    general-purpose register AT the hijacked-PC state — the
    "crash state" one-gadget constraint checking needs.
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
        return bytes(data), _state_snapshot(candidate, entry_sp=entry_sp)
    return None


#: rsp-relative memory window captured at the hijacked state — one-
#: gadget constraints are dominated by [rsp+K] slots; 32 qwords covers
#: the offsets real gadget constraint sets reference.
_MEM_WINDOW_BYTES = 0x100


def _state_snapshot(state, *, entry_sp: Optional[int] = None) -> dict:
    """Registers plus the rsp-relative memory window, JSON-safe.

    Shape: ``{"registers": {...}, "memory": {"rsp+0x30": int, ...}}``.
    Memory capture needs a concrete stack pointer; each 8-byte slot is
    recorded only when the state pins it to one concretion — a
    symbolic slot stays absent (free for the one-gadget solver, which
    matches what the attacker may control). Slots at or above the
    ENTRY stack pointer are skipped even when concrete: that region
    holds the loader model's argv/env layout, whose values a real
    process would not reproduce — reporting them would condition
    verdicts on model artifacts.
    """
    registers = _register_snapshot(state)
    snap = {"registers": registers}
    sp_name = "rsp" if "rsp" in registers else (
        "esp" if "esp" in registers else None)
    sp_val = (registers.get(sp_name) or {}).get("value") if sp_name else None
    if sp_val is None or entry_sp is None:
        return snap
    reject_value = _model_value_rejector(state, entry_sp)
    memory: dict = {}
    for off in range(0, _MEM_WINDOW_BYTES, 8):
        addr = sp_val + off
        if addr >= entry_sp:
            break  # loader-layout territory — model, not program
        try:
            v = state.memory.load(
                addr, 8, endness=state.arch.memory_endness,
            )
            if not state.solver.unique(v):
                continue
            value = int(state.solver.eval(v))
            if reject_value(value):
                # A pointer into the model stack, the extern/
                # SimProcedure glue, or a PIC object is an address
                # no real (ASLR'd) process reproduces — conditioning
                # a one-gadget verdict on it would be unsound even
                # though the slot itself was program-written.
                continue
            memory[f"{sp_name}+{off:#x}"] = value
        except Exception:  # noqa: BLE001 — unmapped slot: omit
            continue
    if memory:
        snap["memory"] = memory
    return snap


def _model_value_rejector(state, entry_sp: int):
    """Predicate: is this concrete VALUE a model-specific address?

    The entry-sp boundary handles model addresses; program-written
    slots below it can still HOLD model addresses the program copied
    or the glue wrote (argv pointers, saved returns into the loader's
    fake libc, frame pointers). Real processes randomise all of them.
    """
    bands = [(entry_sp - 0x800000, entry_sp + 0x10000)]
    try:
        loader = state.project.loader
        ext = loader.extern_object
        if ext is not None:
            bands.append((ext.min_addr, ext.max_addr))
        for obj in loader.all_objects:
            if getattr(obj, "pic", False):
                bands.append((obj.min_addr, obj.max_addr))
    except Exception:  # noqa: BLE001 — filter degrades to stack band
        pass

    def _reject(value: int) -> bool:
        return any(lo <= value <= hi for lo, hi in bands)

    return _reject


def _register_snapshot(state) -> dict:
    """General-purpose registers at the hijacked-PC state.

    Per register: ``{"value": int}`` when the state pins it to one
    concretion, else ``{"symbolic": True, "attacker_influenced":
    bool}`` (influenced = its expression involves stdin bytes, so
    the attacker can steer it). The concrete subset is exactly the
    crash-state dict one-gadget SMT checking conditions on; symbolic
    registers stay absent there — free for the solver, which matches
    reality. The register name list comes from archinfo, not a
    hardcoded per-arch table.
    """
    snap: dict = {}
    try:
        names = list(state.arch.default_symbolic_registers)
    except Exception:  # noqa: BLE001 — exotic arch: no snapshot
        return snap
    pc_names = {"rip", "eip", "pc", "ip"}
    for name in names:
        if name in pc_names:
            continue  # constrained to the target by construction
        try:
            v = getattr(state.regs, name)
            if state.solver.unique(v):
                snap[name] = {"value": int(state.solver.eval(v))}
            else:
                snap[name] = {
                    "symbolic": True,
                    "attacker_influenced": any(
                        "stdin" in var for var in v.variables
                    ),
                }
        except Exception:  # noqa: BLE001 — unreadable register: omit
            continue
    return snap


def _has_canary(project) -> bool:
    """Stack-protector present in the target.

    The model's stack guard is a free symbolic value — the solver
    "defeats" it by choosing it, which no real attacker can do. A
    hijack witness on a canary'd binary is therefore model-optimistic
    and consumers must weight it accordingly; the flag makes that
    judgement mechanical.
    """
    try:
        return project.loader.find_symbol("__stack_chk_fail") is not None
    except Exception:  # noqa: BLE001 — unknown loader state: no claim
        return False
