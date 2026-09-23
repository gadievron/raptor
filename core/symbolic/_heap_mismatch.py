"""Heap-copy-size mismatch witness primitive.

Symbolically verify that a copy operation can overflow its destination
buffer on at least one feasible path.  The static heap_copy_checker
(``core.audit.heap_copy_checker``) finds candidates by pattern-matching
decompiled C; this primitive proves them via angr symbolic execution.

Architecture
~~~~~~~~~~~~

Three angr SimProcedure hooks installed on the target binary:

1. **Alloc hook** (malloc / calloc / realloc): records
   ``{returned_pointer_AST: size_AST}`` in the state's globals dict.
   Size is kept SYMBOLIC so the solver can reason about it.

2. **Copy hook** (memcpy / memmove / strncpy): at each call, iterates
   tracked allocations and asks the solver whether
   ``dst == alloc_ptr AND count > alloc_size`` is satisfiable.  When
   yes, pins those constraints and extracts a concrete stdin witness.

3. **Free hook** (free / realloc): removes the pointer from the
   tracked-allocation map so freed buffers don't generate stale
   findings.

All hooks are installed INSIDE the isolated child process
(``_isolate.run_isolated``), so the parent's project cache stays
clean.

Security
~~~~~~~~

- Runs in a spawned child with hard-kill timeout (``_isolate``).
- Child installs Landlock (writes denied outside a private
  per-child temp directory; no outbound TCP) before importing angr,
  confining the VEX lifter and z3 solver against hostile binaries.
  The temp-dir carve-out is what lets angr import at all — see
  :func:`core.symbolic._isolate._apply_symex_sandbox`.
- Pointer comparison is SYMBOLIC (``solver.satisfiable``), not
  concretised — a crafted binary cannot evade by making the pointer
  multi-valued.
- Result strings are attacker-influenced — envelope before prompt use.
"""
from __future__ import annotations

import time
from pathlib import Path

from core.symbolic import _engine
from core.symbolic._budget import z3_call_budget
from core.symbolic._types import SymbolicResult

_DEFAULT_TIMEOUT_SECONDS = 60.0
_DEFAULT_MAX_INPUT_BYTES = 4096


def find_heap_mismatch_witness(
    binary_path: Path,
    target_address: int,
    *,
    timeout: float = _DEFAULT_TIMEOUT_SECONDS,
    max_input_bytes: int = _DEFAULT_MAX_INPUT_BYTES,
) -> SymbolicResult:
    """Isolated entry point — runs in a spawned child with hard-kill
    via :func:`core.symbolic._engine.dispatch_isolated`; when angr is
    unavailable the availability guard answers directly.

    SUCCESS CONTRACT — read before treating a witness as proof of a
    specific finding: ``target_address`` steers only the mapped-check
    and the result metadata. Exploration accepts the FIRST state
    whose copy hook recorded ANY satisfiable ``count > alloc_size``,
    at ANY call site — a binary with a second symbolically
    overflowable copy can return ``succeeded=True`` whose
    ``metadata.call_addr`` points somewhere other than the
    hypothesised site. Success therefore proves "SOME heap-copy
    mismatch is reachable", and a consumer certifying a specific
    static candidate MUST join ``metadata.call_addr`` against the
    hypothesised site before attributing the witness to it.

    Wiring status: not exported from ``core.symbolic`` — consumers
    import this module directly; the package ``__all__`` surface
    lists only the general-purpose solvers.
    """
    return _engine.dispatch_isolated(
        _find_heap_mismatch_impl,
        {"binary_path": binary_path, "target_address": target_address,
         "timeout": timeout, "max_input_bytes": max_input_bytes},
        timeout=timeout,
    )


# ── Allocation-tracking globals key ─────────────────────────────────
# Stored in angr's state.globals dict, which is per-state (forked on
# branch).  Each entry maps a claripy AST (the pointer) to its
# allocation size AST.  We use a list of (ptr_ast, size_ast) pairs
# rather than a dict because ASTs are unhashable.
_ALLOC_KEY = "_raptor_heap_allocs"
_MISMATCH_KEY = "_raptor_heap_mismatch"


def _append_alloc(state, ptr, size) -> None:
    """Record an allocation with copy-on-write discipline.

    angr's ``SimStateGlobals.copy`` is a SHALLOW copy, so forked
    sibling states share the same list object.  An in-place append
    leaks the allocation into mutually exclusive branches — the safe
    branch's copy then satisfies ``dst == <other branch's alloc>`` and
    mints a false heap-overflow confirmation.  Rebuild-and-reassign
    (the pattern the realloc/free hooks already use) keeps each
    state's view isolated.
    """
    allocs = list(state.globals.get(_ALLOC_KEY, ()))
    allocs.append((ptr, size))
    state.globals[_ALLOC_KEY] = allocs


def _install_heap_hooks(project) -> int:
    """Hook malloc/calloc/realloc + memcpy/memmove/strncpy + free.

    Returns the number of symbols hooked.
    """
    import angr
    from angr.procedures import SIM_PROCEDURES

    hooked = 0

    # ── Alloc hooks ──────────────────────────────────────────────────

    class _TrackedMalloc(angr.SimProcedure):
        def run(self, size):  # noqa: N802
            result = self.inline_call(
                SIM_PROCEDURES["libc"]["malloc"], size,
            )
            ptr = result.ret_expr
            _append_alloc(self.state, ptr, size)
            return ptr

    class _TrackedCalloc(angr.SimProcedure):
        def run(self, nmemb, size):  # noqa: N802
            total = nmemb * size
            result = self.inline_call(
                SIM_PROCEDURES["libc"]["calloc"], nmemb, size,
            )
            ptr = result.ret_expr
            _append_alloc(self.state, ptr, total)
            return ptr

    class _TrackedRealloc(angr.SimProcedure):
        def run(self, old_ptr, size):  # noqa: N802
            result = self.inline_call(
                SIM_PROCEDURES["libc"]["realloc"], old_ptr, size,
            )
            new_ptr = result.ret_expr
            allocs = self.state.globals.get(_ALLOC_KEY, [])
            # Remove old allocation (best-effort symbolic match)
            allocs = [
                (p, s) for p, s in allocs
                if not self.state.solver.is_true(p == old_ptr)
            ]
            allocs.append((new_ptr, size))
            self.state.globals[_ALLOC_KEY] = allocs
            return new_ptr

    # ── Copy hooks ───────────────────────────────────────────────────

    class _CheckedCopy(angr.SimProcedure):
        """Hook for memcpy / memmove / strncpy.

        At each call, check whether count > alloc_size is satisfiable
        for any tracked allocation whose pointer matches dst.

        Pointer matching uses solver.satisfiable (SYMBOLIC comparison)
        — not solver.eval (concretisation).  This prevents a crafted
        binary from evading detection by making the pointer
        multi-valued.
        """
        _base_name: str = "memcpy"

        def run(self, dst, src, count):  # noqa: N802
            import claripy
            allocs = self.state.globals.get(_ALLOC_KEY, [])

            for alloc_ptr, alloc_size in allocs:
                # Symbolic pointer match: is dst == alloc_ptr feasible?
                try:
                    ptr_match = self.state.solver.satisfiable(
                        extra_constraints=[dst == alloc_ptr],
                    )
                except Exception:  # noqa: BLE001
                    continue
                if not ptr_match:
                    continue

                # Core query: can count exceed alloc_size on this path?
                try:
                    overflow_feasible = self.state.solver.satisfiable(
                        extra_constraints=[
                            dst == alloc_ptr,
                            claripy.UGT(count, alloc_size),
                        ],
                    )
                except Exception:  # noqa: BLE001
                    continue
                if not overflow_feasible:
                    continue

                # PIN the overflow condition into the path constraints.
                # The satisfiable() call above used TEMPORARY
                # extra_constraints; without solver.add the stdin
                # witness dumped from the found state concretises under
                # the bare path constraints, where a benign count (0)
                # is an equally valid model — and the result would
                # still claim "concrete stdin witness triggers
                # heap-copy overflow". If pinning fails, skip the
                # allocation rather than record an unpinned mismatch:
                # never mint witness-grade evidence the solve doesn't
                # actually constrain.
                try:
                    self.state.solver.add(dst == alloc_ptr)
                    self.state.solver.add(claripy.UGT(count, alloc_size))
                except Exception:  # noqa: BLE001
                    continue

                # Record the mismatch — exploration will pick it up
                self.state.globals[_MISMATCH_KEY] = {
                    "copy_fn": self._base_name,
                    "call_addr": self.state.addr,
                }
                break

            base = SIM_PROCEDURES["libc"].get(self._base_name)
            if base is not None:
                return self.inline_call(base, dst, src, count).ret_expr
            return dst

    class _CheckedMemmove(_CheckedCopy):
        _base_name = "memmove"

    class _CheckedStrncpy(_CheckedCopy):
        _base_name = "strncpy"

    # ── Free hook ────────────────────────────────────────────────────

    class _TrackedFree(angr.SimProcedure):
        def run(self, ptr):  # noqa: N802
            allocs = self.state.globals.get(_ALLOC_KEY, [])
            self.state.globals[_ALLOC_KEY] = [
                (p, s) for p, s in allocs
                if not self.state.solver.is_true(p == ptr)
            ]
            base = SIM_PROCEDURES["libc"].get("free")
            if base is not None:
                return self.inline_call(base, ptr).ret_expr

    # ── Install hooks ────────────────────────────────────────────────

    _HOOK_MAP: dict[str, type] = {
        "malloc": _TrackedMalloc,
        "calloc": _TrackedCalloc,
        "realloc": _TrackedRealloc,
        "memcpy": _CheckedCopy,
        "memmove": _CheckedMemmove,
        "strncpy": _CheckedStrncpy,
        "free": _TrackedFree,
    }

    for name, cls in _HOOK_MAP.items():
        try:
            project.hook_symbol(name, cls(), replace=True)
            hooked += 1
        except Exception:  # noqa: BLE001 — symbol absent
            continue

    return hooked


def _find_heap_mismatch_impl(
    binary_path: Path,
    target_address: int,
    *,
    timeout: float = _DEFAULT_TIMEOUT_SECONDS,
    max_input_bytes: int = _DEFAULT_MAX_INPUT_BYTES,
) -> SymbolicResult:
    """Symbolic execution from binary entry to ``target_address``.

    Hooks libc allocation + copy functions.  When a copy whose
    count > alloc_size is satisfiable on any reachable path, extracts
    a concrete stdin witness.
    """
    gate = _engine.availability_gate("find_heap_mismatch_witness")
    if gate is not None:
        return gate

    binary_path, missing = _engine.check_binary(binary_path)
    if missing is not None:
        return missing

    t0 = time.monotonic()
    project, load_error = _engine.open_gated_project(
        binary_path, t0, install_hooks=_install_heap_hooks,
    )
    if load_error is not None:
        return load_error

    unmapped = _engine.check_mapped(project, target_address, t0)
    if unmapped is not None:
        return unmapped

    state = _engine.make_entry_state(project)
    simgr = project.factory.simulation_manager(state)

    deadline = t0 + timeout

    def _has_mismatch(st) -> bool:
        return _MISMATCH_KEY in st.globals

    def _scan_for_mismatch(sg):
        # Check active states for mismatch findings
        for st in list(sg.active):
            if _has_mismatch(st):
                sg.move(
                    from_stash="active", to_stash="found",
                    filter_func=lambda s: _MISMATCH_KEY in s.globals,
                )
                break
        return sg

    step = _engine.budget_step(deadline, on_continue=_scan_for_mismatch)
    try:
        with z3_call_budget(deadline):
            simgr.explore(
                find=lambda s: _has_mismatch(s),
                num_find=1,
                step_func=step,
            )
    except Exception as exc:  # noqa: BLE001
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
            no_path_reason="no heap-copy mismatch on any explored path",
            metadata={"target_address": target_address},
            step=step, simgr=simgr,
        )

    found = simgr.found[0]
    mismatch_info = found.globals.get(_MISMATCH_KEY, {})

    concrete = _engine.dump_stdin_witness(
        found, max_input_bytes=max_input_bytes, wall=wall, states=states,
        metadata={"target_address": target_address},
    )
    if isinstance(concrete, SymbolicResult):
        return concrete

    return SymbolicResult(
        succeeded=True,
        reason="concrete stdin witness triggers heap-copy overflow",
        wall_seconds=wall,
        concrete_input=concrete,
        states_explored=states,
        metadata={
            "target_address": target_address,
            "input_length": len(concrete),
            "copy_fn": mismatch_info.get("copy_fn", ""),
            "call_addr": mismatch_info.get("call_addr"),
        },
    )

