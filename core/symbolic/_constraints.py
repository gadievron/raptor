"""Path constraint extraction: given a binary + target address, symex
from entry to that address and return, for each path found, the SMT
constraints stdin bytes must satisfy for the path to be feasible.

Rationale (design-memo's flagged biggest-missing primitive): higher-
level substrates need to reason about REACHABILITY + FEASIBILITY of
specific program points. ``find_reaching_input`` answers "IS this
address reachable?"; this primitive answers "WHY / under what input
constraints IS it reachable?" — a strictly more useful signal for the
LLM when verifying multi-step hypotheses or characterising a bug.

Consumers (per design roadmap):
  * ``/crash-analysis`` — reconstruct which input branches led to the
    crash state (root-cause narrative).
  * ``/understand`` — data-flow characterisation: which input bytes
    gate which downstream operations.
  * ``/validate`` — feasibility: is the found path SAT under additional
    caller-supplied constraints (e.g., "given the hypothesised heap
    layout, can the OOB read still reach the secret?").
  * binary audit verification — the LLM asks "what must input
    satisfy to reach the suspect sink?" and the answer corroborates
    or refutes the hypothesis.

Return shape (metadata['paths']):
  [
    {
      "constraints": ["<file_0_stdin_0_0_1024[7:0] == 0x41>", ...],
      "stdin_bytes_touched": [0, 1, 2, ...],  # sorted, unique
      "concrete_input_hex": "aabbcc...",
      "branch_count": int,   # rough proxy for path complexity
    },
    ...
  ]
"""
from __future__ import annotations

import re
import time
from pathlib import Path
from typing import Any, Optional

from core.symbolic._project import _open_project
from core.symbolic._budget import z3_call_budget
from core.symbolic._types import SymbolicResult

_DEFAULT_TIMEOUT_SECONDS = 30.0
_DEFAULT_MAX_INPUT_BYTES = 128
_DEFAULT_MAX_PATHS = 3

# Angr / claripy name pattern for symbolic stdin bytes. Bytes are
# named ``file_<n>_stdin_<x>_<y>_<len>``; the index-into-the-buffer
# comes from an inclusive-exclusive bit slice on the whole file BV.
_STDIN_VAR_RE = re.compile(r"^file_\d+_stdin_\d+_\d+_\d+$")


def extract_path_constraints(
    binary_path: Path,
    target_address: int,
    *,
    max_paths: int = _DEFAULT_MAX_PATHS,
    timeout: float = _DEFAULT_TIMEOUT_SECONDS,
    max_input_bytes: int = _DEFAULT_MAX_INPUT_BYTES,
) -> SymbolicResult:
    """Isolated entry point — semantics in
    :func:`_extract_path_constraints_impl`.

    Hard-budget process isolation; see :mod:`core.symbolic._isolate`.
    When angr is unavailable the availability guard answers directly.
    """
    from core.symbolic._availability import angr_available
    from core.symbolic._isolate import run_isolated
    if not angr_available():
        return _extract_path_constraints_impl(
            binary_path, target_address, max_paths=max_paths,
            timeout=timeout, max_input_bytes=max_input_bytes)
    return run_isolated(
        "core.symbolic._constraints", "_extract_path_constraints_impl",
        {"binary_path": binary_path, "target_address": target_address,
         "max_paths": max_paths, "timeout": timeout,
         "max_input_bytes": max_input_bytes},
        timeout=timeout,
    )


def _extract_path_constraints_impl(
    binary_path: Path,
    target_address: int,
    *,
    max_paths: int = _DEFAULT_MAX_PATHS,
    timeout: float = _DEFAULT_TIMEOUT_SECONDS,
    max_input_bytes: int = _DEFAULT_MAX_INPUT_BYTES,
) -> SymbolicResult:
    """Symex from entry to ``target_address`` with symbolic stdin.
    For up to ``max_paths`` distinct paths that reach it, collect
    the solver constraints on stdin bytes and one satisfying
    concrete input.

    Args:
        binary_path: ELF to symbolic-execute.
        target_address: rebased address to reach.
        max_paths: how many distinct-path solutions to enumerate.
            Angr's ``num_find`` semantics — not "all paths" (that
            usually state-explodes), just N.
        timeout: hard wall-clock budget.
        max_input_bytes: symbolic-stdin cap (bytes).

    Returns:
        :class:`SymbolicResult`. On success ``metadata['paths']`` is
        a list of per-path dicts (see module docstring). Empty list
        + ``succeeded=False`` when no path was found in budget.
    """
    from core.symbolic._availability import (
        angr_available, unavailable_result,
    )
    if not angr_available():
        return unavailable_result("angr", "extract_path_constraints")

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
        add_options={angr.options.LAZY_SOLVES},
    )
    # save_unconstrained=True: capture states whose PC becomes symbolic
    # (typical of stack-overflow-to-PC paths). Post-explore we
    # constrain each unconstrained state's PC to target_address; when
    # satisfiable that gives us an OVERFLOW-HIJACK path — for the
    # LLM, the constraint set is what a violating input must satisfy
    # to reach the hijack point AND land PC on target. Without this
    # flag the primitive would miss every PC-control-shape target
    # (the most common shape in the corpus).
    simgr = project.factory.simulation_manager(
        state, save_unconstrained=True,
    )

    deadline = t0 + timeout

    def _stop(_simgr) -> bool:
        return time.monotonic() >= deadline

    def _step(sg):
        if _stop(sg):
            return sg.move(from_stash="active", to_stash="deadended")
        if len(sg.active) > 512:
            # RAM bound (mirrors _overflow).
            return sg.move(from_stash="active", to_stash="deadended")
        return sg

    try:
        with z3_call_budget(deadline):
            simgr.explore(
                find=target_address,
                num_find=max_paths,
                step_func=_step,
            )
    except Exception as exc:  # noqa: BLE001
        return SymbolicResult(
            succeeded=False,
            reason=f"angr explore raised: {type(exc).__name__}: {exc}",
            wall_seconds=time.monotonic() - t0,
            states_explored=_count_states(simgr),
            metadata={"target_address": target_address},
        )

    wall = time.monotonic() - t0
    states = _count_states(simgr)

    # Second pass: unconstrained states are overflow-hijack candidates.
    # Constrain each state's PC to target_address; when satisfiable,
    # the state's now-augmented constraint set is exactly the path
    # requirement for a feasible PC-control path. Same pattern
    # find_overflow_reaching_input uses for overflow witnesses.
    hijack_states = _promote_unconstrained_to_target(
        simgr, target_address, max_paths - len(simgr.found),
    )

    if not simgr.found and not hijack_states:
        timed_out = time.monotonic() >= deadline
        return SymbolicResult(
            succeeded=False,
            reason=(
                f"timeout after {wall:.1f}s with no path found"
                if timed_out
                else "explored fully; no path reaches target"
            ),
            wall_seconds=wall,
            states_explored=states,
            metadata={"target_address": target_address, "paths": []},
        )

    paths: list[dict[str, Any]] = []
    for state in simgr.found:
        try:
            path = _extract_one_path(state, max_input_bytes)
            path["path_kind"] = "natural_cfg"
            paths.append(path)
        except Exception as exc:  # noqa: BLE001
            # A single path that fails to extract shouldn't torpedo
            # the whole result — record the failure and continue.
            paths.append({
                "constraints": [],
                "stdin_bytes_touched": [],
                "concrete_input_hex": None,
                "branch_count": 0,
                "path_kind": "natural_cfg",
                "extraction_error": (
                    f"{type(exc).__name__}: {str(exc)[:120]}"
                ),
            })
    for state in hijack_states:
        try:
            path = _extract_one_path(state, max_input_bytes)
            path["path_kind"] = "overflow_hijack"
            paths.append(path)
        except Exception as exc:  # noqa: BLE001
            paths.append({
                "constraints": [],
                "stdin_bytes_touched": [],
                "concrete_input_hex": None,
                "branch_count": 0,
                "path_kind": "overflow_hijack",
                "extraction_error": (
                    f"{type(exc).__name__}: {str(exc)[:120]}"
                ),
            })

    return SymbolicResult(
        succeeded=True,
        reason=(
            f"extracted constraints for {len(paths)} path(s) "
            f"({len(simgr.found)} natural-CFG, {len(hijack_states)} "
            "overflow-hijack)"
        ),
        wall_seconds=wall,
        states_explored=states,
        metadata={
            "target_address": target_address,
            "paths": paths,
        },
    )


def _promote_unconstrained_to_target(
    simgr, target_address: int, want: int,
) -> list:
    """For each state in ``simgr.unconstrained`` (which has symbolic
    PC — typical of stack-overflow-to-PC paths), constrain PC to
    ``target_address`` and keep the state when the constraint is
    satisfiable. Returns up to ``want`` such states.

    The augmented constraint set on each returned state IS the
    path-feasibility requirement — what the input must satisfy to reach
    a PC-hijack point AND land on target. Mirrors the pattern
    :func:`~core.symbolic._overflow.find_overflow_reaching_input`
    uses for overflow witnesses.

    ``want <= 0`` short-circuits to an empty list — the caller has
    already collected enough natural-CFG paths.
    """
    if want <= 0:
        return []
    out = []
    for state in simgr.unconstrained:
        if len(out) >= want:
            break
        candidate = state.copy()
        try:
            candidate.solver.add(candidate.regs.pc == target_address)
        except Exception:  # noqa: BLE001
            continue
        try:
            if not candidate.satisfiable():
                continue
        except Exception:  # noqa: BLE001
            continue
        out.append(candidate)
    return out


def _extract_one_path(state, max_input_bytes: int) -> dict[str, Any]:
    """Distil one found state into the per-path dict."""
    # Constraints — stringify each. Claripy AST's ``__repr__`` is
    # verbose but stable; consumers see human-readable expressions
    # with recognisable stdin variable names.
    constraint_strs = [str(c) for c in state.solver.constraints]

    # Which stdin bytes did the path constrain? Walk each constraint
    # AST for ``Extract(hi, lo, stdin_var)`` ops — the slice range
    # tells us exactly which byte(s) the constraint touches. Bit
    # ordering: angr's SimFileStream numbers bit `size-1` as the
    # MSB of byte 0, so a slice `[hi:lo]` on a var of width
    # ``total_bits`` covers byte indices
    # ``(total_bits - 1 - hi) // 8`` .. ``(total_bits - 1 - lo) // 8``
    # inclusive.
    stdin_bytes: set[int] = set()
    for c in state.solver.constraints:
        try:
            _collect_stdin_byte_indices(c, stdin_bytes)
        except Exception:  # noqa: BLE001
            # Best-effort — a walk failure on one constraint doesn't
            # block extraction of the others (or the concrete input).
            pass

    # Concrete satisfying input.
    try:
        raw = bytes(state.posix.dumps(0)[:max_input_bytes])
        concrete_hex: Optional[str] = raw.hex()
    except Exception:  # noqa: BLE001
        concrete_hex = None

    return {
        "constraints": constraint_strs,
        "stdin_bytes_touched": sorted(stdin_bytes),
        "concrete_input_hex": concrete_hex,
        "branch_count": len(constraint_strs),
    }


def _collect_stdin_byte_indices(ast, out: set) -> None:
    """Walk a claripy AST looking for ``Extract(hi, lo, stdin_var)``
    slices and record the byte indices those slices reference into
    ``out``. Handles nested asts recursively.

    File-bit ordering per angr's ``SimFileStream``: bit ``size-1`` is
    the MSB of byte 0. So slice ``[hi:lo]`` on a var of width
    ``total_bits`` covers bytes
    ``(total_bits - 1 - hi) // 8`` through
    ``(total_bits - 1 - lo) // 8`` inclusive.
    """
    # Terminal: BV leaf that IS a stdin variable → the whole thing.
    op = getattr(ast, "op", None)
    if op is None:
        return
    if op == "Extract":
        # ast.args = (hi, lo, inner_ast); inner might be a plain BV
        # leaf or a nested Extract.
        try:
            hi = int(ast.args[0])
            lo = int(ast.args[1])
            inner = ast.args[2]
        except Exception:  # noqa: BLE001
            return
        inner_vars = getattr(inner, "variables", frozenset())
        stdin_vars = [v for v in inner_vars if _STDIN_VAR_RE.match(v)]
        if stdin_vars:
            total_bits = getattr(inner, "size", lambda: None)()
            if total_bits is None or not isinstance(total_bits, int):
                # Fallback: parse "<total_len>" from the var name.
                # file_0_stdin_0_<a>_<total_bits>
                for v in stdin_vars:
                    try:
                        total_bits = int(v.rsplit("_", 1)[-1])
                        break
                    except (ValueError, IndexError):
                        continue
            if total_bits:
                lo_byte = (total_bits - 1 - hi) // 8
                hi_byte = (total_bits - 1 - lo) // 8
                if lo_byte > hi_byte:
                    lo_byte, hi_byte = hi_byte, lo_byte
                for b in range(lo_byte, hi_byte + 1):
                    out.add(b)
        # Recurse into the inner in case it's a compound expression.
        _collect_stdin_byte_indices(inner, out)
        return
    # Non-Extract op: recurse into children that are ASTs.
    args = getattr(ast, "args", ())
    for a in args:
        if hasattr(a, "op"):
            _collect_stdin_byte_indices(a, out)


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
