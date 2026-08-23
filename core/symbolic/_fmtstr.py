"""Format-string slot discovery primitive.

When a binary contains a CWE-134 sink of the shape ``printf(buf)``
(attacker-controlled format string), a violating path typically
needs to know:

  * which slot indices (as accessed by ``%N$p``) leak useful pointers
    (code pointers → defeats PIE; stack pointers → locates saved rbp
    / return address);
  * which slot indices are ATTACKER-CONTROLLED (i.e. read directly
    from stdin) — those are the ones that let ``%hn`` do a
    write-what-where by controlling the target address of the write.

Empirical LLM playbooks discover this by sending a probe input like
``AAAA %1$p %2$p ... %20$p`` and parsing the output. That works when
the target loops on printf, but it's a whole extra interaction round.
When the target only prints once, or when we're doing static analysis,
we don't get a probe channel.

This primitive replaces the probe with symbolic execution: explore
from binary entry to the printf call site with symbolic stdin,
then classify each vararg slot per the SysV amd64 calling convention:

  * ``%1$p`` → ``rsi``       (2nd arg — 1st vararg after fmt)
  * ``%2$p`` → ``rdx``
  * ``%3$p`` → ``rcx``
  * ``%4$p`` → ``r8``
  * ``%5$p`` → ``r9``
  * ``%(5+i)$p`` → ``[rsp+8*i]``  (stack vararg #i, skips return addr)

For each slot the classifier reports:

  * ``code`` — concrete pointer into an executable section (PIE leak)
  * ``rodata`` / ``data`` — concrete pointer into a data section
  * ``stack`` — concrete pointer into the state's stack region
  * ``concrete`` — concrete but not a recognisable pointer (integer,
    small constant); usually junk from register spill
  * ``stdin`` — symbolic value derived from stdin — attacker-
    controlled: ``%N$hn`` here writes to whatever address the
    attacker sends in the corresponding buf offset
  * ``symbolic`` — symbolic value with no stdin dependency
    (uninitialised at this PC — angr's placeholder)

Scope for v1:
  * x86_64 SysV only. Other arches (i386 cdecl, ARM64) fail with a
    descriptive reason so the caller can pick a different primitive.
  * Single call site — caller supplies ``sink_addr``. Discovery of
    ``printf`` call sites lives in the router (source scan + PLT
    lookup already handle that path).
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from core.function_taxonomy import FORMAT_STRING_FMT_ARG_INDEX
from core.symbolic._project import _open_project
from core.symbolic._budget import z3_call_budget
from core.symbolic._types import SymbolicResult

_DEFAULT_TIMEOUT_SECONDS = 30.0
_DEFAULT_NUM_SLOTS = 20
_DEFAULT_MAX_INPUT_BYTES = 128

# SysV amd64: the first 6 integer/pointer args live in these regs
# in order. Args beyond the 6th spill to [rsp+8*(i-6)] (i-1 stack
# words above the return address).
_SYSV_AMD64_ARG_REGS_ALL = ("rdi", "rsi", "rdx", "rcx", "r8", "r9")


def fmt_arg_index_for(sink_name: str) -> Optional[int]:
    """Return the 1-based fmt-arg position for a named fmt sink
    (e.g. ``"snprintf"`` → 3), or None if the name isn't a known
    fmt-family function. Shared registry lives in
    :mod:`core.function_taxonomy`."""
    return FORMAT_STRING_FMT_ARG_INDEX.get(sink_name)


@dataclass(frozen=True)
class FmtstrSlot:
    """One slot in the classified varargs map."""
    index: int          # %N$p index (1-based)
    location: str       # e.g. "rsi", "[rsp+8]"
    kind: str           # "code" / "data" / "rodata" / "stack" / "concrete" / "stdin" / "symbolic"
    value_hex: Optional[str] = None   # concrete slots: hex string
    section: Optional[str] = None     # concrete slots that fall in a mapped section
    object_name: Optional[str] = None # loader object name (main / cle##tls / extern-address)
    stdin_variables: tuple[str, ...] = ()   # for stdin slots: which stdin vars leak in

    def as_dict(self) -> dict[str, Any]:
        d = {"index": self.index, "location": self.location, "kind": self.kind}
        if self.value_hex is not None:
            d["value_hex"] = self.value_hex
        if self.section is not None:
            d["section"] = self.section
        if self.object_name is not None:
            d["object_name"] = self.object_name
        if self.stdin_variables:
            d["stdin_variables"] = list(self.stdin_variables)
        return d


def discover_fmtstr_slots(
    binary_path: Path,
    sink_addr: int,
    *,
    fmt_arg_index: int = 1,
    num_slots: int = _DEFAULT_NUM_SLOTS,
    timeout: float = _DEFAULT_TIMEOUT_SECONDS,
    max_input_bytes: int = _DEFAULT_MAX_INPUT_BYTES,
) -> SymbolicResult:
    """Isolated entry point — semantics in
    :func:`_discover_fmtstr_slots_impl`.

    Hard-budget process isolation; see :mod:`core.symbolic._isolate`.
    When angr is unavailable the availability guard answers directly.
    """
    from core.symbolic._availability import angr_available
    from core.symbolic._isolate import run_isolated
    if not angr_available():
        return _discover_fmtstr_slots_impl(
            binary_path, sink_addr, fmt_arg_index=fmt_arg_index,
            num_slots=num_slots, timeout=timeout,
            max_input_bytes=max_input_bytes)
    return run_isolated(
        "core.symbolic._fmtstr", "_discover_fmtstr_slots_impl",
        {"binary_path": binary_path, "sink_addr": sink_addr,
         "fmt_arg_index": fmt_arg_index, "num_slots": num_slots,
         "timeout": timeout, "max_input_bytes": max_input_bytes},
        timeout=timeout,
    )


def _discover_fmtstr_slots_impl(
    binary_path: Path,
    sink_addr: int,
    *,
    fmt_arg_index: int = 1,
    num_slots: int = _DEFAULT_NUM_SLOTS,
    timeout: float = _DEFAULT_TIMEOUT_SECONDS,
    max_input_bytes: int = _DEFAULT_MAX_INPUT_BYTES,
) -> SymbolicResult:
    """Symex from entry to ``sink_addr`` with symbolic stdin, then
    classify the first ``num_slots`` varargs the format string would
    consume.

    Args:
        binary_path: ELF to symbolic-execute.
        sink_addr: address of the FIRST instruction of the fmt sink
            (typically its PLT stub — e.g.
            ``proj.loader.main_object.plt['printf']``).
        fmt_arg_index: 1-based position of the format-string argument
            in the sink's calling convention. Defaults to 1
            (``printf(fmt, ...)``). Use 2 for
            ``fprintf(FILE*, fmt, ...)`` /
            ``sprintf(dst, fmt, ...)`` / ``dprintf(fd, fmt, ...)``,
            3 for ``snprintf(dst, size, fmt, ...)``, etc.
            The helper :func:`fmt_arg_index_for` looks up common
            sinks by name.

            The SysV amd64 varargs live at positions
            ``(fmt_arg_index + 1)..N`` in the callee's argument list.
            The first ``6 - fmt_arg_index`` varargs come from the
            remaining registers ``rdi..r9``; subsequent varargs come
            from ``[rsp+8], [rsp+16], ...`` (skipping the return
            address at ``[rsp+0]``).
        num_slots: how many %N$p slots to classify. Default 20 covers
            the range attackers usually probe.
        timeout: hard wall-clock budget for the exploration step.
        max_input_bytes: symbolic-stdin cap. Kept small (default 128)
            because slot discovery only needs enough input to *reach*
            the sink call; the LLM reasons about concrete violating input
            afterwards.

    Returns:
        SymbolicResult. On success, ``metadata['slots']`` is a list of
        :class:`FmtstrSlot`-shaped dicts. On failure, ``reason``
        explains the failure (arch unsupported, path not reached,
        timeout, etc.).
    """
    from core.symbolic._availability import (
        angr_available, unavailable_result,
    )
    if not angr_available():
        return unavailable_result("angr", "discover_fmtstr_slots")

    binary_path = Path(binary_path)
    if not binary_path.is_file():
        return SymbolicResult(
            succeeded=False,
            reason=f"binary not found: {binary_path}",
            wall_seconds=0.0,
        )

    if fmt_arg_index < 1 or fmt_arg_index > len(_SYSV_AMD64_ARG_REGS_ALL):
        return SymbolicResult(
            succeeded=False,
            reason=(
                f"fmt_arg_index={fmt_arg_index} out of range 1..6 "
                "(SysV amd64 puts args beyond 6 on the stack; a fmt "
                "arg past the 6th register slot is not supported)"
            ),
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

    if project.arch.name != "AMD64":
        return SymbolicResult(
            succeeded=False,
            reason=(
                f"unsupported arch {project.arch.name!r} — this "
                "primitive only implements SysV amd64 vararg mapping"
            ),
            wall_seconds=time.monotonic() - t0,
            metadata={"arch": project.arch.name},
        )

    if not _is_mapped(project, sink_addr):
        return SymbolicResult(
            succeeded=False,
            reason=(
                f"sink_addr 0x{sink_addr:x} not in a mapped segment"
            ),
            wall_seconds=time.monotonic() - t0,
            metadata={"sink_addr": sink_addr},
        )

    import angr

    state = project.factory.entry_state(
        stdin=angr.SimFileStream,
        add_options={angr.options.LAZY_SOLVES},
    )
    simgr = project.factory.simulation_manager(state)

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
                find=sink_addr,
                num_find=1,
                step_func=_step,
            )
    except Exception as exc:  # noqa: BLE001
        return SymbolicResult(
            succeeded=False,
            reason=f"angr explore raised: {type(exc).__name__}: {exc}",
            wall_seconds=time.monotonic() - t0,
            states_explored=_count_states(simgr),
            metadata={"sink_addr": sink_addr},
        )

    wall = time.monotonic() - t0

    if not simgr.found:
        timed_out = time.monotonic() >= deadline
        return SymbolicResult(
            succeeded=False,
            reason=(
                f"timeout after {wall:.1f}s (never reached sink)"
                if timed_out
                else "no path from entry to sink_addr"
            ),
            wall_seconds=wall,
            states_explored=_count_states(simgr),
            metadata={"sink_addr": sink_addr},
        )

    state = simgr.found[0]
    slots = _classify_slots(project, state, num_slots, fmt_arg_index)

    return SymbolicResult(
        succeeded=True,
        reason=f"classified {len(slots)} vararg slots at sink call",
        wall_seconds=wall,
        states_explored=_count_states(simgr),
        metadata={
            "sink_addr": sink_addr,
            "slots": [s.as_dict() for s in slots],
            "arch": project.arch.name,
        },
    )


def _classify_slots(
    project, state, num_slots: int, fmt_arg_index: int,
) -> list[FmtstrSlot]:
    """Read + classify the first ``num_slots`` varargs the format
    string would see, per SysV amd64 mapping.

    Varargs start at callee-arg position ``fmt_arg_index + 1``. The
    first ``6 - fmt_arg_index`` of those come from the remaining
    registers ``rdi..r9`` (specifically
    ``_SYSV_AMD64_ARG_REGS_ALL[fmt_arg_index:]``); subsequent varargs
    come from stack slots ``[rsp+8], [rsp+16], ...`` (skipping the
    return address at ``[rsp+0]``).
    """
    slots: list[FmtstrSlot] = []
    reg_varargs = _SYSV_AMD64_ARG_REGS_ALL[fmt_arg_index:]

    for i, reg in enumerate(reg_varargs, start=1):
        if i > num_slots:
            break
        bv = getattr(state.regs, reg)
        slots.append(_classify_bv(bv, i, reg, project, state))

    for offset_i in range(1, num_slots - len(reg_varargs) + 1):
        idx = len(reg_varargs) + offset_i
        if idx > num_slots:
            break
        byte_off = 8 * offset_i
        try:
            bv = state.memory.load(
                state.regs.rsp + byte_off, 8,
                endness=project.arch.memory_endness,
            )
        except Exception:  # noqa: BLE001
            slots.append(FmtstrSlot(
                index=idx, location=f"[rsp+{byte_off}]",
                kind="symbolic",
            ))
            continue
        slots.append(
            _classify_bv(bv, idx, f"[rsp+{byte_off}]", project, state)
        )
    return slots


def _classify_bv(bv, index: int, location: str, project, state) -> FmtstrSlot:
    """Classify a single bitvector value as a fmtstr slot kind."""
    if bv.symbolic:
        stdin_vars = tuple(
            v for v in bv.variables if _looks_like_stdin(v)
        )
        return FmtstrSlot(
            index=index,
            location=location,
            kind="stdin" if stdin_vars else "symbolic",
            stdin_variables=stdin_vars,
        )
    try:
        value = state.solver.eval(bv)
    except Exception:  # noqa: BLE001
        return FmtstrSlot(
            index=index, location=location, kind="symbolic",
        )
    kind, section, obj_name = _classify_concrete_addr(project, state, value)
    return FmtstrSlot(
        index=index,
        location=location,
        kind=kind,
        value_hex=f"0x{value:x}",
        section=section,
        object_name=obj_name,
    )


def _classify_concrete_addr(project, state, addr: int) -> tuple[str, Optional[str], Optional[str]]:
    """Return (kind, section_name, object_name) for a concrete
    address. Detects code / data / rodata / stack / plain-concrete."""
    if addr == 0:
        return "concrete", None, None
    # Stack: within one page below the initial rsp is the growing
    # stack region. Angr's default stack ceiling is high memory.
    initial_sp = state.arch.initial_sp
    if 0 < initial_sp - addr < 0x10000 or 0 < addr - initial_sp < 0x1000:
        return "stack", None, None
    # Loader lookup.
    obj = project.loader.find_object_containing(addr)
    if obj is None:
        # Angr places stack ceiling at 0x7fff_ffff_..., stack pages
        # below that. Match a broader range as a heuristic.
        if 0x7000_0000_0000 <= addr < 0x8000_0000_0000:
            return "stack", None, None
        return "concrete", None, None
    obj_name = getattr(obj, "binary_basename", None) or getattr(obj, "provides", None) or "unknown"
    # Section lookup, if the object has sections indexed.
    section_name: Optional[str] = None
    kind = "data"
    try:
        for sect in getattr(obj, "sections", ()) or ():
            if sect.min_addr <= addr <= sect.max_addr and sect.name:
                section_name = sect.name
                if getattr(sect, "is_executable", False):
                    kind = "code"
                elif "rodata" in sect.name.lower():
                    kind = "rodata"
                else:
                    kind = "data"
                break
    except Exception:  # noqa: BLE001
        pass
    return kind, section_name, obj_name


def _looks_like_stdin(var_name: str) -> bool:
    """Angr names symbolic stdin bytes with a prefix that includes
    ``stdin``. We match loosely because the exact scheme has
    varied across angr versions (``file_0_stdin_...``,
    ``stdin_...``, ``file_/dev/stdin_...``)."""
    lower = var_name.lower()
    return "stdin" in lower


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
