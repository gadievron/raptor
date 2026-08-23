"""Return-shape dataclasses for the symbolic substrate.

Consumers observe angr through these types — they never touch
``angr.Project`` or ``claripy.Solver`` directly. Keeps the LLM-
facing surface stable across angr version bumps and prevents each
consumer from reinventing "how do I dump a symbolic state" ad-hoc.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass(frozen=True)
class BinaryInfo:
    """Metadata about a loaded binary — what a consumer needs to
    reason about symex without needing the ``angr.Project`` handle.

    Every field is populated by :func:`load_binary` at load time.
    ``symbols`` is intentionally a snapshot, not a live view: the
    project may resolve additional symbols lazily; consumers that
    need the fresh set should re-load.
    """

    path: Path
    """Path passed to :func:`load_binary`."""

    arch_name: str
    """Human-readable arch (e.g. ``AMD64``, ``ARMEL``). From
    ``angr.Project.arch.name``."""

    bits: int
    """Word width: 32 or 64."""

    entry_point: int
    """Address of the ELF entry point (``_start`` for a typical
    static binary; loader entry for dynamic). Not necessarily
    ``main``."""

    is_pie: bool
    """True when the binary is position-independent (ELF Type=DYN).
    Consumers use this to decide whether static-address analysis
    applies."""

    symbols: dict[str, int]
    """``{symbol_name: rebased_address}`` snapshot. Includes only
    resolved defined symbols; skip-listed ones (weak / undefined /
    imported) are absent."""


@dataclass(frozen=True)
class SymbolicResult:
    """Outcome of a symex operation.

    ``succeeded`` is the only field consumers should branch on. The
    remaining fields carry evidence / debugging context.

    For ``find_reaching_input``: ``concrete_input`` is the stdin
    bytes that drive the target from entry to the requested target
    address; ``None`` when ``succeeded`` is ``False``.
    """

    succeeded: bool
    """True when the symex operation returned a positive result
    (path found, constraints extracted, input synthesised)."""

    reason: str
    """Human-readable summary. Populated on both success and
    failure — reads as ``"found reaching input"``, ``"timeout
    after N.Ns"``, ``"no path to target"``, ``"target address
    outside binary"``, etc.

    UNTRUSTED CONTENT: failure reasons may embed loader/solver
    exception text quoting bytes from a malformed target. Envelope
    before prompt use."""

    wall_seconds: float
    """Wall-clock time spent inside angr for this operation. Bounded
    by the ``timeout`` parameter callers pass; the actual value
    reported here may be slightly above ``timeout`` because angr
    checks the budget between steps, not mid-step."""

    concrete_input: Optional[bytes] = None
    """Concrete stdin bytes for ``find_reaching_input`` success. Not
    populated for other operation types; None on failure."""

    states_explored: int = 0
    """Diagnostic: how many angr states the exploration visited.
    Useful for spotting explosion (millions) vs quick failure
    (zero). Populated on both success and failure paths."""

    metadata: dict = field(default_factory=dict)
    """Free-form additional evidence — populated per-operation. For
    ``find_reaching_input``: may include ``target_address``,
    ``path_length_bytes``. For other ops: whatever the operation
    considers useful debugging context.

    UNTRUSTED CONTENT: values may carry target-derived strings
    (constraint reprs, symbol names, object basenames). Envelope
    before prompt use."""
