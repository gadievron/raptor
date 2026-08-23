"""Shared symbolic-execution substrate for RAPTOR.

Sibling to ``core/smt_solver/``: that layer holds RAPTOR's SMT
abstraction (BitVec, Bool, Solver — used by
``packages/exploit_feasibility/`` and ``packages/codeql/``); this
layer holds angr-based binary symbolic execution + concrete-input
synthesis.

Consumers (binary audit verification, ``/understand``, ``/validate``)
import from ``core.symbolic`` and never re-implement the underlying
angr calls.

Design principle: heavy lifting lives HERE (angr engine, memory
model, exploration strategy, timeout handling). Consumers get thin
typed wrappers that don't need to know about angr internals.

Trust contract: targets are ATTACKER-SUPPLIED binaries. The solver
primitives run their heavy work in a spawned child with a hard-kill
budget (:mod:`core.symbolic._isolate`) — a hostile target can drive
native solver calls past every cooperative bound, so termination is
enforced by process isolation. ``load_binary`` and ``detect_shape``
parse the target IN-PROCESS (CLE / pyelftools / pyvex — parser
attack surface, no solving); consumers analysing untrusted binaries
at scale should isolate the whole analysis like the repo's other
binary-touching tools (``core.sandbox.run``). Strings originating
from the target (symbol names, loader/exception text, source
excerpts in evidence, constraint reprs) are attacker-influenced —
see the field docstrings — and must be enveloped before any prompt
use.

Public surface: :class:`SymbolicResult` (return shape from every
entry point), :class:`BinaryInfo`, :class:`FmtstrSlot`,
:class:`ShapeDetection`; :func:`load_binary` / :func:`clear_cache`;
:func:`detect_shape` (millisecond pre-gate); the solvers
:func:`find_reaching_input`, :func:`find_overflow_reaching_input`,
:func:`extract_path_constraints`; and
:func:`discover_fmtstr_slots` / :func:`fmt_arg_index_for`. Every
solver returns a ``SymbolicResult`` — including on failure, with a
descriptive ``reason`` — never a bare value or an ImportError.
"""
from __future__ import annotations

from core.symbolic._constraints import extract_path_constraints
from core.symbolic._detect import ShapeDetection, detect_shape
from core.symbolic._fmtstr import (
    FmtstrSlot,
    discover_fmtstr_slots,
    fmt_arg_index_for,
)
from core.symbolic._overflow import find_overflow_reaching_input
from core.symbolic._project import clear_cache, load_binary
from core.symbolic._reach import find_reaching_input
from core.symbolic._types import BinaryInfo, SymbolicResult

__all__ = [
    "BinaryInfo",
    "FmtstrSlot",
    "ShapeDetection",
    "SymbolicResult",
    "clear_cache",
    "detect_shape",
    "discover_fmtstr_slots",
    "extract_path_constraints",
    "find_overflow_reaching_input",
    "find_reaching_input",
    "fmt_arg_index_for",
    "load_binary",
]
