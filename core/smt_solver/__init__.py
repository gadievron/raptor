"""SMT solver framework for RAPTOR.

A thin, optional Z3 harness shared by domain encoders in ``packages/``.
Handles availability gating, bitvector primitives, signed/unsigned
comparison routing, witness extraction, and solver construction with a
default timeout.

Encoders parametrise width and signedness via ``BVProfile`` — one
handle instead of two flags, with pre-made profiles for common
architecture and C-type flavours (``BV_X86_64``, ``BV_C_UINT32``,
``BV_C_INT32``, ...).

C-semantics primitives (overflow predicates, width coercion, shift
disambiguators, casts) live in ``core.smt_solver.csem`` and are
imported directly by encoders that need them; they're deliberately not
re-exported here to keep the top-level surface small.

Domain-specific encodings (sanitizer patterns, integer overflow
predicates, one-gadget constraints, ...) live in their respective
``packages/`` modules and import primitives from here.
"""

from .availability import z3, z3_available
from .bitvec import ge, gt, le, lt, mk_val, mk_var
from .config import (
    BVProfile,
    BV_AARCH64,
    BV_ARM32,
    BV_C_INT8,
    BV_C_INT16,
    BV_C_INT32,
    BV_C_INT64,
    BV_C_UINT8,
    BV_C_UINT16,
    BV_C_UINT32,
    BV_C_UINT64,
    BV_I386,
    BV_X86_64,
)
from .explain import core_names, track
from .rejection import (
    Rejection,
    RejectionKind,
    classify_solver_unknown,
    parse_literal_value,
    propagate,
)
from .session import DEFAULT_TIMEOUT_MS, new_solver, scoped
from .witness import bv_to_int, format_vars, format_witness

__all__ = [
    # Availability
    "z3_available",
    "z3",
    # Profiles
    "BVProfile",
    "BV_X86_64",
    "BV_AARCH64",
    "BV_I386",
    "BV_ARM32",
    "BV_C_UINT64",
    "BV_C_INT64",
    "BV_C_UINT32",
    "BV_C_INT32",
    "BV_C_UINT16",
    "BV_C_INT16",
    "BV_C_UINT8",
    "BV_C_INT8",
    # Bitvec primitives
    "mk_var",
    "mk_val",
    "le",
    "lt",
    "ge",
    "gt",
    # Witness
    "bv_to_int",
    "format_vars",
    "format_witness",
    # Session
    "DEFAULT_TIMEOUT_MS",
    "new_solver",
    "scoped",
    # Unsat-core explanation
    "track",
    "core_names",
    # Structured parser rejection reasons
    "Rejection",
    "RejectionKind",
    "propagate",
    "parse_literal_value",
    "classify_solver_unknown",
]
