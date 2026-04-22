"""SMT solver framework for RAPTOR.

A thin, optional Z3 harness shared by domain encoders in ``packages/``.
Handles availability gating, bitvector configuration, signed/unsigned
comparison routing, witness extraction, and solver construction with a
default timeout.

Domain-specific encodings (sanitizer patterns, integer overflow predicates,
one-gadget constraints, ...) live in their respective ``packages/`` modules
and import primitives from here.
"""

from .availability import z3, z3_available
from .bitvec import ge, gt, le, lt, mk_val, mk_var
from .config import bv_width, is_signed, mode_tag
from .session import DEFAULT_TIMEOUT_MS, new_solver
from .witness import bv_to_int, format_vars, format_witness

__all__ = [
    "z3_available",
    "z3",
    "bv_width",
    "is_signed",
    "mode_tag",
    "mk_var",
    "mk_val",
    "le",
    "lt",
    "ge",
    "gt",
    "bv_to_int",
    "format_vars",
    "format_witness",
    "DEFAULT_TIMEOUT_MS",
    "new_solver",
]
