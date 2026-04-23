"""Width-parametric bitvector helpers for RAPTOR's SMT harness.

``BitVec`` comparisons in z3-py default to signed semantics; unsigned
variants must go through ``z3.ULE/ULT/UGE/UGT``. The wrappers in this
module route signed/unsigned through a single switch so domain encoders
don't scatter that logic throughout their own files.

These are low-level primitives — they take explicit ``width`` /
``signed`` arguments rather than reading from a global config. Domain
encoders translate a ``BVProfile`` into the per-call values once at
their entry point and thread the resulting width/signed through.
"""
from __future__ import annotations

from typing import Any

from .availability import z3


def mk_var(name: str, width: int) -> Any:
    """Create a ``BitVec`` variable at the given width."""
    return z3.BitVec(name, width)


def mk_val(v: int, width: int) -> Any:
    """Create a ``BitVecVal`` at the given width."""
    return z3.BitVecVal(v, width)


def le(a: Any, b: Any, signed: bool) -> Any:
    return a <= b if signed else z3.ULE(a, b)


def lt(a: Any, b: Any, signed: bool) -> Any:
    return a < b if signed else z3.ULT(a, b)


def ge(a: Any, b: Any, signed: bool) -> Any:
    return a >= b if signed else z3.UGE(a, b)


def gt(a: Any, b: Any, signed: bool) -> Any:
    return a > b if signed else z3.UGT(a, b)
