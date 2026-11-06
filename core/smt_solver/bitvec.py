"""Width-parametric bitvector helpers for RAPTOR's SMT harness.

``BitVec`` comparisons in z3-py default to signed semantics; unsigned
variants must go through ``z3.ULE/ULT/UGE/UGT``. The wrappers in this
module route signed/unsigned through a single switch so domain encoders
don't scatter that logic throughout their own files.

Binary operations require explicit bitvectors of matching width and context.
Use mk_val to construct literal bit patterns; implicit Python coercions are
not arithmetic semantics.

These are low-level primitives — they take explicit ``width`` /
``signed`` arguments rather than reading from a global config. Domain
encoders translate a ``BVProfile`` into the per-call values once at
their entry point and thread the resulting width/signed through.
"""
from __future__ import annotations

from typing import Any

from .availability import z3
from ._validation import require_bool, require_bv_pair, require_width


def mk_var(name: str, width: int) -> Any:
    """Create a ``BitVec`` variable at the given width."""
    require_width(width)
    if not isinstance(name, str):
        raise ValueError("bitvector name must be a string")
    return z3.BitVec(name, width)


def mk_val(v: int, width: int) -> Any:
    """Create an integer bit pattern, wrapping modulo ``2**width``."""
    require_width(width)
    if type(v) is not int:
        raise ValueError("bitvector value must be an integer")
    return z3.BitVecVal(v, width)


def le(a: Any, b: Any, signed: bool) -> Any:
    require_bool(signed, argument="signed")
    require_bv_pair(a, b)
    return a <= b if signed else z3.ULE(a, b)


def lt(a: Any, b: Any, signed: bool) -> Any:
    require_bool(signed, argument="signed")
    require_bv_pair(a, b)
    return a < b if signed else z3.ULT(a, b)


def ge(a: Any, b: Any, signed: bool) -> Any:
    require_bool(signed, argument="signed")
    require_bv_pair(a, b)
    return a >= b if signed else z3.UGE(a, b)


def gt(a: Any, b: Any, signed: bool) -> Any:
    require_bool(signed, argument="signed")
    require_bv_pair(a, b)
    return a > b if signed else z3.UGT(a, b)
