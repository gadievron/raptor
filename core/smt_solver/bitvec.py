"""Width-parametric bitvector helpers for RAPTOR's SMT harness.

``BitVec`` comparisons in z3-py default to signed semantics; unsigned
variants must go through ``z3.ULE/ULT/UGE/UGT``. The wrappers in this
module route signed/unsigned through a single switch so domain encoders
don't scatter that logic throughout their own files.

Default-width helpers read ``config.bv_width()`` / ``config.is_signed()``.
Pass ``width`` / ``signed`` explicitly when modeling an expression at a
non-default configuration (for example, an ``unsigned int`` sink at bv32
while the global mode is bv64).
"""
from __future__ import annotations

from typing import Any, Optional

from .availability import z3
from .config import bv_width, is_signed


def mk_var(name: str, width: Optional[int] = None) -> Any:
    """Create a ``BitVec`` variable (default width = ``bv_width()``)."""
    return z3.BitVec(name, width if width is not None else bv_width())


def mk_val(v: int, width: Optional[int] = None) -> Any:
    """Create a ``BitVecVal`` (default width = ``bv_width()``)."""
    return z3.BitVecVal(v, width if width is not None else bv_width())


def le(a: Any, b: Any, signed: Optional[bool] = None) -> Any:
    s = is_signed() if signed is None else signed
    return a <= b if s else z3.ULE(a, b)


def lt(a: Any, b: Any, signed: Optional[bool] = None) -> Any:
    s = is_signed() if signed is None else signed
    return a < b if s else z3.ULT(a, b)


def ge(a: Any, b: Any, signed: Optional[bool] = None) -> Any:
    s = is_signed() if signed is None else signed
    return a >= b if s else z3.UGE(a, b)


def gt(a: Any, b: Any, signed: Optional[bool] = None) -> Any:
    s = is_signed() if signed is None else signed
    return a > b if s else z3.UGT(a, b)
