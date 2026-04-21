"""Z3 model → Python dict conversion with signed-bitvector reinterpretation.

A bitvector with the high bit set, extracted under signed semantics, still
comes out of ``as_long()`` as a raw unsigned integer. RAPTOR reports
witnesses the way a human reads the C value, so these helpers reinterpret
high-bit-set values as two's-complement negatives when ``signed=True``.
"""
from __future__ import annotations

from typing import Any, Dict

from .availability import z3


def bv_to_int(raw: int, width: int, signed: bool) -> int:
    """Reinterpret an ``as_long()`` result as two's-complement when ``signed``."""
    if signed and width > 0 and raw >= (1 << (width - 1)):
        return raw - (1 << width)
    return raw


def format_witness(model: Any, signed: bool) -> Dict[str, int]:
    """Render every concrete BitVec decl in a Z3 model as ``{name: int}``."""
    out: Dict[str, int] = {}
    for decl in model.decls():
        val = model[decl]
        if not z3.is_bv_value(val):
            continue
        out[str(decl)] = bv_to_int(val.as_long(), val.size(), signed)
    return out


def format_vars(
    model: Any,
    vars_: Dict[str, Any],
    signed: bool,
    *,
    completion: bool = False,
) -> Dict[str, int]:
    """Render the caller's named variables from a Z3 model.

    Unlike ``format_witness``, this walks the caller's variable registry
    rather than the model's top-level decls — useful when free variables
    need ``model_completion=True`` to yield a concrete value.
    """
    out: Dict[str, int] = {}
    for name, var in vars_.items():
        if completion:
            val = model.eval(var, model_completion=True)
        else:
            val = model[var]
        if val is None or not z3.is_bv_value(val):
            continue
        out[name] = bv_to_int(val.as_long(), val.size(), signed)
    return out
