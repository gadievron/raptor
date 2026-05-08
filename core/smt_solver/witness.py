"""Z3 model → Python dict conversion with signed-bitvector reinterpretation.

A bitvector with the high bit set, extracted under signed semantics, still
comes out of ``as_long()`` as a raw unsigned integer. RAPTOR reports
witnesses the way a human reads the C value, so these helpers reinterpret
high-bit-set values as two's-complement negatives when ``signed=True``.
"""
from __future__ import annotations

from typing import Any, Dict, Mapping, Optional, Union

from .availability import z3


def bv_to_int(raw: int, width: int, signed: bool) -> int:
    """Reinterpret an ``as_long()`` result as two's-complement when ``signed``.

    `as_long()` always returns a non-negative integer in
    ``[0, 2**width)`` for a well-formed BitVec value, but a few callers
    pass values that drifted out of range — most often:

    * `width <= 0` (a degenerate decl, e.g. from a `Const` rather than
      a `BitVec`); fall through with `raw` unchanged.
    * `raw` already < 0 (a previously-converted signed value being
      passed through this function twice — happens when the caller
      runs `bv_to_int(format_witness(...))` against a model of a
      model). Returning silently with a different value than the
      caller expects masks the bug; surface it as `ValueError`.
    * `raw >= 1 << width` (caller passed a value larger than the
      declared width — width/raw mismatch from a wrong decl size or
      a hand-constructed test). Same: silent truncation hides the bug.
    """
    if width <= 0:
        return raw
    upper = 1 << width
    if not 0 <= raw < upper:
        raise ValueError(
            f"bv_to_int: raw={raw} out of range [0, {upper}) for width={width}"
        )
    if signed and raw >= (1 << (width - 1)):
        return raw - upper
    return raw


def _resolve_signedness(
    name: str,
    signed: Union[bool, Mapping[str, bool]],
) -> bool:
    """Resolve per-decl signedness from either a bool default or a map.

    Pre-fix `format_witness` / `format_vars` took a single `signed:
    bool` that applied to ALL decls. Real constraint sets mix
    signed / unsigned types — `int` is signed, `unsigned int` is
    not, `size_t` is unsigned, `ssize_t` is signed. A single
    bool forced wrong rendering for half the variables in any
    realistic mixed-type program.

    Accept either:
    * `bool` — uniform signedness for every decl (legacy callers
      stay correct)
    * `Mapping[str, bool]` — per-decl override; unmapped names
      fall back to `False` (unsigned, the safer default for
      bit-pattern interpretation since it never re-interprets a
      high-bit-set value as negative without explicit operator
      consent).
    """
    if isinstance(signed, bool):
        return signed
    return bool(signed.get(name, False))


def format_witness(
    model: Any,
    signed: Union[bool, Mapping[str, bool]],
) -> Dict[str, int]:
    """Render every concrete BitVec decl in a Z3 model as ``{name: int}``.

    `signed` accepts either a global `bool` (legacy) or a
    `Mapping[str, bool]` per-decl signedness map (preferred for
    mixed-type constraint sets). See `_resolve_signedness`.
    """
    out: Dict[str, int] = {}
    for decl in model.decls():
        val = model[decl]
        if not z3.is_bv_value(val):
            continue
        name = str(decl)
        out[name] = bv_to_int(
            val.as_long(), val.size(), _resolve_signedness(name, signed),
        )
    return out


def format_vars(
    model: Any,
    vars_: Dict[str, Any],
    signed: Union[bool, Mapping[str, bool]],
    *,
    completion: bool = False,
) -> Dict[str, int]:
    """Render the caller's named variables from a Z3 model.

    Unlike ``format_witness``, this walks the caller's variable registry
    rather than the model's top-level decls — useful when free variables
    need ``model_completion=True`` to yield a concrete value.

    `signed` accepts either a global `bool` (legacy) or a
    `Mapping[str, bool]` per-decl signedness map. Per-decl is
    preferred — see `_resolve_signedness`.
    """
    out: Dict[str, int] = {}
    for name, var in vars_.items():
        if completion:
            val = model.eval(var, model_completion=True)
        else:
            val = model[var]
        if val is None or not z3.is_bv_value(val):
            continue
        out[name] = bv_to_int(
            val.as_long(), val.size(), _resolve_signedness(name, signed),
        )
    return out
