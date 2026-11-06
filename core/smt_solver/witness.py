"""Z3 model → Python dict conversion with signed-bitvector reinterpretation.

A bitvector with the high bit set, extracted under signed semantics, still
comes out of ``as_long()`` as a raw unsigned integer. RAPTOR reports
witnesses the way a human reads the C value, so these helpers reinterpret
high-bit-set values as two's-complement negatives when ``signed=True``.
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .availability import z3
from ._validation import require_bool, require_width


def bv_to_int(raw: int, width: int, signed: bool) -> int:
    """Reinterpret an ``as_long()`` result as two's-complement when ``signed``.

    `as_long()` always returns a non-negative integer in
    ``[0, 2**width)`` for a well-formed BitVec value, but a few callers
    pass values that drifted out of range — most often:

    * `width <= 0` (a degenerate decl, e.g. from a `Const` rather than
      a `BitVec`). Pre-fix this fell through with `raw` unchanged —
      silent passthrough that masked the underlying bug (caller
      passed the wrong decl). The signed/unsigned reinterpretation
      is meaningless without a width, so a width<=0 caller is a
      programming error that should surface as ValueError just like
      the out-of-range cases below.
    * `raw` already < 0 (a previously-converted signed value being
      passed through this function twice — happens when the caller
      runs `bv_to_int(format_witness(...))` against a model of a
      model). Returning silently with a different value than the
      caller expects masks the bug; surface it as `ValueError`.
    * `raw >= 1 << width` (caller passed a value larger than the
      declared width — width/raw mismatch from a wrong decl size or
      a hand-constructed test). Same: silent truncation hides the bug.
    """
    require_width(width)
    require_bool(signed, argument="signed")
    if type(raw) is not int:
        raise ValueError("bv_to_int: raw must be an integer")
    upper = 1 << width
    if not 0 <= raw < upper:
        msg = f"bv_to_int: raw={raw} out of range [0, {upper}) for width={width}"
        raise ValueError(msg)
    if signed and raw >= (1 << (width - 1)):
        return raw - upper
    return raw


def _signedness_context(signed):
    """Snapshot explicit flags, including entries absent from this model."""
    if type(signed) is bool:
        return signed
    if not isinstance(signed, Mapping):
        raise ValueError("signed must be a boolean or a mapping of names to booleans")
    context = dict(signed)
    for name, value in context.items():
        if not isinstance(name, str):
            raise ValueError("signedness map names must be strings")
        require_bool(value, argument=f"signed[{name!r}]")
    return context


def _resolve_signedness(
    name: str,
    signed: bool | Mapping[str, bool],
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
    if not isinstance(signed, Mapping):
        raise ValueError("signed must be a boolean or a mapping of names to booleans")
    return require_bool(signed.get(name, False), argument=f"signed[{name!r}]")


def format_witness(
    model: Any,
    signed: bool | Mapping[str, bool],
) -> dict[str, int]:
    """Render every concrete BitVec decl in a Z3 model as ``{name: int}``.

    `signed` accepts either a global `bool` (legacy) or a
    `Mapping[str, bool]` per-decl signedness map (preferred for
    mixed-type constraint sets). See `_resolve_signedness`.

    Aliases for repeated names are display labels. Consumers that need
    source-variable identity should use ``format_vars`` with their own
    expression registry, not infer identity from a generated alias.
    """
    signed = _signedness_context(signed)
    declarations = model.decls()
    entries = [(decl, model[decl]) for decl in declarations]
    entries = [(decl, value) for decl, value in entries if z3.is_bv_value(value)]
    # Generated display aliases must not take any declaration's real name,
    # even when that declaration occurs later in the model's traversal.
    reserved = {str(decl) for decl in declarations}
    out: dict[str, int] = {}
    next_suffix: dict[str, int] = {}
    for decl, val in entries:
        base_name = str(decl)
        name = base_name
        if name in out:
            suffix = next_suffix.get(base_name, 1)
            while f"{base_name}__{suffix}" in reserved or f"{base_name}__{suffix}" in out:
                suffix += 1
            name = f"{base_name}__{suffix}"
            next_suffix[base_name] = suffix + 1
        out[name] = bv_to_int(
            val.as_long(), val.size(), _resolve_signedness(base_name, signed),
        )
    return out


def format_vars(
    model: Any,
    vars_: dict[str, Any],
    signed: bool | Mapping[str, bool],
    *,
    completion: bool = False,
) -> dict[str, int]:
    """Render the caller's named variables from a Z3 model.

    Unlike ``format_witness``, this walks the caller's variable registry
    rather than the model's top-level decls — useful when free variables
    need ``model_completion=True`` to yield a concrete value.

    `signed` accepts either a global `bool` (legacy) or a
    `Mapping[str, bool]` per-decl signedness map. Per-decl is
    preferred — see `_resolve_signedness`.

    `completion` semantics (default False):
      * False — `model[var]` returns None for variables Z3 didn't
        constrain. The function silently skips them. Pre-fix
        operators reading the resulting witness saw ONLY the
        constrained vars but had no signal that OTHER vars
        existed as unconstrained. A `pop_rdi_ret` solver model
        with 8 free vars and 1 constrained showed only the 1
        constrained — operators concluded the witness was
        complete and tried to apply it, missing the 7 free
        slots.
      * True — Z3 fills any unconstrained variable with an
        arbitrary concrete value (model completion). The
        returned dict is then complete but the values for
        unconstrained vars are arbitrary (a single satisfying
        assignment, not "any").

    The default stays False for back-compat. A debug-level log
    line on each silent skip lets operators investigate
    suspicious witness gaps without changing the public API.
    """
    signed = _signedness_context(signed)
    require_bool(completion, argument="completion")
    out: dict[str, int] = {}
    for name, var in vars_.items():
        val = model.eval(var, model_completion=True) if completion else model[var]
        if val is None or not z3.is_bv_value(val):
            # Pre-fix this skip was silent. Log so operators
            # tailing debug see WHICH vars went unconstrained.
            # `model[var] is None` (the unconstrained case) and
            # "not a bv_value" (the corrupt-state case) are both
            # surfaced via the same debug line — both indicate
            # the witness will be incomplete.
            try:
                from core.logging import get_logger
                get_logger(__name__).debug(
                    "format_vars: skipping %r — model[%r]=%r "
                    "(consider completion=True for model_completion semantics)",
                    name, name, val,
                )
            except Exception:  # noqa: BLE001, S110 — observability must never break witness extraction (matches core/logging emitter guards)
                pass
            continue
        out[name] = bv_to_int(
            val.as_long(), val.size(), _resolve_signedness(name, signed),
        )
    return out
