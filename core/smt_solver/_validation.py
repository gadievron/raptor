"""Input contracts shared by SMT profiles, primitives, and witness rendering."""

from typing import Any

# Z3's sort widths, extraction indices and extension counts cross unsigned
# 32-bit native arguments. ctypes otherwise reduces larger Python integers
# modulo 2**32, changing the requested formula without reporting an error.
_MAX_NATIVE_WIDTH = (1 << 32) - 1


def require_width(width: Any, *, argument: str = "width") -> int:
    """Require an exact positive width representable by the native API."""
    if type(width) is not int or width <= 0:
        raise ValueError(f"{argument} must be positive and an integer, got {width!r}")
    if width > _MAX_NATIVE_WIDTH:
        raise ValueError(f"{argument} exceeds the native unsigned 32-bit width limit")
    return width


def require_bool(value: Any, *, argument: str) -> bool:
    """A truthy configuration value must not choose arithmetic semantics."""
    if type(value) is not bool:
        raise ValueError(f"{argument} must be a boolean")
    return value


def require_bv(value: Any, *, argument: str = "operand") -> Any:
    """Require an explicit bitvector, avoiding native Python coercions."""
    from .availability import z3

    if z3 is None or not z3.is_bv(value):
        raise ValueError(f"{argument} must be a bitvector expression")
    return value


def require_bv_pair(a: Any, b: Any) -> None:
    """Binary operations need matching widths and one native context.

    Construct literals with mk_val/BitVecVal and convert widths explicitly;
    neither Python truthiness nor native truncation selects a formula here.
    """
    require_bv(a, argument="left operand")
    require_bv(b, argument="right operand")
    if a.ctx != b.ctx:
        raise ValueError("bitvector operands must share the same Z3 context")
    if a.size() != b.size():
        raise ValueError("bitvector operands must have the same width")
