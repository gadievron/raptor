"""Scalar contracts shared by SMT profiles, primitives, and witness rendering."""

from typing import Any


def require_width(width: Any, *, argument: str = "width") -> int:
    """Booleans, floats, and numeric strings are not bit widths."""
    if type(width) is not int or width <= 0:
        raise ValueError(f"{argument} must be positive and an integer, got {width!r}")
    return width


def require_bool(value: Any, *, argument: str) -> bool:
    """A truthy configuration value must not choose arithmetic semantics."""
    if type(value) is not bool:
        raise ValueError(f"{argument} must be a boolean")
    return value
