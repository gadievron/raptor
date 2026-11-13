"""Strict from_dict validation helpers shared by the core/dataflow
value modules (``finding``, ``label``, ``sanitizer_evidence``).

The three modules are deliberately import-light value-type homes, so
each had grown a byte-identical copy of these two checks; the copies
live here now so the strictness contract (unknown fields REJECTED,
required strings non-empty after strip) cannot drift per module.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Mapping


def check_extra_fields(
    name: str, data: "Mapping[str, Any]", allowed: frozenset[str],
) -> None:
    """Reject unknown keys — strict schemas surface producer drift
    instead of silently dropping data."""
    extras = set(data.keys()) - allowed
    if extras:
        msg = f"unknown fields in {name} JSON: {sorted(extras)}"
        raise ValueError(msg)


def require_nonempty(label: str, value: str) -> None:
    """Reject non-string or blank-after-strip required fields."""
    if not isinstance(value, str) or not value.strip():
        msg = f"{label} must be a non-empty string"
        raise ValueError(msg)


def unique_object_fields(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Reject ambiguous object fields before strict record validation."""
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON field in dataflow record")
        result[key] = value
    return result
