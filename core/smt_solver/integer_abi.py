"""Explicit target integer layouts, validation and stable proof context.

No host probing, binary inspection, source parsing or audit orchestration.
"""

from dataclasses import asdict, dataclass
import re
from typing import Any


@dataclass(frozen=True)
class IntegerABI:
    name: str
    char_bits: int
    short_bits: int
    int_bits: int
    long_bits: int
    long_long_bits: int
    representation: str
    source: str = "explicit"

    def __post_init__(self):
        if self.source not in {"explicit", "host-assumption", "binary-platform"}:
            raise ValueError("unsupported integer ABI source")
        if self.representation != "twos-complement-no-padding":
            raise ValueError("unsupported integer representation")
        widths = (
            self.char_bits,
            self.short_bits,
            self.int_bits,
            self.long_bits,
            self.long_long_bits,
        )
        if not isinstance(self.name, str) or not re.fullmatch(
            r"[a-zA-Z0-9_-]{1,80}", self.name
        ):
            raise ValueError("invalid integer ABI name")
        if any(
            type(width) is not int or width not in {8, 16, 32, 64} for width in widths
        ):
            raise ValueError("unsupported integer ABI width")
        if (
            widths != tuple(sorted(widths))
            or self.int_bits < 16
            or self.long_bits < 32
            or self.long_long_bits < 64
        ):
            raise ValueError("inconsistent integer ABI widths")

    def record(self):
        return asdict(self)


IntegerABIInput = IntegerABI | str | dict[str, Any] | None

INTEGER_ABIS = {
    "ilp32": IntegerABI("ilp32", 8, 16, 32, 32, 64, "twos-complement-no-padding"),
    "lp64": IntegerABI("lp64", 8, 16, 32, 64, 64, "twos-complement-no-padding"),
    "llp64": IntegerABI("llp64", 8, 16, 32, 32, 64, "twos-complement-no-padding"),
    "ilp64": IntegerABI("ilp64", 8, 16, 64, 64, 64, "twos-complement-no-padding"),
    "i16": IntegerABI("i16", 8, 16, 16, 32, 64, "twos-complement-no-padding"),
}


def resolve_integer_abi(value: IntegerABIInput) -> IntegerABI | None:
    """Resolve explicit configuration or a validated broker record."""
    if isinstance(value, IntegerABI):
        return value
    if isinstance(value, str):
        return INTEGER_ABIS.get(value)
    if isinstance(value, dict):
        try:
            return IntegerABI(**value)
        except (TypeError, ValueError):
            return None
    return None


def integer_abi_record(value):
    abi = resolve_integer_abi(value)
    return abi.record() if abi is not None else None


def integer_abi_key(value):
    """Stable scalar cache context, including every measured width."""
    from core.json import dumps_canonical

    record = integer_abi_record(value)
    return dumps_canonical(record) if record is not None else "unknown"
