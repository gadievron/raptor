"""Builtin integer widths and promotion facts under an explicit target ABI."""

from dataclasses import dataclass
from .integer_abi import resolve_integer_abi


@dataclass(frozen=True)
class IntegerType:
    width: int
    signed: bool
    promoted_width: int
    promoted_signed: bool

    @property
    def profile(self):
        return f"{'int' if self.promoted_signed else 'uint'}{self.promoted_width}"


def integer_type(spelling, integer_abi=None):
    """Parse supported builtin integer grammar, without trusting aliases."""
    abi = resolve_integer_abi(integer_abi)
    if abi is None or not isinstance(spelling, str):
        return None

    def kind(width, signed, promote=True):
        return IntegerType(
            width,
            signed,
            abi.int_bits if promote else width,
            (signed or width < abi.int_bits) if promote else signed,
        )

    words = spelling.split()
    tokens = set(words)
    if (
        not words
        or any(words.count(word) > (2 if word == "long" else 1) for word in tokens)
        or not tokens
        <= {
            "signed",
            "unsigned",
            "char",
            "short",
            "int",
            "long",
            "bool",
            "_Bool",
        }
    ):
        return None
    if {"signed", "unsigned"} <= tokens:
        return None
    if "bool" in tokens or "_Bool" in tokens:
        return kind(1, False) if len(words) == 1 else None
    if "char" in tokens:
        if tokens not in ({"signed", "char"}, {"unsigned", "char"}):
            return None  # plain char signedness is implementation-defined
        return kind(abi.char_bits, "signed" in tokens)
    if "short" in tokens:
        return (
            kind(abi.short_bits, "unsigned" not in tokens)
            if "long" not in tokens
            else None
        )
    if "long" in tokens:
        if words.count("long") > 2:
            return None
        return kind(
            abi.long_long_bits if words.count("long") == 2 else abi.long_bits,
            "unsigned" not in tokens,
            promote=False,
        )
    return kind(abi.int_bits, "unsigned" not in tokens, promote=False)
