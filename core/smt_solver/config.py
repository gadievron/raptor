"""Bitvector profile (width + signedness) for RAPTOR's SMT harness.

A ``BVProfile`` names the bit-width and signedness a domain encoder
uses for its path conditions / constraints / witness rendering. It's
passed as a single kwarg (rather than two separate ``width`` / ``signed``
flags) so call sites read "I'm modelling a C uint32" rather than
"width=32, signed=False".

Pre-made profiles cover common architecture register widths and C
integer types; construct ``BVProfile(width=..., signed=...)`` directly
for unusual cases.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class BVProfile:
    """Width and signedness for SMT bitvector reasoning.

    ``frozen=True`` prevents accidental mutation of shared profile
    instances (e.g. the pre-made ``BV_X86_64``) — a subtle bug class
    that bit us once already via a mutable singleton.
    """
    width: int = 64
    signed: bool = False

    def __post_init__(self):
        if self.width <= 0:
            raise ValueError(f"width must be positive, got {self.width}")

    def mode_tag(self) -> str:
        """Compact tag like ``bv64u`` / ``bv32s`` — useful when brevity matters."""
        return f"bv{self.width}{'s' if self.signed else 'u'}"

    def describe(self) -> str:
        """Human-readable description like ``"64-bit unsigned"`` / ``"32-bit signed"``.

        Used in reasoning strings shown to researchers — spells out what
        ``mode_tag()`` abbreviates.
        """
        return f"{self.width}-bit {'signed' if self.signed else 'unsigned'}"


# ---------------------------------------------------------------------------
# Pre-made profiles — name expresses the modelled type at call sites.
# ---------------------------------------------------------------------------

# Architecture register widths (address reasoning is always unsigned).
BV_X86_64    = BVProfile(width=64, signed=False)
BV_AARCH64   = BVProfile(width=64, signed=False)
BV_I386      = BVProfile(width=32, signed=False)
BV_ARM32     = BVProfile(width=32, signed=False)

# C integer types — the usual suspects for CWE-190 reasoning.
BV_C_UINT64  = BVProfile(width=64, signed=False)
BV_C_INT64   = BVProfile(width=64, signed=True)
BV_C_UINT32  = BVProfile(width=32, signed=False)
BV_C_INT32   = BVProfile(width=32, signed=True)
BV_C_UINT16  = BVProfile(width=16, signed=False)
BV_C_INT16   = BVProfile(width=16, signed=True)
BV_C_UINT8   = BVProfile(width=8, signed=False)
BV_C_INT8    = BVProfile(width=8, signed=True)
