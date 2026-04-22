"""Bitvector width/signedness configuration for RAPTOR's SMT harness.

Dataclass - SMTSolverBVConfig is the base bitvector config class. This
    gets passed around and is referenced by bv_width and is_signed. 

mode_tag returns bv(32|64)(u|s) in line with onegadgets format e.g. 'bv64u'
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Optional


@dataclass
class SMTSolverBVConfig:
    """Dataclass for SMT Solver Bitvector Config"""
    width: Literal[32, 64] = 64
    signed: bool = True

    def __post_init__(self):
        if self.width not in (32, 64):
            raise ValueError(f"width must be 32 or 64, got {self.width}")


_Z3_BVConfig = SMTSolverBVConfig()


def bv_width() -> int:
    """Get the bitvector width"""
    return _Z3_BVConfig.width


def is_signed() -> bool:
    """Get bitvector signedness"""
    return _Z3_BVConfig.signed


def mode_tag(width: Optional[int] = None, signed: Optional[bool] = None) -> str:
    """Human-readable mode tag like ``bv64u`` / ``bv32s`` (for reasoning strings)."""
    w = width  if width  is not None else _Z3_BVConfig.width
    s = signed if signed is not None else _Z3_BVConfig.signed
    return f"bv{w}{'s' if s else 'u'}"
