"""Bitvector width/signedness configuration for RAPTOR's SMT harness.

Environment:
    RAPTOR_SMT_WIDTH   - ``32`` or ``64`` (default ``64``)
    RAPTOR_SMT_SIGNED  - ``signed`` or ``unsigned`` (default ``signed``)

These are read each call so width/signedness can change between test cases
or validator passes without module reload.
"""
from __future__ import annotations

import os
from typing import Optional


def bv_width() -> int:
    """Default bitvector width. Only 32 or 64 are honoured; anything else → 64."""
    try:
        w = int(os.environ.get("RAPTOR_SMT_WIDTH", "64"))
    except ValueError:
        return 64
    return w if w in (32, 64) else 64


def is_signed() -> bool:
    """Default bitvector signedness (True for signed, False for unsigned)."""
    return os.environ.get("RAPTOR_SMT_SIGNED", "signed").lower() != "unsigned"


def mode_tag(width: Optional[int] = None, signed: Optional[bool] = None) -> str:
    """Human-readable mode tag like ``bv64-signed`` (for reasoning strings)."""
    w = width if width is not None else bv_width()
    s = signed if signed is not None else is_signed()
    return f"bv{w}-{'signed' if s else 'unsigned'}"
