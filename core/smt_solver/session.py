"""Solver construction with a default timeout.

The harness caps solver queries at 5 s by default so a pathological
encoding from one finding can't stall an entire validation pass. Override
per-call via ``new_solver(timeout_ms=...)``.
"""
from __future__ import annotations

from typing import Any

from .availability import z3

DEFAULT_TIMEOUT_MS = 5000


def new_solver(timeout_ms: int = DEFAULT_TIMEOUT_MS) -> Any:
    """Return a fresh ``z3.Solver()`` with the given timeout applied."""
    s = z3.Solver()
    s.set("timeout", timeout_ms)
    return s
