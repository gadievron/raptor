"""Solver construction with a default timeout.

The harness caps solver queries at 5 s by default so a pathological
encoding from one finding can't stall an entire validation pass. Override
per-call via ``new_solver(timeout_ms=...)``.
"""
from __future__ import annotations

from contextlib import contextmanager
from typing import Any, Iterator

from .availability import z3

DEFAULT_TIMEOUT_MS = 5000


def new_solver(timeout_ms: int = DEFAULT_TIMEOUT_MS) -> Any:
    """Return a fresh ``z3.Solver()`` with the given timeout applied."""
    s = z3.Solver()
    s.set("timeout", timeout_ms)
    return s


@contextmanager
def scoped(solver: Any) -> Iterator[Any]:
    """Push an assertion scope on ``solver`` for the duration of the block.

    On exit (normal or exception), pops the scope — assertions added
    inside are removed, assertions from before remain. Lets domain
    encoders try hypothesis constraints and roll back cheaply without
    discarding the surrounding solver state.
    """
    solver.push()
    try:
        yield solver
    finally:
        solver.pop()
