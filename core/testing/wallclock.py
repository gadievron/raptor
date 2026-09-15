"""Load-tolerant timing asserts for tests.

Wall-clock upper bounds in tests measure the RUNNER, not the code: a
1-2s scheduler stall is routine on a loaded CI host (and normal under
``pytest -n 16``), so any tight ``elapsed < N`` assert false-fails
under load sooner or later. Two replacement shapes, picked by what
the test actually pins:

* :func:`cpu_budget` — algorithmic-complexity pins ("hostile input
  must not go quadratic / backtrack catastrophically"). Measure
  ``time.process_time()`` (CPU actually burned by this process, all
  threads, user+system) instead of wall clock: a starved runner does
  not advance CPU time, while the complexity regression the pin
  exists to catch still burns it. Only for in-process work — child
  processes' CPU is invisible to ``process_time``.

* :func:`wall_deadline` — the CODE under test enforces a timeout /
  deadline and the test proves prompt return. Wall clock IS the
  property there, so it stays — but the assert bound must sit with
  wide separation on BOTH sides: several seconds of load headroom
  above the expected prompt return, and well below the code-side
  bound whose service would be the regression. Callers push the
  code-side timeout far past the test window (e.g. 60-300s) so the
  gap is unmissable; ``code_bound_s`` documents and enforces that
  separation.

Both raise ``AssertionError`` with the measured numbers so a genuine
failure is diagnosable from the CI log alone.
"""

from __future__ import annotations

import time
from contextlib import contextmanager
from typing import Iterator


class Stopwatch:
    """Wall + CPU readings for the enclosed block (filled on exit)."""

    wall_s: float = 0.0
    cpu_s: float = 0.0


def check_wall_deadline(
    elapsed_s: float,
    seconds: float,
    *,
    code_bound_s: float,
    what: str = "operation",
) -> None:
    """Function form of :func:`wall_deadline` for pre-measured
    durations (e.g. a subprocess probe that prints its own elapsed).
    Same separation contract: the code-side bound must sit at least
    2x past the assert bound."""
    if code_bound_s < 2 * seconds:
        raise ValueError(
            f"check_wall_deadline needs separation: code_bound_s="
            f"{code_bound_s} must be >= 2x the assert bound {seconds} "
            f"(push the code-side timeout out of the test window)"
        )
    assert elapsed_s < seconds, (
        f"{what} took {elapsed_s:.2f}s wall (budget {seconds}s, "
        f"code-side bound {code_bound_s}s) — the code likely served "
        f"its own timeout instead of returning promptly"
    )


@contextmanager
def cpu_budget(seconds: float, what: str = "operation") -> Iterator[Stopwatch]:
    """Assert the block burns less than *seconds* of process CPU time.

    For complexity pins on in-process work. Immune to scheduler
    stalls (a descheduled process accumulates no CPU), so the budget
    can stay tight enough to catch the regression it pins. The wall
    reading rides along in the failure message for diagnosis.
    """
    sw = Stopwatch()
    wall0 = time.perf_counter()
    cpu0 = time.process_time()
    yield sw
    sw.cpu_s = time.process_time() - cpu0
    sw.wall_s = time.perf_counter() - wall0
    assert sw.cpu_s < seconds, (
        f"{what} burned {sw.cpu_s:.2f}s CPU "
        f"(wall {sw.wall_s:.2f}s), budget {seconds}s"
    )


@contextmanager
def wall_deadline(
    seconds: float,
    *,
    code_bound_s: float,
    what: str = "operation",
) -> Iterator[Stopwatch]:
    """Assert the block returns within *seconds* of wall clock.

    For prompt-return proofs where the regression is the code serving
    its own timeout (``code_bound_s``). The caller must arrange the
    code-side bound ABOVE the assert bound with real separation —
    at least 2x, so a load stall inside the assert window can never
    be confused with the code serving its bound — and *seconds*
    itself must carry seconds of headroom over the expected prompt
    return.
    """
    if code_bound_s < 2 * seconds:
        raise ValueError(
            f"wall_deadline needs separation: code_bound_s="
            f"{code_bound_s} must be >= 2x the assert bound {seconds} "
            f"(push the code-side timeout out of the test window)"
        )
    sw = Stopwatch()
    wall0 = time.perf_counter()
    cpu0 = time.process_time()
    yield sw
    sw.cpu_s = time.process_time() - cpu0
    sw.wall_s = time.perf_counter() - wall0
    check_wall_deadline(
        sw.wall_s, seconds, code_bound_s=code_bound_s, what=what,
    )
