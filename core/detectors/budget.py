"""Shared analysis deadline and bounded dispatch for mechanical detectors."""
from __future__ import annotations

from collections.abc import Callable, Iterable, Iterator
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
import math
import subprocess
from threading import Event
from time import monotonic
from typing import Any, TypeVar

T = TypeVar('T')
R = TypeVar('R')
DEFAULT_COMPILER_SCAN_SECONDS = 300.0


def positive_seconds(value: str | float) -> float:
    seconds = float(value)
    if not math.isfinite(seconds) or seconds <= 0:
        raise ValueError('seconds must be positive and finite')
    return seconds


class WorkBudget:
    """One analysis window; tool cleanup and Python work can add overhead."""

    def __init__(self, seconds: float) -> None:
        self.seconds = positive_seconds(seconds)
        self.deadline = monotonic() + self.seconds
        self._exhausted = Event()

    def remaining(self) -> float:
        return max(0.0, self.deadline - monotonic())

    @property
    def exhausted(self) -> bool:
        return self._exhausted.is_set()

    def mark_exhausted(self) -> None:
        self._exhausted.set()

    def runner(self, run: Callable[..., Any]) -> Callable[..., Any]:
        """Recompute the remaining timeout immediately before every tool call."""
        def bounded(command, **kwargs):
            remaining = self.remaining()
            if remaining <= 0:
                self.mark_exhausted()
                raise subprocess.TimeoutExpired(command, 0)
            requested = kwargs.get('timeout')
            timeout = remaining if requested is None else min(requested, remaining)
            kwargs['timeout'] = timeout
            try:
                return run(command, **kwargs)
            except subprocess.TimeoutExpired:
                if requested is None or remaining <= requested or self.remaining() <= 0:
                    self.mark_exhausted()
                raise
        return bounded


def bounded_futures(
    items: Iterable[T], work: Callable[[T], R], *, workers: int,
    budget: WorkBudget | None = None,
) -> Iterator[tuple[T, Future[R]]]:
    """Keep at most *workers* jobs submitted; harvest active work on expiry.

    Work must pass the remaining budget to its blocking tools. This scheduler
    does not abandon live threads or their scratch directories on timeout.
    """
    workers = max(1, workers)
    iterator = iter(items)
    with ThreadPoolExecutor(max_workers=workers) as pool:
        pending: dict[Future[R], T] = {}
        finished = False
        def refill():
            nonlocal finished
            while not finished and len(pending) < workers:
                try:
                    item = next(iterator)
                except StopIteration:
                    finished = True
                    break
                if budget is not None and budget.remaining() <= 0:
                    budget.mark_exhausted()
                    finished = True
                    break
                pending[pool.submit(work, item)] = item
        refill()
        while pending:
            done, _ = wait(pending, return_when=FIRST_COMPLETED)
            for future in done:
                yield pending.pop(future), future
            refill()
