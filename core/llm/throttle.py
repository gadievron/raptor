"""Adaptive concurrency throttle for LLM API calls.

When a worker receives a 429 (rate-limit) response, it signals the
throttle which temporarily halves the effective concurrency.  After a
cooldown period without further 429s, concurrency restores to the
original level.  This prevents the stampede where N workers all hit
429 simultaneously, each independently backing off while the semaphore
keeps dispatching at full rate.

Thread-safe: multiple workers can signal concurrently from provider
threads.  The concurrency gate uses a counter + asyncio.Event so
throttle-down takes effect immediately for *all* new acquisitions —
there is no stale-semaphore-reference problem.

Usage with asyncio (executor)::

    throttle = AdaptiveThrottle(max_workers=8)

    async with throttle.acquire():
        result = await do_llm_call()

    # in the provider's retry loop, on 429:
    from core.llm.throttle import broadcast_rate_limit
    broadcast_rate_limit()

Usage standalone (serial loops)::

    throttle = AdaptiveThrottle(max_workers=4)
    throttle.signal_rate_limit()  # halves to 2
    throttle.effective_workers    # 2
    # after cooldown_s with no signals → restores to 4
"""

from __future__ import annotations

import asyncio
import logging
import threading
import time
from contextlib import asynccontextmanager, contextmanager
from typing import AsyncIterator, Iterator

logger = logging.getLogger(__name__)

_DEFAULT_COOLDOWN_S = 30.0
_MIN_WORKERS = 1


class AdaptiveThrottle:
    """Dynamically adjusts concurrency in response to rate-limit signals.

    Correctness invariant: ``_in_flight`` never exceeds ``_effective``.
    Unlike a semaphore-replacement design, throttle-down takes effect
    immediately — new ``acquire()`` calls block until in-flight drops
    below the *current* effective level, even if the level changed
    while they were waiting.

    Parameters
    ----------
    max_workers:
        The baseline (maximum) concurrency.  Restored after cooldown.
    cooldown_s:
        Seconds after the last 429 signal before restoring concurrency.
    min_workers:
        Floor — never reduce below this.
    """

    def __init__(
        self,
        max_workers: int,
        *,
        cooldown_s: float = _DEFAULT_COOLDOWN_S,
        min_workers: int = _MIN_WORKERS,
        auto_register: bool = True,
    ) -> None:
        self._max_workers = max(max_workers, 1)
        self._cooldown_s = cooldown_s
        self._min_workers = max(min_workers, 1)

        self._lock = threading.Lock()
        self._effective = self._max_workers
        self._last_signal: float = 0.0
        self._signal_count: int = 0
        self._in_flight: int = 0

        self._event: asyncio.Event | None = None
        self._condition = threading.Condition(self._lock)

        self._registered = False
        if auto_register:
            _register(self)
            self._registered = True

    def close(self) -> None:
        """Unregister from the broadcast registry."""
        if self._registered:
            _unregister(self)
            self._registered = False

    @property
    def max_workers(self) -> int:
        return self._max_workers

    @property
    def effective_workers(self) -> int:
        self._maybe_restore()
        return self._effective

    @property
    def is_throttled(self) -> bool:
        self._maybe_restore()
        return self._effective < self._max_workers

    @property
    def signal_count(self) -> int:
        return self._signal_count

    @property
    def in_flight(self) -> int:
        return self._in_flight

    def signal_rate_limit(self) -> None:
        """Called when a 429 is received.

        Halves effective concurrency (floored at min_workers) and
        resets the cooldown timer.  Does NOT touch the asyncio event —
        the ``acquire()`` loop checks ``_in_flight < _effective``
        under the lock on each iteration, so a reduced ``_effective``
        takes effect immediately for new entrants.  Clearing the event
        here would race with ``event.set()`` in ``acquire()``'s
        finally block.

        Wakes sync waiters (``acquire_sync``) so they re-evaluate
        ``_in_flight < _effective`` under the new limit — without the
        notify, a thread blocked at ``_condition.wait()`` would sleep
        through the reduction and only wake on the next release.
        """
        with self._condition:
            self._last_signal = time.monotonic()
            self._signal_count += 1
            old = self._effective
            self._effective = max(self._effective // 2, self._min_workers)
            if self._effective != old:
                logger.info(
                    "throttle: 429 signal — concurrency %d → %d "
                    "(cooldown %.0fs)",
                    old, self._effective, self._cooldown_s,
                )
            self._condition.notify_all()

    def _maybe_restore(self) -> None:
        """Restore concurrency if cooldown has elapsed since last signal.

        Called from ``acquire()`` (event-loop thread), ``acquire_sync()``
        (worker thread), and property accessors.  When capacity
        increases, sets the asyncio event (if present) and notifies
        sync waiters.
        """
        if self._effective >= self._max_workers:
            return
        with self._condition:
            if self._effective >= self._max_workers:
                return
            elapsed = time.monotonic() - self._last_signal
            if elapsed >= self._cooldown_s:
                old = self._effective
                self._effective = self._max_workers
                logger.info(
                    "throttle: cooldown elapsed — concurrency %d → %d",
                    old, self._effective,
                )
                if self._event is not None:
                    self._event.set()
                self._condition.notify_all()

    def _ensure_event(self) -> asyncio.Event:
        """Create the asyncio.Event on first use (must be called from
        the event loop thread)."""
        with self._lock:
            if self._event is None:
                self._event = asyncio.Event()
                self._event.set()
            return self._event

    @asynccontextmanager
    async def acquire(self) -> AsyncIterator[None]:
        """Acquire a concurrency slot, respecting the current effective level.

        Blocks until ``_in_flight < _effective``.  On exit, decrements
        ``_in_flight`` and wakes any waiters.  Because the check reads
        ``_effective`` fresh each time, a throttle-down mid-wait
        correctly delays new entrants.
        """
        self._maybe_restore()
        event = self._ensure_event()
        while True:
            await event.wait()
            with self._lock:
                if self._in_flight < self._effective:
                    self._in_flight += 1
                    if self._in_flight >= self._effective:
                        event.clear()
                    break
        try:
            yield
        finally:
            with self._lock:
                self._in_flight -= 1
                if self._in_flight < self._effective:
                    event.set()

    @contextmanager
    def acquire_sync(self) -> Iterator[None]:
        """Synchronous blocking counterpart of ``acquire()``.

        For use in ``ThreadPoolExecutor`` worker threads — blocks the
        calling thread (via ``threading.Condition.wait()``) until a
        concurrency slot is available.  On exit, releases the slot
        and wakes one waiter.

        ``_maybe_restore`` cannot be called while holding
        ``_condition`` (it acquires the same underlying lock, and
        ``threading.Lock`` is non-reentrant).  Instead we call it
        before entering the wait loop and after each timeout expiry
        (the ``wait()`` releases the lock internally, so
        ``_maybe_restore`` runs outside the held region).
        """
        while True:
            self._maybe_restore()
            with self._condition:
                if self._in_flight < self._effective:
                    self._in_flight += 1
                    break
                self._condition.wait(timeout=0.5)
        try:
            yield
        finally:
            with self._condition:
                self._in_flight -= 1
                self._condition.notify()

    def to_dict(self) -> dict:
        self._maybe_restore()
        return {
            "max_workers": self._max_workers,
            "effective_workers": self._effective,
            "is_throttled": self._effective < self._max_workers,
            "signal_count": self._signal_count,
            "in_flight": self._in_flight,
        }


# ── module-level signal registry ──────────────────────────────────────
#
# Providers call ``broadcast_rate_limit()`` when they see a 429.
# Active throttles register themselves so they receive the signal
# without the provider needing a reference to the throttle instance.

_active_throttles: list[AdaptiveThrottle] = []
_registry_lock = threading.Lock()


def _register(throttle: AdaptiveThrottle) -> None:
    with _registry_lock:
        _active_throttles.append(throttle)


def _unregister(throttle: AdaptiveThrottle) -> None:
    with _registry_lock:
        try:
            _active_throttles.remove(throttle)
        except ValueError:
            pass


def broadcast_rate_limit() -> None:
    """Signal all active throttles that a 429 was received.

    Called by provider retry loops.  Safe to call when no throttle
    is active (no-op).
    """
    with _registry_lock:
        targets = list(_active_throttles)
    for t in targets:
        t.signal_rate_limit()
