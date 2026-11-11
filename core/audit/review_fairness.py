"""Persistent admission opportunities for first reviews and continuations.

The queue does not dispatch work, wait for results, or promise completion
latency. Its owner supplies only dependency-ready work and owns its lock.
"""

from __future__ import annotations

import heapq
import math
from dataclasses import dataclass

_INITIALS_PER_CONTINUATION = 3
_PRIORITY_BOOST_LIMIT = 3.0
_POLICY_VERSION = "review-admission-v1"


@dataclass(frozen=True)
class _Pending:
    sequence: int
    revision: int
    continuation: bool
    rank: float


class ReviewAdmissionQueue:
    """Two ready lanes with persistent 3:1 opportunities and bounded aging.

    A priority may advance an item by at most three FIFO positions. A later
    high-priority arrival therefore cannot indefinitely overtake an old
    eligible item. Reprioritisation preserves the original ready sequence.
    Empty lanes yield immediately, without resetting state on empty polls.
    """

    def __init__(self) -> None:
        self._initial: list[tuple[float, int, int, str]] = []
        self._continuation: list[tuple[float, int, int, str]] = []
        self._pending: dict[str, _Pending] = {}
        self._next_sequence = 0
        self._next_revision = 0
        self._initial_since_continuation = 0
        self._initial_admissions = 0
        self._continuation_admissions = 0
        self._initial_wait = 0
        self._continuation_wait = 0
        self._max_initial_wait = 0
        self._max_continuation_wait = 0
        self._starvation_opportunities = 0

    @staticmethod
    def _boost(priority: float) -> float:
        value = float(priority)
        if math.isnan(value) or value <= 0:
            return 0.0
        return min(value, _PRIORITY_BOOST_LIMIT)

    def push(self, key: str, priority: float, *, continuation: bool = False) -> None:
        prior = self._pending.get(key)
        sequence = prior.sequence if prior is not None else self._next_sequence
        if prior is None:
            self._next_sequence += 1
        self._next_revision += 1
        pending = _Pending(sequence, self._next_revision, continuation,
                           sequence - self._boost(priority))
        self._pending[key] = pending
        heap = self._continuation if continuation else self._initial
        heapq.heappush(heap, (pending.rank, sequence, pending.revision, key))
        # Repeated priority changes must not retain an unbounded stale heap.
        if len(heap) > max(64, 2 * len(self._pending)):
            heap[:] = [(item.rank, item.sequence, item.revision, name)
                       for name, item in self._pending.items()
                       if item.continuation is continuation]
            heapq.heapify(heap)

    def discard(self, key: str) -> None:
        self._pending.pop(key, None)

    def _peek(self, *, continuation: bool) -> str | None:
        heap = self._continuation if continuation else self._initial
        while heap:
            _rank, _sequence, revision, key = heap[0]
            pending = self._pending.get(key)
            if (pending is not None and pending.revision == revision
                    and pending.continuation is continuation):
                return key
            heapq.heappop(heap)
        return None

    def pop(self) -> str | None:
        initial = self._peek(continuation=False)
        continuation = self._peek(continuation=True)
        if initial is None and continuation is None:
            return None
        use_continuation = (continuation is not None and
                            (initial is None or self._initial_since_continuation >= _INITIALS_PER_CONTINUATION))
        if use_continuation:
            key = continuation
            heapq.heappop(self._continuation)
            self._continuation_admissions += 1
            self._initial_since_continuation = 0
            self._continuation_wait = 0
            self._initial_wait = self._initial_wait + 1 if initial is not None else 0
        else:
            key = initial
            heapq.heappop(self._initial)
            self._initial_admissions += 1
            self._initial_since_continuation = min(
                _INITIALS_PER_CONTINUATION, self._initial_since_continuation + 1)
            self._initial_wait = 0
            self._continuation_wait = self._continuation_wait + 1 if continuation is not None else 0
        self._max_initial_wait = max(self._max_initial_wait, self._initial_wait)
        self._max_continuation_wait = max(self._max_continuation_wait, self._continuation_wait)
        if self._initial_wait > 1 or self._continuation_wait > _INITIALS_PER_CONTINUATION:
            self._starvation_opportunities += 1
        assert key is not None
        self._pending.pop(key)
        return key

    def __len__(self) -> int:
        return len(self._pending)

    def state(self) -> dict[str, str | int | float]:
        """Return an independent scalar snapshot, suitable for provenance."""
        pending_continuations = sum(item.continuation for item in self._pending.values())
        return {
            "policy_version": _POLICY_VERSION,
            "initial_per_continuation": _INITIALS_PER_CONTINUATION,
            "priority_boost_limit": _PRIORITY_BOOST_LIMIT,
            "initial_admissions": self._initial_admissions,
            "continuation_admissions": self._continuation_admissions,
            "initial_since_continuation": self._initial_since_continuation,
            "pending_initial": len(self._pending) - pending_continuations,
            "pending_continuation": pending_continuations,
            "max_initial_wait_opportunities": self._max_initial_wait,
            "max_continuation_wait_opportunities": self._max_continuation_wait,
            "starvation_opportunities": self._starvation_opportunities,
        }
