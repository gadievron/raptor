"""
Token-bucket rate limiter.

GitHub's unauthenticated REST API caps a single IP at 60 requests/hour, and
OSV's public endpoint is informally bounded around 1 request/second sustained.
On the 712-CVE benchmark the reference project exhausted the GitHub quota
mid-run and failed every subsequent cascade attempt. Plan structural
invariant #7 names a rate limiter as a first-class guard alongside the disk
budget — this module is it.

Design:
- Pure token bucket (capacity, refill rate).
- `acquire()` sleeps (or raises if a timeout is set) until a token is free.
- Time source is injectable (`now` + `sleep`) so tests are deterministic and
  bench runs can swap in a monotonic clock without the module caring.
- No global singleton. The pipeline (or HTTP client wrapper) owns an instance
  per-endpoint.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Callable


class RateLimitTimeout(TimeoutError):
    pass


@dataclass
class TokenBucket:
    """Classic token bucket.

    Args:
        capacity: max burst (tokens in the bucket when full).
        refill_per_second: steady-state rate; fractional values OK.
        now: callable returning the current monotonic time (injectable).
        sleep: callable sleeping for N seconds (injectable).
    """

    capacity: float
    refill_per_second: float
    now: Callable[[], float] = time.monotonic
    sleep: Callable[[float], None] = time.sleep

    _tokens: float = field(init=False)
    _last: float = field(init=False)
    _lock: threading.Lock = field(init=False, default_factory=threading.Lock)

    def __post_init__(self) -> None:
        if self.capacity <= 0:
            raise ValueError("capacity must be > 0")
        if self.refill_per_second <= 0:
            raise ValueError("refill_per_second must be > 0")
        self._tokens = float(self.capacity)
        self._last = self.now()

    def _refill_locked(self) -> None:
        current = self.now()
        elapsed = current - self._last
        if elapsed > 0:
            self._tokens = min(
                float(self.capacity),
                self._tokens + elapsed * self.refill_per_second,
            )
            self._last = current

    def try_acquire(self, tokens: float = 1.0) -> bool:
        """Take `tokens` if available; never blocks."""
        if tokens <= 0:
            raise ValueError("tokens must be > 0")
        with self._lock:
            self._refill_locked()
            if self._tokens >= tokens:
                self._tokens -= tokens
                return True
            return False

    def acquire(self, tokens: float = 1.0, timeout: float | None = None) -> None:
        """Block until `tokens` are available (or raise on timeout).

        `timeout` is wall-clock seconds from call entry. `None` = wait forever.
        """
        if tokens <= 0:
            raise ValueError("tokens must be > 0")
        if tokens > self.capacity:
            raise ValueError("tokens exceeds bucket capacity")

        deadline = None if timeout is None else self.now() + timeout
        while True:
            with self._lock:
                self._refill_locked()
                if self._tokens >= tokens:
                    self._tokens -= tokens
                    return
                needed = tokens - self._tokens
                wait_s = needed / self.refill_per_second

            if deadline is not None:
                remaining = deadline - self.now()
                if remaining <= 0:
                    raise RateLimitTimeout(
                        f"no tokens available within {timeout:.3f}s"
                    )
                wait_s = min(wait_s, remaining)
            self.sleep(max(wait_s, 0.0))
