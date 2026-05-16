"""
Token-bucket rate limiter tests. All deterministic — time and sleep are
injected so there is no wall-clock dependency.
"""

from __future__ import annotations

import pytest

from cve_diff.infra.rate_limit import RateLimitTimeout, TokenBucket


class FakeClock:
    """Monotonic fake clock; `sleep` advances time instead of blocking."""

    def __init__(self) -> None:
        self.t = 0.0
        self.sleep_log: list[float] = []

    def now(self) -> float:
        return self.t

    def sleep(self, s: float) -> None:
        self.sleep_log.append(s)
        self.t += s


def _bucket(capacity: float, refill: float) -> tuple[TokenBucket, FakeClock]:
    clk = FakeClock()
    return TokenBucket(
        capacity=capacity, refill_per_second=refill, now=clk.now, sleep=clk.sleep
    ), clk


class TestConstruction:
    def test_capacity_must_be_positive(self) -> None:
        with pytest.raises(ValueError):
            TokenBucket(capacity=0, refill_per_second=1.0)

    def test_refill_must_be_positive(self) -> None:
        with pytest.raises(ValueError):
            TokenBucket(capacity=10, refill_per_second=0)


class TestTryAcquire:
    def test_bucket_starts_full(self) -> None:
        bucket, _ = _bucket(capacity=3, refill=1.0)
        assert bucket.try_acquire() is True
        assert bucket.try_acquire() is True
        assert bucket.try_acquire() is True
        assert bucket.try_acquire() is False

    def test_refills_over_time(self) -> None:
        bucket, clk = _bucket(capacity=2, refill=1.0)
        assert bucket.try_acquire(2) is True
        assert bucket.try_acquire() is False
        clk.t = 1.5  # 1.5 tokens earned → 1 whole token
        assert bucket.try_acquire() is True
        assert bucket.try_acquire() is False

    def test_refill_caps_at_capacity(self) -> None:
        bucket, clk = _bucket(capacity=2, refill=10.0)
        assert bucket.try_acquire(2) is True
        clk.t = 100  # would earn 1000 tokens, but cap is 2
        assert bucket.try_acquire(2) is True
        assert bucket.try_acquire() is False


class TestAcquireBlocking:
    def test_sleeps_when_empty_then_returns(self) -> None:
        bucket, clk = _bucket(capacity=1, refill=1.0)
        bucket.try_acquire()  # drain
        bucket.acquire()  # must wait ~1s for refill
        assert clk.sleep_log[0] == pytest.approx(1.0, abs=0.01)

    def test_timeout_raises_when_no_tokens(self) -> None:
        bucket, _ = _bucket(capacity=1, refill=0.1)  # 10s per token
        bucket.try_acquire()
        with pytest.raises(RateLimitTimeout):
            bucket.acquire(timeout=0.05)

    def test_acquire_rejects_more_than_capacity(self) -> None:
        bucket, _ = _bucket(capacity=2, refill=1.0)
        with pytest.raises(ValueError):
            bucket.acquire(tokens=3)

    def test_acquire_sequential_rate(self) -> None:
        """Back-to-back acquires on a drained bucket pace at ~1/refill-rate."""
        bucket, clk = _bucket(capacity=1, refill=2.0)  # 0.5s per token
        bucket.acquire()  # immediate (bucket full)
        bucket.acquire()  # waits 0.5s
        bucket.acquire()  # waits another 0.5s
        assert clk.sleep_log == pytest.approx([0.5, 0.5], abs=0.01)
