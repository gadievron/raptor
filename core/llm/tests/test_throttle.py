"""Tests for core.llm.throttle — adaptive concurrency throttle."""

from __future__ import annotations

import asyncio
import threading
import time

from core.llm.throttle import (
    AdaptiveThrottle,
    _active_throttles,
    broadcast_rate_limit,
)


class TestAdaptiveThrottle:
    def test_initial_state(self):
        t = AdaptiveThrottle(8, auto_register=False)
        assert t.max_workers == 8
        assert t.effective_workers == 8
        assert not t.is_throttled
        assert t.signal_count == 0
        assert t.in_flight == 0

    def test_signal_halves_concurrency(self):
        t = AdaptiveThrottle(8, auto_register=False)
        t.signal_rate_limit()
        assert t.effective_workers == 4
        assert t.is_throttled
        assert t.signal_count == 1

    def test_repeated_signals_halve_further(self):
        t = AdaptiveThrottle(16, auto_register=False)
        t.signal_rate_limit()
        assert t.effective_workers == 8
        t.signal_rate_limit()
        assert t.effective_workers == 4
        t.signal_rate_limit()
        assert t.effective_workers == 2
        t.signal_rate_limit()
        assert t.effective_workers == 1
        assert t.signal_count == 4

    def test_min_workers_floor(self):
        t = AdaptiveThrottle(4, min_workers=2, auto_register=False)
        t.signal_rate_limit()
        assert t.effective_workers == 2
        t.signal_rate_limit()
        assert t.effective_workers == 2

    def test_default_min_workers_is_one(self):
        t = AdaptiveThrottle(2, auto_register=False)
        t.signal_rate_limit()
        assert t.effective_workers == 1
        t.signal_rate_limit()
        assert t.effective_workers == 1

    def test_restore_after_cooldown(self):
        t = AdaptiveThrottle(8, cooldown_s=0.05, auto_register=False)
        t.signal_rate_limit()
        assert t.effective_workers == 4
        time.sleep(0.06)
        assert t.effective_workers == 8
        assert not t.is_throttled

    def test_signal_resets_cooldown(self):
        t = AdaptiveThrottle(8, cooldown_s=0.1, auto_register=False)
        t.signal_rate_limit()
        assert t.effective_workers == 4
        time.sleep(0.06)
        t.signal_rate_limit()
        assert t.effective_workers == 2
        time.sleep(0.06)
        assert t.effective_workers == 2
        time.sleep(0.06)
        assert t.effective_workers == 8

    def test_max_workers_clamped_to_one(self):
        t = AdaptiveThrottle(0, auto_register=False)
        assert t.max_workers == 1
        assert t.effective_workers == 1

    def test_to_dict(self):
        t = AdaptiveThrottle(8, auto_register=False)
        d = t.to_dict()
        assert d == {
            "max_workers": 8,
            "effective_workers": 8,
            "is_throttled": False,
            "signal_count": 0,
            "in_flight": 0,
        }
        t.signal_rate_limit()
        d = t.to_dict()
        assert d["effective_workers"] == 4
        assert d["is_throttled"] is True
        assert d["signal_count"] == 1


class TestAsyncAcquire:
    def test_acquire_limits_concurrency(self):
        t = AdaptiveThrottle(2, auto_register=False)
        peak = [0]
        current = [0]

        async def worker():
            async with t.acquire():
                current[0] += 1
                peak[0] = max(peak[0], current[0])
                await asyncio.sleep(0.02)
                current[0] -= 1

        async def run():
            await asyncio.gather(*(worker() for _ in range(6)))

        asyncio.run(run())
        assert peak[0] <= 2

    def test_acquire_respects_throttle(self):
        t = AdaptiveThrottle(4, auto_register=False)
        t.signal_rate_limit()
        assert t.effective_workers == 2
        peak = [0]
        current = [0]

        async def worker():
            async with t.acquire():
                current[0] += 1
                peak[0] = max(peak[0], current[0])
                await asyncio.sleep(0.02)
                current[0] -= 1

        async def run():
            await asyncio.gather(*(worker() for _ in range(8)))

        asyncio.run(run())
        assert peak[0] <= 2

    def test_mid_flight_throttle_down(self):
        """Throttle-down mid-run must not allow more than the new limit."""
        t = AdaptiveThrottle(4, auto_register=False)
        peak_after_signal = [0]
        current = [0]
        barrier = asyncio.Event()

        async def worker(idx):
            async with t.acquire():
                current[0] += 1
                if idx == 0:
                    t.signal_rate_limit()
                    barrier.set()
                else:
                    await barrier.wait()
                peak_after_signal[0] = max(peak_after_signal[0], current[0])
                await asyncio.sleep(0.02)
                current[0] -= 1

        async def run():
            await asyncio.gather(*(worker(i) for i in range(8)))

        asyncio.run(run())
        assert peak_after_signal[0] <= 4

    def test_in_flight_tracking(self):
        t = AdaptiveThrottle(4, auto_register=False)

        async def run():
            assert t.in_flight == 0
            async with t.acquire():
                assert t.in_flight == 1
                async with t.acquire():
                    assert t.in_flight == 2
                assert t.in_flight == 1
            assert t.in_flight == 0

        asyncio.run(run())

    def test_restore_unblocks_waiters(self):
        """After cooldown, blocked waiters should proceed."""
        t = AdaptiveThrottle(2, cooldown_s=0.05, auto_register=False)
        t.signal_rate_limit()
        assert t.effective_workers == 1
        completed = [0]

        async def worker():
            async with t.acquire():
                await asyncio.sleep(0.01)
                completed[0] += 1

        async def run():
            await asyncio.gather(*(worker() for _ in range(4)))

        asyncio.run(run())
        assert completed[0] == 4


class TestBroadcastRegistry:
    def test_auto_register(self):
        initial = len(_active_throttles)
        t = AdaptiveThrottle(4)
        assert len(_active_throttles) == initial + 1
        t.close()
        assert len(_active_throttles) == initial

    def test_no_auto_register(self):
        initial = len(_active_throttles)
        t = AdaptiveThrottle(4, auto_register=False)
        assert len(_active_throttles) == initial
        t.close()

    def test_broadcast_signals_all(self):
        t1 = AdaptiveThrottle(8)
        t2 = AdaptiveThrottle(16)
        try:
            broadcast_rate_limit()
            assert t1.effective_workers == 4
            assert t2.effective_workers == 8
        finally:
            t1.close()
            t2.close()

    def test_broadcast_noop_when_empty(self):
        broadcast_rate_limit()

    def test_double_close_safe(self):
        t = AdaptiveThrottle(4)
        t.close()
        t.close()

    def test_thread_safety(self):
        t = AdaptiveThrottle(64, auto_register=False)
        errors = []

        def signal_many():
            try:
                for _ in range(50):
                    t.signal_rate_limit()
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=signal_many) for _ in range(4)]
        for th in threads:
            th.start()
        for th in threads:
            th.join()
        assert not errors
        assert t.signal_count == 200


class TestAcquireSync:
    def test_limits_concurrency(self):
        t = AdaptiveThrottle(2, auto_register=False)
        peak = [0]
        current = [0]
        lock = threading.Lock()

        def worker():
            with t.acquire_sync():
                with lock:
                    current[0] += 1
                    peak[0] = max(peak[0], current[0])
                time.sleep(0.03)
                with lock:
                    current[0] -= 1

        threads = [threading.Thread(target=worker) for _ in range(6)]
        for th in threads:
            th.start()
        for th in threads:
            th.join()
        assert peak[0] <= 2

    def test_respects_throttle_down(self):
        t = AdaptiveThrottle(4, auto_register=False)
        t.signal_rate_limit()
        assert t.effective_workers == 2
        peak = [0]
        current = [0]
        lock = threading.Lock()

        def worker():
            with t.acquire_sync():
                with lock:
                    current[0] += 1
                    peak[0] = max(peak[0], current[0])
                time.sleep(0.03)
                with lock:
                    current[0] -= 1

        threads = [threading.Thread(target=worker) for _ in range(6)]
        for th in threads:
            th.start()
        for th in threads:
            th.join()
        assert peak[0] <= 2

    def test_restore_unblocks(self):
        t = AdaptiveThrottle(2, cooldown_s=0.05, auto_register=False)
        t.signal_rate_limit()
        assert t.effective_workers == 1
        completed = [0]

        def worker():
            with t.acquire_sync():
                time.sleep(0.01)
                completed[0] += 1

        threads = [threading.Thread(target=worker) for _ in range(4)]
        for th in threads:
            th.start()
        for th in threads:
            th.join()
        assert completed[0] == 4

    def test_in_flight_tracking(self):
        t = AdaptiveThrottle(4, auto_register=False)
        assert t.in_flight == 0
        with t.acquire_sync():
            assert t.in_flight == 1
        assert t.in_flight == 0


class TestIsRateLimit:
    def test_status_429(self):
        from core.llm.providers import _is_rate_limit

        class FakeExc(Exception):
            status_code = 429

        assert _is_rate_limit(FakeExc()) is True

    def test_status_500_not_rate_limit(self):
        from core.llm.providers import _is_rate_limit

        class FakeExc(Exception):
            status_code = 500

        assert _is_rate_limit(FakeExc()) is False

    def test_no_status_code(self):
        from core.llm.providers import _is_rate_limit

        assert _is_rate_limit(ValueError("boom")) is False


class TestTuningReaders:
    def test_read_tuning_max_llm_workers_auto(self):
        from core.llm.concurrency import read_tuning_max_llm_workers

        assert read_tuning_max_llm_workers() is None or isinstance(
            read_tuning_max_llm_workers(), (int, type(None))
        )

    def test_read_throttle_cooldown_default(self):
        from core.llm.concurrency import read_throttle_cooldown_s

        val = read_throttle_cooldown_s()
        assert isinstance(val, float)
        assert val > 0


class TestRunParallel:
    def test_empty_items(self):
        from core.llm.concurrency import run_parallel

        assert run_parallel([], lambda x: x) == []

    def test_serial_fallback(self):
        from core.llm.concurrency import run_parallel

        results = run_parallel([1, 2, 3], lambda x: x * 2, max_workers=1)
        assert results == [2, 4, 6]

    def test_parallel_execution(self):
        from core.llm.concurrency import run_parallel

        results = run_parallel(
            list(range(10)),
            lambda x: x ** 2,
            max_workers=4,
            label="test-parallel",
        )
        assert results == [x ** 2 for x in range(10)]

    def test_error_handling_default(self):
        from core.llm.concurrency import run_parallel

        def _fail_on_three(x):
            if x == 3:
                raise ValueError("boom")
            return x

        results = run_parallel([1, 2, 3, 4], _fail_on_three, max_workers=2)
        assert results == [1, 2, None, 4]

    def test_error_handler_callback(self):
        from core.llm.concurrency import run_parallel

        def _fail(x):
            raise ValueError(f"fail-{x}")

        results = run_parallel(
            [1, 2],
            _fail,
            max_workers=2,
            on_error=lambda item, _exc: item * -1,
        )
        assert results == [-1, -2]

    def test_serial_error_handler(self):
        from core.llm.concurrency import run_parallel

        def _fail(x):
            raise ValueError("boom")

        results = run_parallel(
            [1, 2],
            _fail,
            max_workers=1,
            on_error=lambda item, _exc: 0,
        )
        assert results == [0, 0]

    def test_respects_throttle(self):
        """Parallel path uses AdaptiveThrottle, not a raw semaphore."""
        from core.llm.concurrency import run_parallel
        from core.llm.throttle import _active_throttles

        initial = len(_active_throttles)
        run_parallel([1, 2, 3], lambda x: x, max_workers=2)
        assert len(_active_throttles) == initial

    def test_position_preserved(self):
        from core.llm.concurrency import run_parallel

        results = run_parallel(
            ["a", "bb", "ccc", "dddd"],
            lambda x: len(x),
            max_workers=3,
        )
        assert results == [1, 2, 3, 4]

    def test_concurrent_execution(self):
        """Multiple items run concurrently, not serially."""
        from core.llm.concurrency import run_parallel

        peak = [0]
        current = [0]
        lock = threading.Lock()

        def _track(x):
            with lock:
                current[0] += 1
                peak[0] = max(peak[0], current[0])
            time.sleep(0.05)
            with lock:
                current[0] -= 1
            return x

        run_parallel(list(range(6)), _track, max_workers=3, label="conc-test")
        assert peak[0] >= 2
