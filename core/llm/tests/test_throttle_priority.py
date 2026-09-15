"""Low-priority acquisition on AdaptiveThrottle.

Background work (study batches) takes the contended slot only when no
normal-priority caller is waiting — review calls always win.
"""

from __future__ import annotations

import threading
import time

from core.llm.throttle import AdaptiveThrottle


class TestLowPriorityAcquire:
    def test_uncontended_low_priority_acquires(self):
        throttle = AdaptiveThrottle(2, auto_register=False)
        with throttle.acquire_sync(low_priority=True):
            assert throttle.in_flight == 1
        assert throttle.in_flight == 0

    def test_default_behaviour_unchanged(self):
        throttle = AdaptiveThrottle(1, auto_register=False)
        with throttle.acquire_sync():
            assert throttle.in_flight == 1
        assert throttle.in_flight == 0

    def test_normal_waiter_beats_low_priority(self):
        """With one slot held, a blocked normal waiter acquires the
        freed slot before a concurrently blocked low-priority waiter."""
        throttle = AdaptiveThrottle(1, auto_register=False)
        order: list[str] = []
        release_first = threading.Event()
        normal_waiting = threading.Event()
        low_started = threading.Event()

        def holder():
            with throttle.acquire_sync():
                order.append("holder")
                # Wait until both contenders are queued.
                normal_waiting.wait(timeout=5)
                low_started.wait(timeout=5)
                release_first.wait(timeout=5)

        def normal():
            normal_waiting.set()
            with throttle.acquire_sync():
                order.append("normal")
                time.sleep(0.05)

        def low():
            low_started.set()
            with throttle.acquire_sync(low_priority=True):
                order.append("low")

        t_holder = threading.Thread(target=holder)
        t_holder.start()
        # Let the holder take the slot first.
        for _ in range(100):
            if throttle.in_flight == 1:
                break
            time.sleep(0.01)

        t_normal = threading.Thread(target=normal)
        t_low = threading.Thread(target=low)
        t_low.start()
        t_normal.start()
        # Positive checkpoint instead of a fixed sleep: the strict
        # order assert below is only valid once the NORMAL contender
        # has registered itself (low-priority defers only while
        # ``_sync_waiters > 0``); on a loaded box a fixed 0.3s window
        # let low legitimately win the freed slot. Single read per
        # check — ``_sync_waiters`` transiently drops to 0 on every
        # bounded-wait cycle (same pattern as test_throttle.py's
        # blocked checkpoint).
        deadline = time.monotonic() + 5.0
        observed = throttle._sync_waiters
        while observed == 0 and time.monotonic() < deadline:
            time.sleep(0.005)
            observed = throttle._sync_waiters
        assert observed >= 1
        release_first.set()

        for t in (t_holder, t_normal, t_low):
            t.join(timeout=10)

        assert order[0] == "holder"
        assert order[1] == "normal", (
            f"normal-priority waiter must win the freed slot; "
            f"acquisition order was {order}"
        )
        assert order[2] == "low"

    def test_low_priority_not_starved_forever(self):
        """Once normal waiters drain, the low-priority caller gets in."""
        throttle = AdaptiveThrottle(1, auto_register=False)
        acquired = threading.Event()
        attempted = threading.Event()

        def low():
            with throttle.acquire_sync(low_priority=True):
                acquired.set()

        with throttle.acquire_sync():
            # Low-priority waiters don't register in _sync_waiters, so
            # observe the contender through the acquire loop's own
            # _maybe_restore call (its first statement per iteration).
            # The former fixed 0.1s window passed vacuously when the
            # thread hadn't even started; the probe proves at least
            # one acquisition pass ran while the slot was held —
            # in_flight == effective makes the negative assert exact.
            orig_restore = throttle._maybe_restore

            def probe() -> None:
                attempted.set()
                orig_restore()

            throttle._maybe_restore = probe  # type: ignore[method-assign]
            t = threading.Thread(target=low)
            t.start()
            assert attempted.wait(timeout=10), (
                "low-priority contender never reached the acquire loop"
            )
            assert not acquired.is_set()
        t.join(timeout=10)
        assert acquired.is_set()

    def test_throttle_down_applies_to_low_priority(self):
        throttle = AdaptiveThrottle(
            4, auto_register=False, cooldown_s=60,
        )
        throttle.signal_rate_limit()  # 4 → 2
        assert throttle.effective_workers == 2
        with throttle.acquire_sync(low_priority=True), \
                throttle.acquire_sync(low_priority=True):
            assert throttle.in_flight == 2
