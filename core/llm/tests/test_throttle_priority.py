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
        # Give both contenders time to enter their wait loops.
        time.sleep(0.3)
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

        def low():
            with throttle.acquire_sync(low_priority=True):
                acquired.set()

        with throttle.acquire_sync():
            t = threading.Thread(target=low)
            t.start()
            time.sleep(0.1)
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
