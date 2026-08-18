"""Deepen/re-review dispatch at cap exhaustion — completed work is
booked, only never-dispatched work is discarded (A3).

The final comparison audit's deepen phase announced 5 re-reviews and
executed all 5, but the collection loop checked the budget BEFORE
harvesting each completed future and ``break``-ed: the two calls that
completed at/after the cap ($10.25 of finished LLM output) were thrown
away — no journal entry, no phase booking. These tests replay that
shape against the shared driver
:func:`core.audit.orchestrator._collect_reviews_until_budget`.
"""

from __future__ import annotations

import threading

from core.audit.orchestrator import _collect_reviews_until_budget


class TestParallelHarvestAtCap:
    def test_in_flight_booked_pending_cancelled(self):
        """Replay of the run's shape: the cap fires while calls are in
        flight. Already-dispatched calls (money spent, text paid for)
        are still collected when they complete; the queued item that
        never started is cancelled and never executes.

        Determinism: 2 workers, 4 items. Item 1 returns immediately;
        items 2 and 3 block both workers (released only once the cap
        has fired), so item 4 is provably still queued when the cancel
        sweep runs.
        """
        started = {2: threading.Event(), 3: threading.Event()}
        release = threading.Event()
        executed: list[int] = []

        def do_review(item):
            executed.append(item)
            if item in started:
                started[item].set()
                assert release.wait(timeout=10)
            return item

        def should_stop():
            # Called after the first harvest (item 1). Both workers
            # are (or are about to be) busy with items 2/3; wait for
            # that state so item 4 is deterministically pending, then
            # let the in-flight calls finish.
            assert started[2].wait(timeout=10)
            assert started[3].wait(timeout=10)
            release.set()
            return True

        collected = _collect_reviews_until_budget(
            [1, 2, 3, 4], do_review, should_stop, 2,
            phase_label="deepen",
        )
        assert sorted(collected) == [1, 2, 3]
        assert 4 not in executed

    def test_all_completed_results_survive_late_cap(self):
        """Results that completed before the cap check must be
        harvested — the pre-fix loop discarded them all (break before
        harvest), which is exactly the $10.25-thrown-away anomaly."""
        collected = _collect_reviews_until_budget(
            [1, 2, 3, 4, 5],
            lambda item: item,
            lambda: True,  # cap already blown when collection starts
            4,
            phase_label="deepen",
        )
        # Every non-cancelled (i.e. dispatched) call must be
        # collected; pre-fix this came back [] — completed results
        # silently dropped.
        assert collected
        for r in collected:
            assert r in [1, 2, 3, 4, 5]

    def test_no_cap_collects_everything(self):
        collected = _collect_reviews_until_budget(
            list(range(7)), lambda i: i * 10, lambda: False, 3,
            phase_label="deepen",
        )
        assert sorted(collected) == [i * 10 for i in range(7)]


class TestSingleWorkerGate:
    def test_stop_gates_before_dispatch(self):
        """Sequential mode keeps the check-before-dispatch contract: a
        call that would breach the cap is never made."""
        executed: list[int] = []
        state = {"n": 0}

        def should_stop():
            state["n"] += 1
            return state["n"] > 2  # allow two dispatches

        collected = _collect_reviews_until_budget(
            [1, 2, 3, 4],
            lambda i: (executed.append(i), i)[1],
            should_stop, 1,
            phase_label="deepen",
        )
        assert collected == [1, 2]
        assert executed == [1, 2]
