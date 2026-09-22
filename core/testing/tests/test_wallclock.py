"""Tests for core.testing.wallclock — the timing-assert helpers."""

from __future__ import annotations

import time

import pytest

from core.testing.wallclock import (
    check_wall_deadline,
    cpu_budget,
    wall_deadline,
)


class TestCpuBudget:
    def test_cheap_block_passes(self):
        with cpu_budget(5.0) as sw:
            sum(range(1000))
        assert sw.cpu_s < 5.0
        assert sw.wall_s >= 0.0

    def test_cpu_burn_past_budget_fails(self):
        # Busy-loop until the process has demonstrably burned more
        # CPU than the budget — deterministic in CPU terms.
        with pytest.raises(AssertionError, match="burned"):
            with cpu_budget(0.05, what="busy loop"):
                cpu0 = time.process_time()
                while time.process_time() - cpu0 < 0.15:
                    pass

    def test_idle_wait_does_not_charge_the_budget(self):
        # The whole point: blocked/descheduled time is not CPU time,
        # so a stall (here an honest sleep) cannot false-fail a pin.
        #
        # Bounds, both directions: the budget must sit well BELOW the
        # sleep — a regression that charges idle wait (wall time
        # leaking into cpu_s) reads charge ~= sleep and must overrun
        # it — and well ABOVE incidental in-process CPU, because
        # process_time() counts every thread in the process and a
        # parallel-tier worker's siblings (execnet pump, GC) can burst
        # tens of milliseconds during the sleep: a 0.05s budget over a
        # 0.2s sleep false-failed on a loaded runner.
        with cpu_budget(0.4) as sw:
            time.sleep(1.0)
        # Non-vacuity: the block really idled for the full sleep (a
        # short-circuited sleep would pass the budget trivially).
        assert sw.wall_s >= 0.9


class TestWallDeadline:
    def test_prompt_return_passes(self):
        with wall_deadline(10.0, code_bound_s=60.0) as sw:
            pass
        assert sw.wall_s < 10.0

    def test_slow_block_fails(self):
        with pytest.raises(AssertionError, match="served"):
            with wall_deadline(0.05, code_bound_s=300.0):
                time.sleep(0.2)

    def test_insufficient_separation_refused(self):
        # A code-side bound inside 2x of the assert bound cannot be
        # told apart from a load stall — the helper refuses it.
        with pytest.raises(ValueError, match="separation"):
            with wall_deadline(5.0, code_bound_s=8.0):
                pass


class TestCheckWallDeadline:
    def test_pre_measured_duration(self):
        check_wall_deadline(0.1, 5.0, code_bound_s=60.0)
        with pytest.raises(AssertionError, match="served"):
            check_wall_deadline(30.0, 5.0, code_bound_s=60.0)
        with pytest.raises(ValueError, match="separation"):
            check_wall_deadline(0.1, 5.0, code_bound_s=6.0)

    def test_infinite_code_bound_for_hang_regressions(self):
        # "The regression never returns" — code_bound_s=inf documents
        # it and trivially satisfies the separation contract.
        check_wall_deadline(
            0.1, 10.0, code_bound_s=float("inf"), what="drain",
        )
