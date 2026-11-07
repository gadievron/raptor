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
        # process_time counts every thread. Isolate the idle control from
        # serving threads left running by other tests in a shuffled worker.
        import subprocess
        import sys
        result = subprocess.run(
            [sys.executable, "-c", """
import time
from pytest import MonkeyPatch
from core.testing.module_bindings import patch_module_attribute
import core.testing.wallclock as consumer
# Preserve the original 2.5x sleep/budget separation.
with consumer.cpu_budget(0.04) as sw:
    time.sleep(0.1)
assert sw.wall_s >= 0.09, sw.wall_s
shared_cpu_clock = time.process_time
with MonkeyPatch.context() as scope:
    patch_module_attribute(scope, consumer, "time", "process_time", time.perf_counter)
    # A wall-clock substitution must charge the same idle wait and fail.
    try:
        with consumer.cpu_budget(0.04):
            time.sleep(0.1)
    except AssertionError as error:
        assert "burned" in str(error), str(error)
    else:
        raise AssertionError("wall-clock CPU measurement passed")
    assert time.process_time is shared_cpu_clock
assert consumer.time is time
"""],
            capture_output=True, text=True, timeout=15,
        )
        assert result.returncode == 0, result.stdout + result.stderr



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
