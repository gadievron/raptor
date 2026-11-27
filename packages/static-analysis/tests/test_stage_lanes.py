"""Tests for ``_run_stage_lanes`` — the post-scan stage lane pool.

The quartet of post-scan stages (python-sql / cocci / graduated /
source-wrappers) runs on this helper. The contracts pinned here:

- collection order equals LANE LIST order, not completion order, so
  the caller's SARIF concatenation order never depends on scheduling;
- every lane is awaited even after one raises, and the FIRST failure
  in lane order propagates (the sequential path's error surface);
- ``sequential=True`` and single-lane inputs run inline on the
  calling thread (no pool threads at all);
- an abort escaping the collection loop itself (a Ctrl-C landing
  between result() waits) cancels QUEUED lanes instead of letting
  them start during pool shutdown.
"""

from __future__ import annotations

import importlib.util
import threading
import time
from pathlib import Path
from unittest.mock import patch

import pytest

# packages/static-analysis has a hyphen — load via importlib.
_SCANNER_PATH = Path(__file__).parent.parent / "scanner.py"
_spec = importlib.util.spec_from_file_location(
    "static_analysis_scanner_lanes", _SCANNER_PATH)
assert _spec is not None and _spec.loader is not None
_scanner_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_scanner_mod)

_run_stage_lanes = _scanner_mod._run_stage_lanes


class TestCollectionOrder:
    def test_results_keyed_and_complete(self):
        results = _run_stage_lanes(
            [("a", lambda: 1), ("b", lambda: 2), ("c", lambda: 3)],
            sequential=False, max_workers=4,
        )
        assert results == {"a": 1, "b": 2, "c": 3}

    def test_collection_order_ignores_completion_order(self):
        # The first lane finishes LAST; collection must still await it
        # first so the caller sees lane-list order.
        completion_order: list[str] = []
        release_slow = threading.Event()

        def _slow() -> str:
            release_slow.wait(timeout=10)
            completion_order.append("slow")
            return "slow-result"

        def _fast() -> str:
            completion_order.append("fast")
            release_slow.set()
            return "fast-result"

        results = _run_stage_lanes(
            [("slow", _slow), ("fast", _fast)],
            sequential=False, max_workers=4,
        )
        assert completion_order == ["fast", "slow"]
        assert list(results) == ["slow", "fast"]
        assert results == {"slow": "slow-result", "fast": "fast-result"}


class TestFailureContract:
    def test_first_failure_in_lane_order_propagates(self):
        # Both lanes fail; the later lane fails FIRST in wall time,
        # but the lane-order-first exception must propagate.
        release_early = threading.Event()

        def _early() -> None:
            release_early.wait(timeout=10)
            raise ValueError("early lane")

        def _late() -> None:
            release_early.set()
            raise RuntimeError("late lane")

        with pytest.raises(ValueError, match="early lane"):
            _run_stage_lanes(
                [("early", _early), ("late", _late)],
                sequential=False, max_workers=4,
            )

    def test_all_lanes_awaited_after_failure(self):
        # A failure must not propagate while sibling lanes still run —
        # no lane subprocess may be orphaned by an early raise.
        finished = threading.Event()

        def _fails() -> None:
            raise RuntimeError("boom")

        def _slow_success() -> int:
            time.sleep(0.2)
            finished.set()
            return 7

        with pytest.raises(RuntimeError, match="boom"):
            _run_stage_lanes(
                [("fails", _fails), ("slow", _slow_success)],
                sequential=False, max_workers=4,
            )
        assert finished.is_set()

    def test_sequential_failure_surface_matches(self):
        with pytest.raises(ValueError, match="same error"):
            _run_stage_lanes(
                [("x", lambda: (_ for _ in ()).throw(
                    ValueError("same error")))],
                sequential=True, max_workers=4,
            )

    def test_abort_escaping_collection_cancels_queued_lanes(self):
        # A Ctrl-C landing in the collection loop OUTSIDE the
        # per-future try (simulated by the loop's own failure logging
        # raising KeyboardInterrupt — the same escape path) must not
        # let a still-queued lane start during pool shutdown: the
        # finally cancels pending futures before waiting.
        started = threading.Event()
        go = threading.Event()
        third_ran = threading.Event()

        def _fails() -> None:
            raise RuntimeError("boom")

        def _parks() -> None:
            started.set()
            go.wait(timeout=10)

        def _third() -> None:
            third_ran.set()

        class _KILogger:
            def warning(self, *args: object, **kwargs: object) -> None:
                # The single worker is parked in the second lane
                # before the interrupt escapes, so the third lane is
                # still queued when the finally cancels it; the timer
                # then releases the worker so shutdown's wait returns.
                assert started.wait(timeout=10)
                threading.Timer(1.0, go.set).start()
                raise KeyboardInterrupt

        with patch.object(_scanner_mod, "logger", _KILogger()), \
                pytest.raises(KeyboardInterrupt):
            _run_stage_lanes(
                [("fails", _fails), ("parks", _parks), ("third", _third)],
                sequential=False, max_workers=1,
            )
        assert not third_ran.is_set()

    def test_shutdown_cancels_queued_futures_in_source(self):
        # The pool must NOT be context-managed: __exit__ is
        # shutdown(wait=True) without cancel_futures, which lets
        # queued lanes start and run to completion behind an abort.
        source = _SCANNER_PATH.read_text(encoding="utf-8")
        body = source[source.index("def _run_stage_lanes("):
                      source.index("def run_python_sql_stage(")]
        assert "pool.shutdown(wait=True, cancel_futures=True)" in body
        assert "with ThreadPoolExecutor" not in body


class TestInlineExecution:
    def test_sequential_runs_on_calling_thread(self):
        threads: list[str] = []

        def _lane() -> None:
            threads.append(threading.current_thread().name)

        caller = threading.current_thread().name
        _run_stage_lanes(
            [("a", _lane), ("b", _lane)],
            sequential=True, max_workers=4,
        )
        assert threads == [caller, caller]

    def test_single_lane_runs_inline(self):
        threads: list[str] = []

        def _lane() -> int:
            threads.append(threading.current_thread().name)
            return 42

        caller = threading.current_thread().name
        results = _run_stage_lanes(
            [("only", _lane)], sequential=False, max_workers=4,
        )
        assert results == {"only": 42}
        assert threads == [caller]

    def test_pool_width_respects_max_workers(self):
        # max_workers=1 serialises the pool: no two lanes overlap.
        active = 0
        peak = 0
        lock = threading.Lock()

        def _lane() -> None:
            nonlocal active, peak
            with lock:
                active += 1
                peak = max(peak, active)
            time.sleep(0.05)
            with lock:
                active -= 1

        _run_stage_lanes(
            [("a", _lane), ("b", _lane), ("c", _lane)],
            sequential=False, max_workers=1,
        )
        assert peak == 1


class TestMergeOrderPinned:
    """combined.sarif input order is a source-level contract."""

    def test_sarif_concatenation_order_is_fixed_in_source(self):
        # The concatenation below has golden-file consumers
        # (test_sarif_golden.py); lane parallelism must never reorder
        # it. Pin the exact source expression.
        source = _SCANNER_PATH.read_text(encoding="utf-8")
        assert (
            "semgrep_sarifs + codeql_sarifs + cocci_sarifs\n"
            "            + compiler_sarifs + expanded_sarifs + graduated_sarifs\n"
            "            + config_resolved_sarifs + source_wrapper_sarifs + python_sql_sarifs"
        ) in source

    def test_lane_group_collects_in_fixed_order(self):
        source = _SCANNER_PATH.read_text(encoding="utf-8")
        group = source.index("_lane_results = _run_stage_lanes(")
        block = source[group:group + 600]
        for name in ('"python-sql"', '"cocci"', '"graduated"',
                     '"source-wrappers"'):
            assert name in block
