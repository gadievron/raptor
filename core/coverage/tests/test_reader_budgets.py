"""Budgets for the run/project-dir readers outside the load_json
closure oracle's spelling.

Every member here reads a writable run/project-dir file through a
NON-``load_json`` idiom (per-line loads over an open(), a plain
``load_jsonl``, ``read_text``), so the closure oracle never saw
them — and the live ones were measured OOM levers on the render and
prompt-assembly paths. Each member's budget is pinned with a peak
memory bound (deterministic: the plant is written locally, the
reader runs in-process).
"""

from __future__ import annotations

import json
import tracemalloc

from core.coverage.store_summary import format_progress_trend


def _peak(fn):
    tracemalloc.start()
    try:
        result = fn()
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    return result, peak


class TestProgressTrend:
    def _trail(self, tmp_path, rows):
        (tmp_path / "coverage-progress.jsonl").write_text(
            "".join(json.dumps(r) + "\n" for r in rows))
        return tmp_path / "coverage.json"

    def test_trend_reads_last_two_rows(self, tmp_path):
        store = self._trail(tmp_path, [
            {"run": f"r{i}", "llm_reviewed": i * 10,
             "llm_reviewable": 100}
            for i in range(1, 4)
        ])
        line = format_progress_trend(store)
        assert line is not None
        assert "30/100" in line and "+10" in line
        assert "3 runs recorded" in line

    def test_single_row_trail(self, tmp_path):
        store = self._trail(tmp_path, [
            {"run": "r1", "llm_reviewed": 5, "llm_reviewable": 10}])
        line = format_progress_trend(store)
        assert line is not None and "(1 run recorded)" in line

    def test_render_memory_is_bounded(self, tmp_path):
        # A planted multi-MB trail renders on EVERY coverage report;
        # the reader must retain two rows, not all of them (a 48 MB
        # plant measured +215 MB peak RSS pre-fix).
        rows = [
            {"run": f"r{i}", "llm_reviewed": i, "llm_reviewable": 9,
             "pad": "x" * 512}
            for i in range(20_000)                     # ~11 MB trail
        ]
        store = self._trail(tmp_path, rows)
        line, peak = _peak(lambda: format_progress_trend(store))
        assert line is not None and "20000 runs recorded" in line
        assert peak < 4 * 1024 * 1024, (
            f"trend render peaked at {peak} bytes — retaining every "
            "trail row"
        )

    def test_fifo_trail_refused_without_blocking(self, tmp_path):
        import os
        import threading
        os.mkfifo(tmp_path / "coverage-progress.jsonl")
        done = threading.Event()

        def _render() -> None:
            format_progress_trend(tmp_path / "coverage.json")
            done.set()

        t = threading.Thread(target=_render, daemon=True)
        t.start()
        assert done.wait(5), "trend render wedged on a planted FIFO"


class TestVerifiedOutcomesTrail:
    def _row(self, i: int, pad: str = "") -> dict:
        return {
            "finding_id": f"f{i}", "oracle": "sandbox",
            "status": "verified", "reproducible": True,
            "evidence": {"pad": pad},
        }

    def test_over_long_line_skipped_normal_rows_survive(self, tmp_path):
        from core.labeled_attempts.view import (
            _MAX_OUTCOMES_LINE_BYTES,
            collect_outcomes,
        )
        trail = tmp_path / "verified-outcomes.jsonl"
        with trail.open("w") as fh:
            fh.write(json.dumps(self._row(1)) + "\n")
            fh.write(json.dumps(
                self._row(2, pad="x" * (_MAX_OUTCOMES_LINE_BYTES + 10)),
            ) + "\n")
            fh.write(json.dumps(self._row(3)) + "\n")
        outcomes = collect_outcomes(tmp_path)
        ids = {o.finding_id for o in outcomes}
        assert ids == {"f1", "f3"}, (
            "an over-long trail line was materialised instead of "
            "skipped"
        )

    def test_oversize_trail_loads_as_empty(self, tmp_path):
        from core.labeled_attempts.view import (
            _MAX_OUTCOMES_TRAIL_BYTES,
            collect_outcomes,
        )
        trail = tmp_path / "verified-outcomes.jsonl"
        row = json.dumps(self._row(0, pad="y" * 900)) + "\n"
        need = _MAX_OUTCOMES_TRAIL_BYTES // len(row) + 2
        with trail.open("w") as fh:
            for _ in range(need):
                fh.write(row)
        outcomes, peak = _peak(lambda: collect_outcomes(tmp_path))
        assert outcomes == []
        assert peak < 8 * 1024 * 1024, (
            f"oversize trail read peaked at {peak} bytes"
        )


class TestTrajectoryIteration:
    def test_oversize_trajectory_skipped_without_buffering(
            self, tmp_path):
        from core.trajectories.store import (
            _MAX_TRAJECTORY_BYTES,
            iter_trajectory_json,
        )
        run = tmp_path / "trajectories" / "run1"
        run.mkdir(parents=True)
        big = run / "trajectory.json"
        plant = _MAX_TRAJECTORY_BYTES * 4              # 256 MB, sparse
        with big.open("wb") as fh:
            fh.seek(plant)
            fh.write(b"\0")
        small = tmp_path / "trajectories" / "run2"
        small.mkdir()
        (small / "trajectory.json").write_text('{"ok": 1}')
        result, peak = _peak(
            lambda: list(iter_trajectory_json(tmp_path)))
        assert [parsed for _, parsed in result] == [{"ok": 1}]
        # The budgeted read holds at most ~2x the cap (probe buffer +
        # truncation slice); the unbudgeted read_text buffered (and
        # decoded) the whole plant.
        assert peak < int(_MAX_TRAJECTORY_BYTES * 2.5), (
            f"trajectory iteration peaked at {peak} bytes — the "
            "oversize file was buffered whole"
        )
