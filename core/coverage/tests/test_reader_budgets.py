"""Budgets for the run/project-dir readers outside the load_json
closure oracle's spelling.

Every member here reads a writable run/project-dir file through a
NON-``load_json`` idiom (per-line loads over an open(), a plain
``load_jsonl``, ``read_text``), so the closure oracle never saw
them — and the live ones were measured OOM levers on the render and
prompt-assembly paths. Each member's budget is pinned with a peak
memory bound (deterministic: the plant is written locally, the
reader runs in-process unless a tracing session is borrowed).
"""

from __future__ import annotations

import json
import tracemalloc

from core.coverage.store_summary import format_progress_trend
from core.testing.processes import run_in_process_group as _run_memory_process


def _peak(fn):
    assert not tracemalloc.is_tracing(), "memory measurement requires an owned trace"
    try:
        tracemalloc.start()
        result = fn()
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    return result, peak


_MEMORY_CASES = {
    ("TestProgressTrend", "test_render_memory_is_bounded"),
    ("TestVerifiedOutcomesTrail", "test_oversize_trail_loads_as_empty"),
    ("TestTrajectoryIteration", "test_oversize_trajectory_skipped_without_buffering"),
}


def _run_reader_memory_proof(tmp_path, owner, method):
    """Measure the native reader without consuming a borrowed tracing session."""
    from pathlib import Path
    import subprocess
    import sys

    from core.testing.standalone_cli import standalone_cli_env

    assert (owner, method) in _MEMORY_CASES
    root = Path(__file__).resolve().parents[3]
    script = """\
import sys
import tracemalloc
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from pytest import MonkeyPatch
from core.testing.state_isolation import pin_user_state_dirs
from core.coverage.tests import test_reader_budgets as native
assert not tracemalloc.is_tracing()
owned = Path(sys.argv[2])
case = (sys.argv[3], sys.argv[4])
assert case in native._MEMORY_CASES
with MonkeyPatch.context() as patch:
    pin_user_state_dirs(patch, owned / "memory-child-state")
    getattr(getattr(native, case[0])(), case[1])(owned)
print("reader-memory-proof-ok")
"""
    with standalone_cli_env() as env:
        result = _run_memory_process(
            [sys.executable, "-I", "-c", script, str(root), str(tmp_path), owner, method],
            timeout=30, env=env, cwd=root,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "reader-memory-proof-ok", result.stdout


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
        if tracemalloc.is_tracing():
            _run_reader_memory_proof(tmp_path, "TestProgressTrend", "test_render_memory_is_bounded")
            return

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
        from core.coverage.tests.test_reader_fd_discipline import _retiring_fifo_thread

        fifo = tmp_path / "coverage-progress.jsonl"
        os.mkfifo(fifo)
        done = threading.Event()

        def _render() -> None:
            format_progress_trend(tmp_path / "coverage.json")
            done.set()

        t = threading.Thread(target=_render, daemon=True)
        with _retiring_fifo_thread(t, done, fifo, writer=False):
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
        if tracemalloc.is_tracing():
            _run_reader_memory_proof(tmp_path, "TestVerifiedOutcomesTrail", "test_oversize_trail_loads_as_empty")
            return

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
        if tracemalloc.is_tracing():
            _run_reader_memory_proof(
                tmp_path, "TestTrajectoryIteration",
                "test_oversize_trajectory_skipped_without_buffering",
            )
            return

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
