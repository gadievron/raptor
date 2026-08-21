"""Tests for the orchestrator's run-progress checkpoint writer."""

from __future__ import annotations

import json
from types import SimpleNamespace

from core.audit.orchestrator import _update_run_progress


class TestUpdateRunProgress:
    def test_writes_progress_into_extra(self, tmp_path) -> None:
        meta_path = tmp_path / ".raptor-run.json"
        meta_path.write_text(
            json.dumps({"status": "running", "extra": {}}),
            encoding="utf-8",
        )
        _update_run_progress(tmp_path, SimpleNamespace(reviewed=7))
        updated = json.loads(meta_path.read_text(encoding="utf-8"))
        assert updated["extra"]["progress"] == {"completed": 7}
        assert updated["status"] == "running"

    def test_preserves_concurrently_set_terminal_status(
        self, tmp_path,
    ) -> None:
        """A lifecycle writer marking the run interrupted between
        checkpoints must not be clobbered back to running."""
        meta_path = tmp_path / ".raptor-run.json"
        meta_path.write_text(
            json.dumps({
                "status": "interrupted",
                "extra": {"interrupt_reason": "sigterm"},
            }),
            encoding="utf-8",
        )
        _update_run_progress(tmp_path, SimpleNamespace(reviewed=3))
        updated = json.loads(meta_path.read_text(encoding="utf-8"))
        assert updated["status"] == "interrupted"
        assert updated["extra"]["interrupt_reason"] == "sigterm"
        assert updated["extra"]["progress"] == {"completed": 3}

    def test_missing_metadata_is_noop(self, tmp_path) -> None:
        _update_run_progress(tmp_path, SimpleNamespace(reviewed=1))
        assert not (tmp_path / ".raptor-run.json").exists()

    def test_malformed_metadata_is_noop(self, tmp_path) -> None:
        meta_path = tmp_path / ".raptor-run.json"
        meta_path.write_text("[1, 2, 3]", encoding="utf-8")
        try:
            _update_run_progress(tmp_path, SimpleNamespace(reviewed=1))
            assert (
                json.loads(meta_path.read_text(encoding="utf-8")) == [1, 2, 3]
            )
        finally:
            # Hermeticity: tmp_path is a child of the shared pytest tmp
            # root, which other tests may sweep as a project directory —
            # never leave a malformed .raptor-run.json behind.
            meta_path.unlink()


class TestResetShutdownState:
    def test_second_run_not_poisoned(self) -> None:
        import core.audit.orchestrator as orch

        orch.request_shutdown()
        orch._sigterm_event.set()
        orch._sigterm_state["count"] = 1
        try:
            assert orch.is_shutdown_requested()
            orch._reset_shutdown_state()
            assert not orch.is_shutdown_requested()
            assert not orch.is_sigterm_requested()
            assert orch._sigterm_state["count"] == 0
        finally:
            orch._shutdown_event.clear()
            orch._sigterm_event.clear()
            orch._sigterm_state["count"] = 0

    def test_installed_flag_preserved(self) -> None:
        import core.audit.orchestrator as orch

        prior = orch._sigterm_state["installed"]
        orch._reset_shutdown_state()
        assert orch._sigterm_state["installed"] == prior


class TestFileLinesCache:
    def test_mtime_change_invalidates(self, tmp_path) -> None:
        import os

        from core.audit.orchestrator import (
            _file_lines_cache,
            _read_raw_source,
        )

        _file_lines_cache.clear()
        src = tmp_path / "a.c"
        src.write_text("first version\n", encoding="utf-8")
        assert _read_raw_source(tmp_path, "a.c", 1, 1) == "first version"

        src.write_text("second version\n", encoding="utf-8")
        # Force a distinct mtime even on coarse filesystems.
        st = src.stat()
        os.utime(src, (st.st_atime, st.st_mtime + 10))
        assert _read_raw_source(tmp_path, "a.c", 1, 1) == "second version"

    def test_cache_bounded(self, tmp_path) -> None:
        import core.audit.orchestrator as orch

        orch._file_lines_cache.clear()
        for i in range(orch._FILE_LINES_CACHE_MAX + 20):
            f = tmp_path / f"f{i}.c"
            f.write_text(f"line {i}\n", encoding="utf-8")
            orch._read_raw_source(tmp_path, f"f{i}.c", 1, 1)
        assert len(orch._file_lines_cache) <= orch._FILE_LINES_CACHE_MAX
        orch._file_lines_cache.clear()

    def test_missing_file_returns_empty(self, tmp_path) -> None:
        from core.audit.orchestrator import _read_raw_source

        assert _read_raw_source(tmp_path, "nope.c", 1, 2) == ""
