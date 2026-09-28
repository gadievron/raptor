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
        progress = updated["extra"]["progress"]
        assert progress["completed"] == 7
        assert "updated_at" in progress
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
        assert updated["extra"]["progress"]["completed"] == 3

    def test_updated_at_is_utc_iso8601(self, tmp_path) -> None:
        from datetime import datetime, timedelta, timezone

        meta_path = tmp_path / ".raptor-run.json"
        meta_path.write_text(
            json.dumps({"status": "running", "extra": {}}),
            encoding="utf-8",
        )
        before = datetime.now(timezone.utc)
        _update_run_progress(tmp_path, SimpleNamespace(reviewed=1))
        after = datetime.now(timezone.utc)
        updated = json.loads(meta_path.read_text(encoding="utf-8"))
        stamp = datetime.fromisoformat(
            updated["extra"]["progress"]["updated_at"],
        )
        assert stamp.utcoffset() == timedelta(0)
        assert before <= stamp <= after

    def test_study_fields_written_under_study_key(
        self, tmp_path,
    ) -> None:
        meta_path = tmp_path / ".raptor-run.json"
        meta_path.write_text(
            json.dumps({"status": "running", "extra": {}}),
            encoding="utf-8",
        )
        _update_run_progress(
            tmp_path, SimpleNamespace(reviewed=4),
            study={
                "batches_completed": 3,
                "batches_failed": 1,
                "questions_resolved": 9,
                "re_reviews": 2,
            },
        )
        progress = json.loads(
            meta_path.read_text(encoding="utf-8"),
        )["extra"]["progress"]
        assert progress["completed"] == 4
        assert progress["study"] == {
            "batches_completed": 3,
            "batches_failed": 1,
            "questions_resolved": 9,
            "re_reviews": 2,
        }

    def test_review_checkpoint_preserves_study_fields(
        self, tmp_path,
    ) -> None:
        """The executor's review checkpoints (no ``study``) and the
        study consumer's drain checkpoints interleave on the same
        record — a study-less write must not erase the drain's
        fields, and the drain's write must not change ``completed``'s
        meaning."""
        meta_path = tmp_path / ".raptor-run.json"
        meta_path.write_text(
            json.dumps({"status": "running", "extra": {}}),
            encoding="utf-8",
        )
        _update_run_progress(
            tmp_path, SimpleNamespace(reviewed=4),
            study={"batches_completed": 2},
        )
        _update_run_progress(tmp_path, SimpleNamespace(reviewed=6))
        progress = json.loads(
            meta_path.read_text(encoding="utf-8"),
        )["extra"]["progress"]
        assert progress["completed"] == 6
        assert progress["study"] == {"batches_completed": 2}

    def test_non_dict_prior_progress_is_replaced(
        self, tmp_path,
    ) -> None:
        meta_path = tmp_path / ".raptor-run.json"
        meta_path.write_text(
            json.dumps({
                "status": "running",
                "extra": {"progress": "corrupt"},
            }),
            encoding="utf-8",
        )
        _update_run_progress(tmp_path, SimpleNamespace(reviewed=2))
        progress = json.loads(
            meta_path.read_text(encoding="utf-8"),
        )["extra"]["progress"]
        assert progress["completed"] == 2

    def test_checkpoint_write_leaves_no_debris(self, tmp_path) -> None:
        """Still routed through the shared atomic + locked primitive:
        only the metadata file and every writer's flock sidecar may
        exist afterwards."""
        meta_path = tmp_path / ".raptor-run.json"
        meta_path.write_text(
            json.dumps({"status": "running", "extra": {}}),
            encoding="utf-8",
        )
        _update_run_progress(
            tmp_path, SimpleNamespace(reviewed=1),
            study={"batches_completed": 1},
        )
        leftovers = [
            q.name for q in tmp_path.iterdir()
            if q.name not in (
                ".raptor-run.json", ".raptor-run.json.lock",
            )
        ]
        assert leftovers == []

    def test_checkpoint_interval_matches_executor(self) -> None:
        """The consumer mirrors the executor's interval (importing it
        back would be circular) — the two constants must not drift."""
        import core.audit.executor as executor
        import core.audit.orchestrator as orchestrator

        assert (
            orchestrator._PROGRESS_CHECKPOINT_INTERVAL
            == executor._PROGRESS_CHECKPOINT_INTERVAL
        )

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

    def test_cache_byte_bounded(self, tmp_path, monkeypatch) -> None:
        """Eviction is byte-weighted: many mid-size files must not pin
        more than the byte budget even while the entry count is far
        below the entry cap."""
        import core.audit.orchestrator as orch

        orch._file_lines_cache.clear()
        orch._file_lines_cache_bytes = 0
        monkeypatch.setattr(
            orch, "_FILE_LINES_CACHE_MAX_BYTES", 4096, raising=False,
        )
        monkeypatch.setattr(
            orch, "_FILE_LINES_CACHE_MAX_ENTRY_BYTES", 2048, raising=False,
        )
        body = "x" * 511 + "\n"  # 512 bytes per file
        for i in range(32):
            f = tmp_path / f"b{i}.c"
            f.write_text(body, encoding="utf-8")
            orch._read_raw_source(tmp_path, f"b{i}.c", 1, 1)
        cached_bytes = sum(k[2] for k in orch._file_lines_cache)
        assert cached_bytes <= 4096, (
            f"cache pins {cached_bytes} bytes; byte budget is 4096"
        )
        orch._file_lines_cache.clear()
        orch._file_lines_cache_bytes = 0

    def test_oversized_file_served_uncached(self, tmp_path, monkeypatch) -> None:
        import core.audit.orchestrator as orch

        orch._file_lines_cache.clear()
        orch._file_lines_cache_bytes = 0
        monkeypatch.setattr(
            orch, "_FILE_LINES_CACHE_MAX_ENTRY_BYTES", 256, raising=False,
        )
        f = tmp_path / "huge.c"
        f.write_text("y" * 1024 + "\nsecond line\n", encoding="utf-8")
        out = orch._read_raw_source(tmp_path, "huge.c", 2, 2)
        assert out == "second line"
        assert not orch._file_lines_cache, (
            "files above the per-entry byte cap must not be cached"
        )
