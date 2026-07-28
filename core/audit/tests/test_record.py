"""Tests for core.audit.record — audit event-log helpers.

Post-migration (annotation → journal, 2026-07-28): ``record_review``
+ ``_update_coverage_audit`` were removed. The remaining surface is
the audit event log (``.audit-log.jsonl``) — non-review events like
context loads and tool dispatch flow through it. Review outcomes
went to ``review-journal.jsonl`` in the same directory.
"""

from __future__ import annotations

from pathlib import Path

from core.audit.record import (
    append_audit_log,
    load_audit_log,
    _compute_hash,
    _resolve_annotations_dir,
)


class TestAuditLog:
    def test_append_and_load(self, tmp_path: Path):
        append_audit_log(tmp_path, {"action": "context", "file": "a.c"})
        append_audit_log(tmp_path, {"action": "context", "file": "b.c"})
        records = load_audit_log(tmp_path)
        assert len(records) == 2
        assert records[0]["file"] == "a.c"
        assert records[1]["file"] == "b.c"

    def test_load_empty(self, tmp_path: Path):
        assert load_audit_log(tmp_path) == []

    def test_skips_corrupt_lines(self, tmp_path: Path):
        log = tmp_path / ".audit-log.jsonl"
        log.write_text('{"action":"context"}\ngarbage-not-json\n{"action":"tool_dispatch"}\n')
        records = load_audit_log(tmp_path)
        assert len(records) == 2


class TestComputeHash:
    def test_hashes_existing_source(self, tmp_path: Path):
        target = tmp_path / "target"
        target.mkdir()
        (target / "a.c").write_text("int main() { return 0; }\n")
        h = _compute_hash(target, "a.c", 1, 1)
        assert h is not None
        assert isinstance(h, str)

    def test_missing_source_returns_none(self, tmp_path: Path):
        target = tmp_path / "target"
        target.mkdir()
        assert _compute_hash(target, "nonexistent.c", 1, 1) is None


class TestResolveAnnotationsDir:
    def test_project_level_when_run_marker_exists(self, tmp_path: Path):
        project = tmp_path / "project"
        project.mkdir()
        run = project / "run_20260728"
        run.mkdir()
        (run / ".raptor-run.json").write_text("{}")
        assert _resolve_annotations_dir(run) == project / "annotations"

    def test_falls_back_to_run_dir_without_marker(self, tmp_path: Path):
        run = tmp_path / "run_standalone"
        run.mkdir()
        assert _resolve_annotations_dir(run) == run / "annotations"
