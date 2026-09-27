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

    def test_pin_failure_degrades_loudly(
        self, tmp_path: Path, monkeypatch, caplog,
    ):
        # Annotations carry operator-authority notes — a pin
        # resolution failure rerouting reads to the legacy location
        # must warn, never silently swallow. Behaviour (the legacy
        # marker+parent probe) is unchanged.
        import core.run.pin as pin_mod

        def _boom(*a, **kw):
            raise RuntimeError("pin store unreadable")

        monkeypatch.setattr(pin_mod, "resolve_run_pin", _boom)
        project = tmp_path / "project"
        project.mkdir()
        run = project / "run_20260728"
        run.mkdir()
        (run / ".raptor-run.json").write_text("{}")
        with caplog.at_level("WARNING", logger="core.audit.record"):
            resolved = _resolve_annotations_dir(run)
        assert resolved == project / "annotations"
        warnings = [
            r for r in caplog.records
            if r.levelname == "WARNING" and r.name == "core.audit.record"
        ]
        assert len(warnings) == 1
        assert str(run) in warnings[0].getMessage()

    def test_pin_failure_warning_escaped_and_bounded(
        self, tmp_path: Path, monkeypatch, caplog,
    ):
        # A hostile exception message (control bytes + flooding
        # length — exception text is duck-typed input) must land
        # escaped and truncated in the WARNING; the traceback is
        # DEBUG-only.
        import core.run.pin as pin_mod

        hostile = "\x1b]0;pwn\x07" + "A" * 100_000

        def _boom(*a, **kw):
            raise RuntimeError(hostile)

        monkeypatch.setattr(pin_mod, "resolve_run_pin", _boom)
        run = tmp_path / "run_standalone"
        run.mkdir()
        with caplog.at_level("WARNING", logger="core.audit.record"):
            assert _resolve_annotations_dir(run) == run / "annotations"
        warnings = [
            r for r in caplog.records
            if r.levelname == "WARNING" and r.name == "core.audit.record"
        ]
        assert len(warnings) == 1
        msg = warnings[0].getMessage()
        assert "\x1b" not in msg
        assert "\\x1b" in msg
        assert "chars]" in msg  # explicit elision marker
        assert len(msg) < 1000  # bounded, not the 100 KB flood

    def test_healthy_pin_resolution_does_not_warn(
        self, tmp_path: Path, caplog,
    ):
        project = tmp_path / "project"
        project.mkdir()
        run = project / "run_20260728"
        run.mkdir()
        (run / ".raptor-run.json").write_text("{}")
        with caplog.at_level("WARNING", logger="core.audit.record"):
            _resolve_annotations_dir(run)
            _resolve_annotations_dir(tmp_path / "no_such_dir")
        assert [
            r for r in caplog.records
            if r.levelname == "WARNING" and r.name == "core.audit.record"
        ] == []


class TestBinaryItemHash:
    _FILE_ENTRY = {"sha256": "a" * 64}

    def test_int_address(self):
        from core.audit.record import binary_item_hash
        h = binary_item_hash(
            self._FILE_ENTRY, {"address": 0x401000, "size": 32},
        )
        assert h == f"bin:{'a' * 12}:401000:20"

    def test_hex_string_address_coerced(self):
        # Checklists round-trip through JSON and other producers; a
        # hex-string address must hash identically to its int form,
        # not raise ValueError and abort the caller's checklist walk.
        from core.audit.record import binary_item_hash
        h = binary_item_hash(
            self._FILE_ENTRY, {"address": "0x401000", "size": "32"},
        )
        assert h == f"bin:{'a' * 12}:401000:20"

    def test_junk_address_returns_none(self):
        # Missing hash only widens review — never an exception.
        from core.audit.record import binary_item_hash
        assert binary_item_hash(
            self._FILE_ENTRY, {"address": "not-an-addr", "size": 1},
        ) is None
