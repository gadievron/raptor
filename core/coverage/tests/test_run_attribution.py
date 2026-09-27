"""Run attribution stamped on journal rows.

Contract: every journal writer stamps ``run_id`` with the RESOLVED
run-dir basename via :func:`core.coverage.journal.resolved_run_id` —
the identity run-scoped consumers compare rows against. Unresolved, a
relative spelling ("." from inside the run dir has
``Path(".").name == ""``) writes rows that carry no attribution. A
genuinely unresolvable path falls back toward the no-attribution
sentinel (``RUN_ID_UNATTRIBUTED``) — a statement of NO attribution,
never an attribution to a foreign run.

Covers the shared resolver itself plus the coverage-summary mark
journaling seams (``_journal_marks`` / ``_neutralise_journaled_marks``
in libexec/raptor-coverage-summary) that route through it. The audit
orchestrator's own delegation is pinned in
core/audit/tests/test_run_id_stamp_census.py.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.coverage.journal import (
    RUN_ID_UNATTRIBUTED,
    load_entries,
    resolved_run_id,
)
from core.coverage.tests import summary_cli_support


class TestResolvedRunIdHelper:
    def test_relative_out_dir_resolves_to_name(
            self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        run = tmp_path / "runX"
        run.mkdir()
        monkeypatch.chdir(run)
        assert resolved_run_id(Path(".")) == "runX"

    def test_absolute_out_dir_is_the_basename(self, tmp_path: Path) -> None:
        run = tmp_path / "audit_20260927"
        run.mkdir()
        assert resolved_run_id(run) == "audit_20260927"

    def test_none_keeps_empty_stamp(self) -> None:
        # The historical no-run-dir spelling: "" is the consumer-side
        # equivalent of the sentinel, kept byte-identical.
        assert resolved_run_id(None) == ""

    def test_filesystem_root_falls_back_to_sentinel(self) -> None:
        assert resolved_run_id(Path("/")) == RUN_ID_UNATTRIBUTED

    def test_resolution_failure_falls_back_to_unresolved_name(
            self, monkeypatch: pytest.MonkeyPatch) -> None:
        # The OSError arm keeps whatever name the unresolved path
        # carries; only a name-less path lands on the sentinel.
        def _boom(self: Path, strict: bool = False) -> Path:
            raise OSError("resolution failed")

        monkeypatch.setattr(type(Path()), "resolve", _boom)
        assert resolved_run_id(Path("/x/runZ")) == "runZ"
        assert resolved_run_id(Path("")) == RUN_ID_UNATTRIBUTED


def _standalone_run(tmp_path: Path) -> Path:
    """Standalone-run shape: run marker and checklist in ONE dir, so
    the relative ``Path(".")`` spelling (whose ``.parent`` is also
    ".") still finds the checklist beside the journal — the exact
    spelling whose unresolved ``name`` is empty."""
    run = tmp_path / "run1"
    run.mkdir()
    (run / ".raptor-run.json").write_text("{}")
    (run / "checklist.json").write_text(json.dumps({
        "target_path": "",
        "files": [{"path": "src/a.c", "items": [
            {"name": "fn", "line_start": 1, "line_end": 3}]}],
    }))
    return run


class TestMarkJournalRunAttribution:
    def test_relative_run_dir_stamps_resolved_run_id(
            self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        mod = summary_cli_support._load_cli_module()
        run = _standalone_run(tmp_path)
        monkeypatch.chdir(run)

        assert mod._journal_marks(Path("."), [("src/a.c", "fn")], {}) == 1

        assert [e.run_id for e in load_entries(run, fresh=True)] == ["run1"]

    def test_neutralise_rows_stamp_resolved_run_id(
            self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        mod = summary_cli_support._load_cli_module()
        run = _standalone_run(tmp_path)
        monkeypatch.chdir(run)
        assert mod._journal_marks(Path("."), [("src/a.c", "fn")], {}) == 1

        mod._neutralise_journaled_marks(Path("."), [("src/a.c", "fn")])

        entries = load_entries(run, fresh=True)
        assert sorted(e.verdict for e in entries) == ["clean", "error"]
        assert {e.run_id for e in entries} == {"run1"}

    def test_absolute_run_dir_stamp_is_the_basename(
            self, tmp_path: Path) -> None:
        # Differential pin for the project shape (checklist at the
        # parent, absolute run dir): the stamp stays exactly the
        # pre-existing basename.
        proj = tmp_path / "proj"
        run = proj / "run1"
        run.mkdir(parents=True)
        (run / ".raptor-run.json").write_text("{}")
        (proj / "checklist.json").write_text(json.dumps({
            "target_path": "",
            "files": [{"path": "src/a.c", "items": [
                {"name": "fn", "line_start": 1, "line_end": 3}]}],
        }))
        mod = summary_cli_support._load_cli_module()

        assert mod._journal_marks(run, [("src/a.c", "fn")], {}) == 1

        assert [e.run_id for e in load_entries(run, fresh=True)] == ["run1"]
