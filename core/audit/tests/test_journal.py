"""Tests for core.coverage.journal — review journal read/write/merge."""

from __future__ import annotations

import json
from pathlib import Path

from core.coverage.journal import (
    INDEX_FILENAME,
    JOURNAL_FILENAME,
    ReviewJournalEntry,
    append_entry,
    flush_journal,
    latest_entries,
    load_entries,
    load_index,
    merge_into_index,
    reviewed_set,
)


def _entry(
    file: str = "src/auth.c",
    function: str = "check_pw",
    verdict: str = "clean",
    ts: str = "2026-07-19T14:00:00Z",
    run_id: str = "audit-20260719",
    source_hash: str = "abc123",
    **kwargs,
) -> ReviewJournalEntry:
    return ReviewJournalEntry(
        ts=ts,
        run_id=run_id,
        file=file,
        function=function,
        verdict=verdict,
        source_hash=source_hash,
        **kwargs,
    )


class TestAppendAndLoad:
    def test_round_trip(self, tmp_path: Path) -> None:
        e = _entry(strategies=["general", "input_handling"])
        append_entry(tmp_path, e)

        entries = load_entries(tmp_path)
        assert len(entries) == 1
        assert entries[0].file == "src/auth.c"
        assert entries[0].function == "check_pw"
        assert entries[0].verdict == "clean"
        assert entries[0].strategies == ["general", "input_handling"]
        assert entries[0].source_hash == "abc123"

    def test_multiple_appends(self, tmp_path: Path) -> None:
        append_entry(tmp_path, _entry(function="fn_a"))
        append_entry(tmp_path, _entry(function="fn_b"))
        append_entry(tmp_path, _entry(function="fn_c"))

        entries = load_entries(tmp_path)
        assert len(entries) == 3
        assert [e.function for e in entries] == ["fn_a", "fn_b", "fn_c"]

    def test_empty_dir_returns_empty(self, tmp_path: Path) -> None:
        assert load_entries(tmp_path) == []

    def test_optional_fields_round_trip(self, tmp_path: Path) -> None:
        e = _entry(
            cwe="CWE-120",
            confidence=0.85,
            domain_model_hash="b4e8d2",
            domain_concepts_available=["sg_tagging"],
            invariants_available=["inv_page_align"],
            hypotheses=[{"claim": "overflow", "status": "disproven", "evidence": "bounded"}],
            body="Reviewed for buffer overflow.",
            reading_list_items=["What are page ownership semantics?"],
            model="claude-opus-4-7",
            evidence_tools=["source_read", "joern"],
            token_budget=50000,
            cost_usd=0.042,
            duration_s=12.3,
            prior_review="2026-07-18T10:00:00Z",
        )
        append_entry(tmp_path, e)

        loaded = load_entries(tmp_path)[0]
        assert loaded.cwe == "CWE-120"
        assert loaded.confidence == 0.85
        assert loaded.domain_model_hash == "b4e8d2"
        assert loaded.hypotheses[0]["claim"] == "overflow"
        assert loaded.body == "Reviewed for buffer overflow."
        assert loaded.reading_list_items == ["What are page ownership semantics?"]
        assert loaded.model == "claude-opus-4-7"
        assert loaded.cost_usd == 0.042
        assert loaded.prior_review == "2026-07-18T10:00:00Z"

    def test_to_dict_omits_none(self) -> None:
        e = _entry()
        d = e.to_dict()
        assert "cwe" not in d
        assert "model" not in d
        assert "file" in d
        assert "verdict" in d


class TestCorruptLineRecovery:
    def test_corrupt_trailing_line_skipped(self, tmp_path: Path) -> None:
        append_entry(tmp_path, _entry(function="good"))
        journal = tmp_path / JOURNAL_FILENAME
        with open(journal, "a") as f:
            f.write('{"truncat\n')

        entries = load_entries(tmp_path)
        assert len(entries) == 1
        assert entries[0].function == "good"

    def test_corrupt_interior_line_skipped(self, tmp_path: Path) -> None:
        append_entry(tmp_path, _entry(function="first"))
        journal = tmp_path / JOURNAL_FILENAME
        with open(journal, "a") as f:
            f.write("NOT JSON\n")
        append_entry(tmp_path, _entry(function="third"))

        entries = load_entries(tmp_path)
        assert len(entries) == 2
        assert entries[0].function == "first"
        assert entries[1].function == "third"

    def test_empty_lines_skipped(self, tmp_path: Path) -> None:
        journal = tmp_path / JOURNAL_FILENAME
        journal.parent.mkdir(parents=True, exist_ok=True)
        journal.write_text("\n\n\n", encoding="utf-8")
        assert load_entries(tmp_path) == []

    def test_missing_required_field_skipped(self, tmp_path: Path) -> None:
        journal = tmp_path / JOURNAL_FILENAME
        journal.parent.mkdir(parents=True, exist_ok=True)
        journal.write_text(
            json.dumps({"ts": "x", "run_id": "r"}) + "\n",
            encoding="utf-8",
        )
        assert load_entries(tmp_path) == []


class TestReviewedSet:
    def test_returns_keys(self, tmp_path: Path) -> None:
        append_entry(tmp_path, _entry(file="a.c", function="fn1"))
        append_entry(tmp_path, _entry(file="b.c", function="fn2"))

        keys = reviewed_set(tmp_path)
        assert keys == {"a.c:fn1", "b.c:fn2"}

    def test_empty(self, tmp_path: Path) -> None:
        assert reviewed_set(tmp_path) == set()

    def test_error_verdicts_excluded(self, tmp_path: Path) -> None:
        append_entry(tmp_path, _entry(file="a.c", function="ok", verdict="clean"))
        append_entry(tmp_path, _entry(file="b.c", function="fail", verdict="error"))
        keys = reviewed_set(tmp_path)
        assert "a.c:ok" in keys
        assert "b.c:fail" not in keys


class TestLatestEntries:
    def test_most_recent_wins(self, tmp_path: Path) -> None:
        append_entry(tmp_path, _entry(
            ts="2026-07-19T10:00:00Z", verdict="clean",
        ))
        append_entry(tmp_path, _entry(
            ts="2026-07-19T14:00:00Z", verdict="finding",
        ))

        best = latest_entries(tmp_path)
        assert len(best) == 1
        assert best["src/auth.c:check_pw"].verdict == "finding"

    def test_different_keys_kept(self, tmp_path: Path) -> None:
        append_entry(tmp_path, _entry(function="fn_a"))
        append_entry(tmp_path, _entry(function="fn_b"))

        best = latest_entries(tmp_path)
        assert len(best) == 2


class TestEntryKey:
    def test_key_format(self) -> None:
        e = _entry(file="net/algif_aead.c", function="_aead_recvmsg")
        assert e.key == "net/algif_aead.c:_aead_recvmsg"


class TestFlushJournal:
    def test_flush_existing(self, tmp_path: Path) -> None:
        append_entry(tmp_path, _entry())
        flush_journal(tmp_path)

    def test_flush_nonexistent_noop(self, tmp_path: Path) -> None:
        flush_journal(tmp_path)


class TestMergeIntoIndex:
    def test_merge_creates_index(self, tmp_path: Path) -> None:
        project = tmp_path / "project"
        project.mkdir()
        run = tmp_path / "run"
        run.mkdir()

        append_entry(run, _entry(file="a.c", function="f1"))
        append_entry(run, _entry(file="b.c", function="f2"))

        count = merge_into_index(project, run)
        assert count == 2

        index_path = project / INDEX_FILENAME
        assert index_path.is_file()
        data = json.loads(index_path.read_text(encoding="utf-8"))
        assert data["schema_version"] == 1
        # Storage key widened to (file, function, model, strategy_hash)
        # per amendment D1. ``file:function`` no longer appears as
        # a top-level key — the collapsed view is available via
        # ``load_index`` / callers iterate ``entry.file+entry.function``.
        assert any(k.startswith("a.c:f1:") for k in data["entries"])
        assert any(k.startswith("b.c:f2:") for k in data["entries"])

    def test_merge_newer_wins(self, tmp_path: Path) -> None:
        project = tmp_path / "project"
        project.mkdir()

        run1 = tmp_path / "run1"
        run1.mkdir()
        append_entry(run1, _entry(
            ts="2026-07-18T10:00:00Z", verdict="clean",
        ))
        merge_into_index(project, run1)

        run2 = tmp_path / "run2"
        run2.mkdir()
        append_entry(run2, _entry(
            ts="2026-07-19T14:00:00Z", verdict="finding",
        ))
        count = merge_into_index(project, run2)
        assert count == 1

        idx = load_index(project)
        assert idx["src/auth.c:check_pw"].verdict == "finding"

    def test_merge_older_loses(self, tmp_path: Path) -> None:
        project = tmp_path / "project"
        project.mkdir()

        run1 = tmp_path / "run1"
        run1.mkdir()
        append_entry(run1, _entry(
            ts="2026-07-19T14:00:00Z", verdict="finding",
        ))
        merge_into_index(project, run1)

        run2 = tmp_path / "run2"
        run2.mkdir()
        append_entry(run2, _entry(
            ts="2026-07-18T10:00:00Z", verdict="clean",
        ))
        count = merge_into_index(project, run2)
        assert count == 0

        idx = load_index(project)
        assert idx["src/auth.c:check_pw"].verdict == "finding"

    def test_merge_empty_run_returns_zero(self, tmp_path: Path) -> None:
        project = tmp_path / "project"
        project.mkdir()
        run = tmp_path / "run"
        run.mkdir()

        count = merge_into_index(project, run)
        assert count == 0

    def test_merge_idempotent(self, tmp_path: Path) -> None:
        project = tmp_path / "project"
        project.mkdir()
        run = tmp_path / "run"
        run.mkdir()

        append_entry(run, _entry())
        merge_into_index(project, run)
        count = merge_into_index(project, run)
        assert count == 0

    def test_corrupt_index_recovers(self, tmp_path: Path) -> None:
        project = tmp_path / "project"
        project.mkdir()
        (project / INDEX_FILENAME).write_text("NOT JSON", encoding="utf-8")

        run = tmp_path / "run"
        run.mkdir()
        append_entry(run, _entry())

        count = merge_into_index(project, run)
        assert count == 1
        idx = load_index(project)
        assert "src/auth.c:check_pw" in idx


class TestLoadIndex:
    def test_empty_project(self, tmp_path: Path) -> None:
        assert load_index(tmp_path) == {}

    def test_round_trip_through_merge(self, tmp_path: Path) -> None:
        project = tmp_path / "project"
        project.mkdir()
        run = tmp_path / "run"
        run.mkdir()

        append_entry(run, _entry(
            model="test-model",
            strategies=["aliasing"],
            domain_model_hash="hash123",
        ))
        merge_into_index(project, run)

        idx = load_index(project)
        entry = idx["src/auth.c:check_pw"]
        assert entry.model == "test-model"
        assert entry.strategies == ["aliasing"]
        assert entry.domain_model_hash == "hash123"


class TestMechanicalEchoRows:
    """Post-loop pattern-scan findings are journalled as $0
    ``[mechanical]`` echo rows — one per finding. They are not LLM
    reviews and must not inflate naive verdict counts; the single
    counting rule lives in ``is_mechanical_echo``."""

    def _entry(self, **kw):
        from core.coverage.journal import ReviewJournalEntry, now_iso
        base = dict(
            ts=now_iso(), run_id="r", file="a.c", function="f",
            verdict="suspicious", source_hash="",
        )
        base.update(kw)
        return ReviewJournalEntry(**base)

    def test_strategy_tag_marks_echo(self):
        from core.coverage.journal import is_mechanical_echo
        e = self._entry(strategies=["post-loop-mechanical"])
        assert is_mechanical_echo(e) is True

    def test_body_marker_marks_echo(self):
        from core.coverage.journal import is_mechanical_echo
        e = self._entry(body="[mechanical] pattern-scan finding")
        assert is_mechanical_echo(e) is True

    def test_llm_review_is_not_echo(self):
        from core.coverage.journal import is_mechanical_echo
        e = self._entry(
            body="STEP 1 — UNDERSTAND ...", cost_usd=0.31,
            strategies=["crypto", "general"],
        )
        assert is_mechanical_echo(e) is False

    def test_accepts_raw_dicts(self):
        from core.coverage.journal import is_mechanical_echo
        assert is_mechanical_echo(
            {"strategies": ["post-loop-mechanical"], "body": ""},
        ) is True
        assert is_mechanical_echo(
            {"strategies": ["crypto"], "body": "reviewed"},
        ) is False

    def test_review_stats_exclude_echo_rows(self, tmp_path):
        # The operator CLI's stats summary counts echo rows separately.
        import importlib.util
        from pathlib import Path as _P

        from core.coverage.journal import append_entry
        append_entry(tmp_path, self._entry(
            verdict="clean", cost_usd=1.5, model="m",
        ))
        append_entry(tmp_path, self._entry(
            verdict="suspicious",
            body="[mechanical] taint-spec echo",
            strategies=["post-loop-mechanical"],
        ))
        from importlib.machinery import SourceFileLoader
        cli_path = str(
            _P(__file__).resolve().parents[3] / "libexec" / "raptor-review",
        )
        loader = SourceFileLoader("raptor_review_cli", cli_path)
        spec = importlib.util.spec_from_loader("raptor_review_cli", loader)
        mod = importlib.util.module_from_spec(spec)
        loader.exec_module(mod)

        import io
        from contextlib import redirect_stdout

        class _Args:
            out = str(tmp_path)
            project = None
            raw = False

        buf = io.StringIO()
        with redirect_stdout(buf):
            mod.cmd_stats(_Args())
        out = buf.getvalue()
        assert "Mechanical echo rows: 1" in out
        # Verdict tally excludes the echo row: exactly one clean, no
        # suspicious line.
        assert "clean" in out
        assert "suspicious" not in out
