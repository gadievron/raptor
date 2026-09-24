"""Concurrency and corruption-handling tests for journal appends."""

from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
import threading
from pathlib import Path

import pytest

import core.coverage.journal as journal_mod
from core.coverage.journal import (
    ReviewJournalEntry,
    append_entry,
    load_entries,
    now_iso,
)

_REPO_ROOT = Path(__file__).resolve().parents[3]


def _entry(i: int, body_size: int = 0) -> ReviewJournalEntry:
    return ReviewJournalEntry(
        ts=now_iso(),
        run_id="run-1",
        file=f"src/f{i}.c",
        function=f"fn{i}",
        verdict="clean",
        source_hash="abc123",
        body="x" * body_size,
    )


class TestConcurrentAppend:
    def test_threaded_large_appends_never_interleave(
        self, tmp_path: Path,
    ) -> None:
        """Entries larger than PIPE_BUF appended from many threads must
        land as whole lines — the old buffered f.write through per-
        thread fds could interleave partial writes."""
        n_threads = 8
        per_thread = 5
        body_size = 16 * 1024  # comfortably > PIPE_BUF (4096)

        def worker(t: int) -> None:
            for j in range(per_thread):
                append_entry(tmp_path, _entry(t * 100 + j, body_size))

        threads = [
            threading.Thread(target=worker, args=(t,))
            for t in range(n_threads)
        ]
        for th in threads:
            th.start()
        for th in threads:
            th.join()

        raw_lines = (
            (tmp_path / "review-journal.jsonl")
            .read_text(encoding="utf-8")
            .splitlines()
        )
        assert len(raw_lines) == n_threads * per_thread
        for line in raw_lines:
            parsed = json.loads(line)  # every line is intact JSON
            assert len(parsed["body"]) == body_size

        entries = load_entries(tmp_path)
        assert len(entries) == n_threads * per_thread

    def test_single_append_round_trips(self, tmp_path: Path) -> None:
        append_entry(tmp_path, _entry(1))
        entries = load_entries(tmp_path)
        assert len(entries) == 1
        assert entries[0].function == "fn1"

    def test_cross_process_large_appends_never_interleave(
        self, tmp_path: Path,
    ) -> None:
        """Concurrent appenders in SEPARATE PROCESSES (separate fds,
        flock is the only serialiser) must land whole lines — the
        in-process threading.Lock covers none of this."""
        n_procs = 4
        per_proc = 6
        body_size = 16 * 1024  # > PIPE_BUF, forces the flock path

        script = (
            "import sys\n"
            "from pathlib import Path\n"
            "from core.coverage.journal import ("
            "ReviewJournalEntry, append_entry, now_iso)\n"
            "out = Path(sys.argv[1]); tag = int(sys.argv[2])\n"
            f"for j in range({per_proc}):\n"
            "    e = ReviewJournalEntry(ts=now_iso(), run_id='run-1',\n"
            "        file=f'src/p{tag}_{j}.c', function=f'fn{tag}_{j}',\n"
            "        verdict='clean', source_hash='abc',\n"
            f"        body='x' * {body_size})\n"
            "    append_entry(out, e)\n"
        )
        env = dict(os.environ)
        env["PYTHONPATH"] = str(_REPO_ROOT)
        procs = [
            subprocess.Popen(
                [sys.executable, "-c", script, str(tmp_path), str(t)],
                env=env, cwd=str(_REPO_ROOT),
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            for t in range(n_procs)
        ]
        for p in procs:
            _out, err = p.communicate(timeout=120)
            assert p.returncode == 0, err.decode(errors="replace")

        raw_lines = (
            (tmp_path / "review-journal.jsonl")
            .read_text(encoding="utf-8")
            .splitlines()
        )
        assert len(raw_lines) == n_procs * per_proc
        for line in raw_lines:
            parsed = json.loads(line)  # every line is intact JSON
            assert len(parsed["body"]) == body_size
        assert len(load_entries(tmp_path)) == n_procs * per_proc


class TestAppendHardening:
    def test_symlinked_journal_refused(self, tmp_path: Path) -> None:
        """A symlink planted at the journal path is refused (ELOOP)
        and the link target stays untouched — mirrors the
        ``core.json.jsonl`` trail-writer trust contract."""
        if not journal_mod._O_NOFOLLOW:
            pytest.skip("platform lacks O_NOFOLLOW")
        victim = tmp_path / "victim.txt"
        victim.write_text("untouched\n", encoding="utf-8")
        run_dir = tmp_path / "run"
        run_dir.mkdir()
        (run_dir / "review-journal.jsonl").symlink_to(victim)

        with pytest.raises(OSError):
            append_entry(run_dir, _entry(1))
        assert victim.read_text(encoding="utf-8") == "untouched\n"

    def test_short_write_rolls_back_whole_line(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A short os.write must never leave a torn tail: the partial
        bytes are truncated away and the whole line is retried."""
        append_entry(tmp_path, _entry(1))
        real_write = os.write
        calls = {"n": 0}

        def flaky_write(fd: int, data: bytes) -> int:
            calls["n"] += 1
            if calls["n"] == 1:
                # Simulate ENOSPC-style partial success.
                return real_write(fd, data[: len(data) // 2])
            return real_write(fd, data)

        monkeypatch.setattr(journal_mod.os, "write", flaky_write)
        append_entry(tmp_path, _entry(2, body_size=8 * 1024))
        monkeypatch.undo()

        raw_lines = (
            (tmp_path / "review-journal.jsonl")
            .read_text(encoding="utf-8")
            .splitlines()
        )
        assert len(raw_lines) == 2
        for line in raw_lines:
            json.loads(line)
        assert len(load_entries(tmp_path)) == 2

    def test_persistent_short_write_raises_and_stays_intact(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        append_entry(tmp_path, _entry(1))
        real_write = os.write

        def always_short(fd: int, data: bytes) -> int:
            return real_write(fd, data[: max(1, len(data) // 2)])

        monkeypatch.setattr(journal_mod.os, "write", always_short)
        with pytest.raises(OSError):
            append_entry(tmp_path, _entry(2, body_size=4096))
        monkeypatch.undo()

        # The failed append left no torn tail behind.
        raw_lines = (
            (tmp_path / "review-journal.jsonl")
            .read_text(encoding="utf-8")
            .splitlines()
        )
        assert len(raw_lines) == 1
        json.loads(raw_lines[0])


class TestCorruptLineCounting:
    def test_corrupt_lines_counted_and_warned(
        self, tmp_path: Path, caplog,
    ) -> None:
        append_entry(tmp_path, _entry(1))
        journal = tmp_path / "review-journal.jsonl"
        with open(journal, "a", encoding="utf-8") as f:
            f.write("{truncated\n")
            f.write("also not json\n")
        append_entry(tmp_path, _entry(2))

        with caplog.at_level(logging.WARNING, logger="core.coverage.journal"):
            entries = load_entries(tmp_path)

        assert len(entries) == 2
        agg = [
            r for r in caplog.records
            if "skipped 2 corrupt line(s)" in r.getMessage()
        ]
        assert agg, "aggregate corrupt-line warning expected"

    def test_planted_unknown_schema_version_row_quarantined(
        self, tmp_path: Path, caplog,
    ) -> None:
        # The journal lives inside the run dir — SANDBOX-WRITABLE —
        # so a planted schema_version!=1 row must be skipped with a
        # warning. Pre-fix _entry_from_dict's ValueError escaped
        # load_entries and persistently crashed every journal
        # consumer (audit resume, reports, completion merge).
        append_entry(tmp_path, _entry(1))
        journal = tmp_path / "review-journal.jsonl"
        with open(journal, "a", encoding="utf-8") as f:
            f.write(json.dumps({"schema_version": 999}) + "\n")
        append_entry(tmp_path, _entry(2))

        with caplog.at_level(logging.WARNING, logger="core.coverage.journal"):
            entries = load_entries(tmp_path)

        assert len(entries) == 2
        assert any(
            "skipping malformed entry" in r.getMessage()
            for r in caplog.records
        )

    def test_planted_non_dict_json_rows_quarantined(
        self, tmp_path: Path, caplog,
    ) -> None:
        # Valid JSON that is NOT a dict (null / list / string / bare
        # number) parses fine but has no .get — pre-gate it raised
        # AttributeError past the per-row except tuple and crashed
        # load_entries. All four shapes must quarantine per-row.
        append_entry(tmp_path, _entry(1))
        journal = tmp_path / "review-journal.jsonl"
        with open(journal, "a", encoding="utf-8") as f:
            for planted in ("null", "[1, 2, 3]", '"x"', "12345"):
                f.write(planted + "\n")
        append_entry(tmp_path, _entry(2))

        with caplog.at_level(logging.WARNING, logger="core.coverage.journal"):
            entries = load_entries(tmp_path)

        assert len(entries) == 2
        non_dict = [
            r for r in caplog.records
            if "skipping non-dict entry" in r.getMessage()
        ]
        assert len(non_dict) == 4

    def test_planted_null_row_never_persistently_crashes_consumers(
        self, tmp_path: Path,
    ) -> None:
        # The journal lives inside the sandbox-writable run dir: one
        # planted 5-byte row ("null\n") must not wedge the journal —
        # every subsequent load AND append must keep working, with the
        # legit rows intact.
        append_entry(tmp_path, _entry(1))
        journal = tmp_path / "review-journal.jsonl"
        with open(journal, "a", encoding="utf-8") as f:
            f.write("null\n")

        assert len(load_entries(tmp_path)) == 1
        append_entry(tmp_path, _entry(2))
        assert len(load_entries(tmp_path)) == 2
        assert len(load_entries(tmp_path)) == 2


def _base_row() -> dict:
    """A minimal well-shaped dict row (passes every gate as written)."""
    return {
        "ts": now_iso(),
        "run_id": "r-planted",
        "file": "src/p.c",
        "function": "pf",
        "verdict": "clean",
        "schema_version": 1,
    }


_TYPED_FIELDS = sorted(
    name for name in journal_mod._field_types()
    if name not in journal_mod._CLAMPED_FIELDS
    and name != "schema_version"
)

_LIST_FIELDS = sorted(
    name for name in _TYPED_FIELDS
    if journal_mod._value_matches([], journal_mod._field_types()[name])
)


class TestPlantedTypedFieldRows:
    """Wrong-TYPED fields inside a well-shaped dict row must quarantine.

    The non-dict gate above contains bad row SHAPES; these pin the
    field-TYPE boundary one enumeration step further out: a dict row
    with ``"file": 5`` crashed ``encode_key_file`` inside every
    ``reviewed_set()`` call, and an int ``ts`` crashed the ordering
    compares in ``latest_entries`` and ``merge_into_index``. The
    parametrization enumerates the WHOLE dataclass schema, so a field
    added later is covered from birth.
    """

    def _plant(self, tmp_path: Path, row: dict) -> None:
        append_entry(tmp_path, _entry(1))
        journal = tmp_path / "review-journal.jsonl"
        with open(journal, "a", encoding="utf-8") as f:
            f.write(json.dumps(row) + "\n")
        append_entry(tmp_path, _entry(2))

    @pytest.mark.parametrize("field_name", _TYPED_FIELDS)
    def test_wrong_typed_field_quarantines_row(
        self, tmp_path: Path, caplog, field_name: str,
    ) -> None:
        # Self-check: {} conforms to NO field annotation in the current
        # schema — a future dict-typed field would silently make this
        # parametrization vacuous for itself, so assert the premise.
        expected = journal_mod._field_types()[field_name]
        assert not journal_mod._value_matches({}, expected)

        row = _base_row()
        row[field_name] = {}
        self._plant(tmp_path, row)

        with caplog.at_level(logging.WARNING, logger="core.coverage.journal"):
            entries = load_entries(tmp_path)

        assert len(entries) == 2
        assert any(
            "skipping malformed entry" in r.getMessage()
            and repr(field_name) in r.getMessage()
            for r in caplog.records
        )

    @pytest.mark.parametrize("field_name", _LIST_FIELDS)
    def test_wrong_typed_list_element_quarantines_row(
        self, tmp_path: Path, caplog, field_name: str,
    ) -> None:
        # Element depth matters: a non-str element in strategies
        # crashes _canonical_strategy_hash's sorted-join inside
        # index_key at merge time; a non-dict hypothesis element
        # crashes consumers keying h.get(...).
        expected = journal_mod._field_types()[field_name]
        assert not journal_mod._value_matches([5], expected)

        row = _base_row()
        row[field_name] = [5]
        self._plant(tmp_path, row)

        with caplog.at_level(logging.WARNING, logger="core.coverage.journal"):
            entries = load_entries(tmp_path)

        assert len(entries) == 2

    def test_dict_element_values_stay_free_form(self, tmp_path: Path) -> None:
        # Both-directions boundary: dict VALUES inside list elements
        # are LLM-derived free-form (consumers guard/format them) —
        # over-strictening here would retroactively quarantine
        # legitimate historical rows.
        row = _base_row()
        row["hypotheses"] = [{"mechanism": "m", "confidence": 0.7}]
        row["study_receipts"] = [{"question": "q", "tier": 1}]
        self._plant(tmp_path, row)

        assert len(load_entries(tmp_path)) == 3

    def test_int_accepted_where_float_expected(self, tmp_path: Path) -> None:
        # JSON has a single number type: a writer emitting 1 for a
        # float field must keep loading.
        row = _base_row()
        row["confidence"] = 1
        row["cost_usd"] = 2
        self._plant(tmp_path, row)

        assert len(load_entries(tmp_path)) == 3

    def test_bool_rejected_where_int_expected(self, tmp_path: Path) -> None:
        # isinstance(True, int) holds — a bool token_budget is a
        # planted shape, not a number.
        row = _base_row()
        row["token_budget"] = True
        self._plant(tmp_path, row)

        assert len(load_entries(tmp_path)) == 2

    def test_wrong_typed_span_fields_clamp_not_quarantine(
        self, tmp_path: Path,
    ) -> None:
        # Span fields keep their pre-existing containment discipline:
        # a forged/wrong-typed span is CLAMPED while the rest of the
        # row's evidence is kept (see _entry_from_dict).
        row = _base_row()
        row["line_start"] = "9"
        row["line_end"] = {}
        self._plant(tmp_path, row)

        entries = load_entries(tmp_path)
        assert len(entries) == 3
        planted = [e for e in entries if e.run_id == "r-planted"]
        assert planted[0].line_start == 0
        assert planted[0].line_end is None

    def test_planted_typed_rows_never_persistently_crash_consumers(
        self, tmp_path: Path,
    ) -> None:
        # The finding's exact repro rows: "file": 5 (crashed
        # reviewed_set via encode_key_file) and an int ts sharing a
        # key with a real row (crashed the ts ordering compares in
        # latest_entries AND merge_into_index). All consumers must
        # keep working on every subsequent load.
        append_entry(tmp_path, _entry(1))
        journal = tmp_path / "review-journal.jsonl"
        real = load_entries(tmp_path)[0]
        with open(journal, "a", encoding="utf-8") as f:
            row = _base_row()
            row["file"] = 5
            f.write(json.dumps(row) + "\n")
            f.write(json.dumps({
                "ts": 7, "run_id": "r", "file": real.file,
                "function": real.function, "verdict": "clean",
                "schema_version": 1,
            }) + "\n")

        assert journal_mod.reviewed_set(tmp_path) == {real.key}
        assert set(journal_mod.latest_entries(tmp_path)) == {real.key}
        project = tmp_path / "project"
        assert journal_mod.merge_into_index(project, tmp_path) == 1
        append_entry(tmp_path, _entry(2))
        assert len(load_entries(tmp_path)) == 2


class TestSchemaValidatorClosure:
    """Every dataclass field's annotation must be handled by the
    validator — a new field with an unsupported type fails HERE at
    development time instead of quarantining every row that carries
    it in production (the validator fails closed on unknown types)."""

    @staticmethod
    def _sample(expected):
        import types as _types
        import typing as _typing
        origin = _typing.get_origin(expected)
        if origin in (_typing.Union, _types.UnionType):
            args = [
                a for a in _typing.get_args(expected) if a is not type(None)
            ]
            return TestSchemaValidatorClosure._sample(args[0])
        if origin is list or expected is list:
            args = _typing.get_args(expected)
            if not args:
                return []
            return [TestSchemaValidatorClosure._sample(args[0])]
        if origin is dict or expected is dict:
            return {}
        if expected is bool:
            return True
        if expected is int:
            return 1
        if expected is float:
            return 1.0
        if expected is str:
            return "x"
        msg = f"no sample generator for annotation {expected!r} — extend _value_matches AND this generator"
        raise AssertionError(msg)

    def test_every_field_annotation_has_a_validator_arm(self) -> None:
        import dataclasses
        hints = journal_mod._field_types()
        field_names = {
            f.name for f in dataclasses.fields(ReviewJournalEntry)
        }
        assert set(hints) == field_names
        for name, expected in hints.items():
            conforming = self._sample(expected)
            assert journal_mod._value_matches(conforming, expected), (
                f"conforming sample rejected for field {name!r} "
                f"({expected!r})"
            )
            assert not journal_mod._value_matches(object(), expected), (
                f"arbitrary object accepted for field {name!r} "
                f"({expected!r}) — validator arm missing/too wide"
            )


class TestSerializationHostility:
    """Typed-VALID but content-hostile values must quarantine at row
    acceptance.

    A lone surrogate inside a str field (pure-ASCII ``\\ud800`` escape
    on the wire) and a float that overflowed to ``inf`` at parse
    (``1e400`` — ``parse_constant`` fires only on the literal
    ``NaN``/``Infinity`` tokens) both pass the TYPE arms and detonate
    at the write boundary — ``save_json`` inside the merge flock — on
    stdlib-json environments. orjson refuses both shapes at parse, but
    orjson is optional, so these force the stdlib arm explicitly; the
    unpatched tests pin the natural arm's containment too.
    """

    _SURROGATE_LINE = (
        '{"ts": "2099-01-01T00:00:00.000001+00:00", "run_id": "r-pl", '
        '"file": "src/p.c", "function": "pf", "verdict": "clean", '
        '"schema_version": 1, "body": "\\ud800evil"}'
    )
    _INF_LINE = (
        '{"ts": "2099-01-01T00:00:00.000001+00:00", "run_id": "r-pl", '
        '"file": "src/p.c", "function": "pf", "verdict": "clean", '
        '"schema_version": 1, "confidence": 1e400}'
    )

    @staticmethod
    def _force_stdlib_json(monkeypatch) -> None:
        import core.json.utils as json_utils
        monkeypatch.setattr(json_utils, "_orjson", None)

    def _plant(self, tmp_path: Path, line: str) -> None:
        append_entry(tmp_path, _entry(1))
        journal = tmp_path / "review-journal.jsonl"
        with open(journal, "a", encoding="ascii") as f:
            f.write(line + "\n")
        append_entry(tmp_path, _entry(2))

    @pytest.mark.parametrize("line", [_SURROGATE_LINE, _INF_LINE])
    def test_hostile_row_quarantined_on_stdlib_arm(
        self, tmp_path: Path, monkeypatch, line: str,
    ) -> None:
        self._force_stdlib_json(monkeypatch)
        self._plant(tmp_path, line)

        entries = load_entries(tmp_path)

        assert len(entries) == 2
        assert all(e.run_id == "run-1" for e in entries)

    @pytest.mark.parametrize("line", [_SURROGATE_LINE, _INF_LINE])
    def test_hostile_row_contained_on_natural_arm(
        self, tmp_path: Path, line: str,
    ) -> None:
        # No arm forced: with orjson installed the planted line is
        # refused at parse (corrupt-line skip); without it the row
        # quarantines at validation. Both arms: siblings load.
        self._plant(tmp_path, line)

        assert len(load_entries(tmp_path)) == 2

    @pytest.mark.parametrize("line", [_SURROGATE_LINE, _INF_LINE])
    def test_planted_row_never_persistently_crashes_merge(
        self, tmp_path: Path, monkeypatch, line: str,
    ) -> None:
        # The write-boundary repro: pre-fix, the planted row was
        # ACCEPTED by the loader and every run-completion merge then
        # crashed inside the flock at save_json (UnicodeEncodeError /
        # allow_nan=False ValueError) — on EVERY retry.
        self._force_stdlib_json(monkeypatch)
        self._plant(tmp_path, line)
        project = tmp_path / "project"

        assert journal_mod.merge_run_into_index(project, tmp_path) == 2
        # Retry parity: the merge stays alive on every subsequent run.
        assert journal_mod.merge_run_into_index(project, tmp_path) == 0
        index = journal_mod.load_index(project)
        assert {e.run_id for e in index.values()} == {"run-1"}

    def test_serializer_roundtrip_is_the_invariant(self) -> None:
        # Class closure: the validator delegates to the serializer's
        # own strictness pins, not an enumerated hostile-value list.
        with pytest.raises(ValueError, match="round-trip"):
            journal_mod._validate_serializable({"body": "\ud800evil"})
        with pytest.raises(ValueError, match="round-trip"):
            journal_mod._validate_serializable({"confidence": float("inf")})
        with pytest.raises(ValueError, match="round-trip"):
            journal_mod._validate_serializable(
                {"hypotheses": [{"note": float("nan")}]},
            )
        journal_mod._validate_serializable({"body": "café", "ok": 1.0})

    @pytest.mark.parametrize("version", ["true", "1.0"])
    def test_non_int_schema_version_quarantines(
        self, tmp_path: Path, version: str,
    ) -> None:
        # True == 1 and 1.0 == 1 both slip a bare equality compare —
        # the version marker must be a genuine int.
        row_json = (
            '{"ts": "2099-01-01T00:00:00.000001+00:00", "run_id": "r-pl", '
            '"file": "src/p.c", "function": "pf", "verdict": "clean", '
            '"schema_version": ' + version + "}"
        )
        self._plant(tmp_path, row_json)

        assert len(load_entries(tmp_path)) == 2


class TestJournalByteBudget:
    """Journal loads are memory-bounded but NEVER fail open: an
    over-budget journal keeps loading what fits (duplicate
    re-emissions pruned losslessly first), the load flags incomplete
    when rows were actually lost, and spend-authorizing consumers
    refuse an incomplete load instead of reading a partial journal
    as 'nothing was reviewed' (the old size gate returned [] and a
    resume re-bought every prior verdict)."""

    def test_over_budget_journal_still_loads_flagged_incomplete(
        self, tmp_path: Path, monkeypatch,
    ) -> None:
        append_entry(tmp_path, _entry(1))
        append_entry(tmp_path, _entry(2))
        size = (tmp_path / "review-journal.jsonl").stat().st_size
        monkeypatch.setattr(journal_mod, "_MAX_JOURNAL_BYTES", size - 1)
        loaded = journal_mod.load_entries_checked(tmp_path)
        # Distinct live rows cannot prune, so the load is partial —
        # but everything read up to the stop IS returned.
        assert loaded.entries, "over-budget journal read as empty"
        assert not loaded.complete
        assert load_entries(tmp_path) == loaded.entries

    def test_incomplete_load_refused_for_spend_callers(
        self, tmp_path: Path, monkeypatch,
    ) -> None:
        append_entry(tmp_path, _entry(1))
        append_entry(tmp_path, _entry(2))
        size = (tmp_path / "review-journal.jsonl").stat().st_size
        monkeypatch.setattr(journal_mod, "_MAX_JOURNAL_BYTES", size - 1)
        with pytest.raises(journal_mod.JournalIncomplete) as exc_info:
            journal_mod.require_complete_entries(tmp_path)
        # The refusal names the operator remedy.
        assert "journal compact" in str(exc_info.value)

    def test_complete_load_passes_spend_callers(
        self, tmp_path: Path,
    ) -> None:
        append_entry(tmp_path, _entry(1))
        entries = journal_mod.require_complete_entries(tmp_path)
        assert [e.function for e in entries] == ["fn1"]

    def test_reemission_rows_prune_within_budget(
        self, tmp_path: Path, monkeypatch,
    ) -> None:
        """A journal dominated by duplicate reused re-emissions (the
        resume-segment shape) loads COMPLETE past the byte budget:
        pruning keeps the newest row per identity and loses no
        verdict, key, or spend evidence."""
        live = _entry(1)
        live.cost_usd = 0.42
        append_entry(tmp_path, live)
        for _ in range(6):
            dup = _entry(1)
            dup.reused = True
            dup.reused_from_run = "run-0"
            dup.cost_usd = 0.0
            append_entry(tmp_path, dup)
        size = (tmp_path / "review-journal.jsonl").stat().st_size
        monkeypatch.setattr(journal_mod, "_MAX_JOURNAL_BYTES", size // 2)
        loaded = journal_mod.load_entries_checked(tmp_path)
        assert loaded.complete
        assert loaded.pruned > 0
        # The newest reused row and the $-bearing live row survive.
        assert sum(1 for e in loaded.entries if e.reused) == 1
        assert any(e.cost_usd == 0.42 for e in loaded.entries)
        assert {e.key for e in loaded.entries} == {"src/f1.c:fn1"}

    def test_journal_at_cap_still_loads(
        self, tmp_path: Path, monkeypatch,
    ) -> None:
        append_entry(tmp_path, _entry(1))
        size = (tmp_path / "review-journal.jsonl").stat().st_size
        monkeypatch.setattr(journal_mod, "_MAX_JOURNAL_BYTES", size)
        assert len(load_entries(tmp_path)) == 1

    def test_overlong_line_quarantined_neighbours_load(
        self, tmp_path: Path, monkeypatch,
    ) -> None:
        """A single line past the per-line bound quarantines as a row
        (streamed past, never buffered) while its neighbours load."""
        append_entry(tmp_path, _entry(1))
        journal = tmp_path / "review-journal.jsonl"
        with journal.open("ab") as fh:
            fh.write(b'{"pad": "' + b"A" * 4096 + b'"}\n')
        append_entry(tmp_path, _entry(2))
        monkeypatch.setattr(journal_mod, "_MAX_JOURNAL_LINE_BYTES", 1024)
        loaded = journal_mod.load_entries_checked(tmp_path)
        assert [e.function for e in loaded.entries] == ["fn1", "fn2"]
        assert loaded.complete

    def test_retained_entry_count_bounded(
        self, tmp_path: Path, monkeypatch,
    ) -> None:
        """A flood of distinct minimal rows under the byte budget is
        bounded by the COUNT cap (per-entry object overhead is what
        OOMs the reader, not raw bytes) and flags incomplete."""
        journal = tmp_path / "review-journal.jsonl"
        rows = b"".join(
            json.dumps({
                "ts": now_iso(), "run_id": "r", "file": f"h{i}.c",
                "function": f"h{i}", "verdict": "clean",
                "schema_version": 1,
            }).encode() + b"\n"
            for i in range(50)
        )
        journal.write_bytes(rows)
        monkeypatch.setattr(journal_mod, "_MAX_RETAINED_ENTRIES", 20)
        loaded = journal_mod.load_entries_checked(tmp_path)
        assert not loaded.complete
        assert len(loaded.entries) <= 22

    def test_oversize_index_starts_fresh(
        self, tmp_path: Path, monkeypatch,
    ) -> None:
        index_path = tmp_path / journal_mod.INDEX_FILENAME
        index_path.write_text(json.dumps({
            "schema_version": journal_mod.INDEX_SCHEMA_VERSION,
            "entries": {"k": {"padding": "x" * 4096}},
        }))
        monkeypatch.setattr(journal_mod, "_MAX_JOURNAL_BYTES", 64)
        assert journal_mod._load_index(index_path) == {}
        monkeypatch.setattr(journal_mod, "_MAX_JOURNAL_BYTES", 1 << 20)
        assert "k" in journal_mod._load_index(index_path)


class TestIndexShapeGuards:
    """Index-side twins of the journal reader's shape gates.

    The index is reachable via a /project archive import, so its
    "entries" value and every entry value are attacker-shapeable: a
    list/null "entries" passed the top-level dict gate and crashed
    every consumer's .items()/.get, and the writer path crashed
    INSIDE the merge flock — every run-completion merge against such
    an index failed with a raw traceback instead of the designed
    loud refusal.
    """

    def _run_with_entry(self, tmp_path: Path, i: int = 1) -> Path:
        run = tmp_path / f"run{i}"
        run.mkdir(exist_ok=True)
        append_entry(run, _entry(i))
        return run

    @pytest.mark.parametrize("planted", ["[1, 2]", "null", '"x"', "7"])
    def test_non_object_entries_reads_empty(
        self, tmp_path: Path, caplog, planted: str,
    ) -> None:
        index_path = tmp_path / journal_mod.INDEX_FILENAME
        index_path.write_text('{"entries": ' + planted + "}")

        with caplog.at_level(logging.WARNING, logger="core.coverage.journal"):
            assert journal_mod.load_index_full(tmp_path) == {}

        assert any(
            "non-object 'entries'" in r.getMessage()
            for r in caplog.records
        )

    def test_non_object_entries_refuses_merge_file_untouched(
        self, tmp_path: Path,
    ) -> None:
        # Writer discipline: IndexUnreadable, never a rewrite — the
        # unknown content might be history a newer schema wrote.
        index_path = tmp_path / journal_mod.INDEX_FILENAME
        index_path.write_text('{"entries": [1, 2]}')
        run = self._run_with_entry(tmp_path)

        assert journal_mod.merge_into_index(tmp_path, run) == 0
        assert index_path.read_text() == '{"entries": [1, 2]}'

    @pytest.mark.parametrize("planted", ["null", "[1]", '"x"', "7"])
    def test_non_object_entry_value_skipped_by_reader(
        self, tmp_path: Path, caplog, planted: str,
    ) -> None:
        index_path = tmp_path / journal_mod.INDEX_FILENAME
        index_path.write_text('{"entries": {"k": ' + planted + "}}")

        with caplog.at_level(logging.WARNING, logger="core.coverage.journal"):
            assert journal_mod.load_index_full(tmp_path) == {}

        assert any(
            "skipping k: not an object" in r.getMessage()
            for r in caplog.records
        )

    def test_non_object_entry_value_left_in_place_by_merge(
        self, tmp_path: Path,
    ) -> None:
        # Row-level disposition mirrors the unparseable-dict-row rule:
        # leave in place, never drop — but the merge itself (and the
        # re-home walk over the planted key) must proceed.
        index_path = tmp_path / journal_mod.INDEX_FILENAME
        index_path.write_text('{"entries": {"k": null}}')
        run = self._run_with_entry(tmp_path)

        assert journal_mod.merge_into_index(tmp_path, run) == 1

        entries = json.loads(index_path.read_text())["entries"]
        assert "k" in entries and entries["k"] is None
        assert len(entries) == 2

    def test_occupied_key_with_non_str_ts_loses_without_crash(
        self, tmp_path: Path,
    ) -> None:
        # A planted dict row with an int ts at the exact index_key of
        # an incoming entry crashed the `>` compare inside the flock;
        # garbage ts must read as "" (older than every real stamp).
        run = self._run_with_entry(tmp_path)
        assert journal_mod.merge_into_index(tmp_path, run) == 1
        index_path = tmp_path / journal_mod.INDEX_FILENAME
        data = json.loads(index_path.read_text())
        key = next(iter(data["entries"]))
        data["entries"][key]["ts"] = 7
        index_path.write_text(json.dumps(data))

        run2 = tmp_path / "run2"
        run2.mkdir()
        newer = _entry(1)
        newer.verdict = "finding"
        append_entry(run2, newer)

        assert journal_mod.merge_into_index(tmp_path, run2) == 1
        assert journal_mod.load_index(tmp_path)[newer.key].verdict == "finding"

    _HOSTILE_INDEXES = [
        # Lone surrogate inside a preserved row (pure-ASCII bytes).
        '{"entries": {"k": {"body": "\\ud800evil"}}}',
        # Overflow-to-inf float (1e400 parses to inf on stdlib json;
        # parse_constant fires only on literal NaN/Infinity tokens).
        '{"entries": {"k": {"confidence": 1e400}}}',
    ]

    @pytest.mark.parametrize("planted", _HOSTILE_INDEXES)
    def test_content_hostile_preserved_row_refuses_merge_file_untouched(
        self, tmp_path: Path, monkeypatch, planted: str,
    ) -> None:
        # Write-boundary class: never-drop keeps rows that fail row
        # validation, and the writer serializes the WHOLE entries
        # dict — pre-fix, a planted row the serializer refuses
        # (UnicodeEncodeError at the utf-8 encode / allow_nan=False
        # ValueError) crashed save_json inside the merge flock on
        # EVERY retry. The writer must refuse loudly instead, file
        # untouched — parity with orjson environments, where the same
        # planted index refuses at parse.
        import core.json.utils as json_utils
        monkeypatch.setattr(json_utils, "_orjson", None)
        index_path = tmp_path / journal_mod.INDEX_FILENAME
        index_path.write_text(planted, encoding="ascii")
        run = self._run_with_entry(tmp_path)

        assert journal_mod.merge_into_index(tmp_path, run) == 0
        # Retry parity — refusal, never a crash, on every attempt.
        assert journal_mod.merge_into_index(tmp_path, run) == 0
        assert index_path.read_text(encoding="ascii") == planted
        # The reader side degrades row-by-row, never crashes.
        assert journal_mod.load_index_full(tmp_path) == {}

    @pytest.mark.parametrize("planted", _HOSTILE_INDEXES)
    def test_content_hostile_index_contained_on_natural_arm(
        self, tmp_path: Path, planted: str,
    ) -> None:
        # No arm forced: orjson refuses the planted bytes at parse
        # (unreadable-index refusal); stdlib refuses at the new
        # write-boundary proof. Both arms: merge 0, file untouched.
        index_path = tmp_path / journal_mod.INDEX_FILENAME
        index_path.write_text(planted, encoding="ascii")
        run = self._run_with_entry(tmp_path)

        assert journal_mod.merge_into_index(tmp_path, run) == 0
        assert index_path.read_text(encoding="ascii") == planted


class TestNonFiniteWriteParity:
    """The reader skips NaN/Infinity lines as malformed, so the writer
    must fail loudly instead of emitting a row the next read drops."""

    def test_append_rejects_non_finite_field(self, tmp_path: Path):
        e = _entry(1)
        e.confidence = float("nan")
        with pytest.raises(ValueError):
            append_entry(tmp_path, e)
        # No torn/partial line left behind.
        journal = tmp_path / journal_mod.JOURNAL_FILENAME
        assert not journal.exists() or journal.read_text() == ""

    def test_finite_fields_round_trip(self, tmp_path: Path):
        e = _entry(2)
        e.confidence = 0.75
        append_entry(tmp_path, e)
        loaded = load_entries(tmp_path)
        assert len(loaded) == 1
        assert loaded[0].confidence == 0.75
