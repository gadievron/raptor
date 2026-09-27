"""Aggregating merge for the project index.

A run whose distinct identities exceed the per-run merge cap no
longer silently drops the oldest ones: they roll up into the index's
bounded ``aggregates`` section (per-file/per-directory counts,
verdict tallies, ts spans). Two directions under test: a hostile
flood stays bounded (record count, rollup rows, section bytes), and
a legitimate mega-run's counts are conserved — every identity is
accounted for either as a full row or inside an aggregate.

These tests scale the cap DOWN (monkeypatch) to exercise the lane
cheaply; the at-the-real-cap magnitudes — a 22k-identity run merging
as full rows, the beyond-cap lane one identity past the real cap, and
the merge byte ceiling that bounds what the count cap no longer does
— live in ``test_merge_cap_scale.py``.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

import pytest

import core.coverage.journal as journal_mod
from core.coverage.journal import (
    INDEX_FILENAME,
    IndexWriteOverBudget,
    ReviewJournalEntry,
    append_entry,
    load_index,
    load_index_aggregates,
    load_index_full,
    merge_into_index,
    now_iso,
)


def _entry(i: int, *, file: str | None = None,
           verdict: str = "clean") -> ReviewJournalEntry:
    return ReviewJournalEntry(
        ts=now_iso(),
        run_id="run-x",
        file=file if file is not None else f"src/f{i}.c",
        function=f"fn{i}",
        verdict=verdict,
        source_hash=f"hash{i}",
    )


def _mk_run(project: Path, name: str, n: int) -> Path:
    run = project / name
    run.mkdir(parents=True)
    for i in range(n):
        append_entry(run, _entry(i))
    return run


class TestConservation:
    def test_mega_run_counts_conserved(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        # The legitimate direction: a run over the cap reaches the
        # index as cap-many full rows PLUS truthful aggregates —
        # nothing silently vanishes. Scaled cap; the same lane at the
        # real cap value is pinned by test_merge_cap_scale.py.
        monkeypatch.setattr(journal_mod, "_MAX_MERGE_ENTRIES", 5)
        project = tmp_path / "project"
        run = _mk_run(project, "run1", 20)

        with caplog.at_level(logging.WARNING):
            merged = merge_into_index(project, run)

        assert merged == 5, "rollup aggregates must not count as merges"
        full = load_index_full(project)
        assert len(full) == 5
        # Newest identities survive as full rows, exactly as before.
        assert {e.function for e in full.values()} == {
            f"fn{i}" for i in range(15, 20)
        }
        aggregates = load_index_aggregates(project)
        (record,) = aggregates.values()
        assert record["identities"] == 15
        assert record["granularity"] == "file"
        assert sum(
            row["identities"] for row in record["rollups"]
        ) == 15, "rollup groups must partition the overflow"
        assert sum(
            sum(row["verdicts"].values()) for row in record["rollups"]
        ) == 15
        assert len(full) + record["identities"] == 20
        # Loud disclosure in the log too.
        assert any(
            "rollup aggregates" in r.message for r in caplog.records
        )

    def test_no_overflow_document_is_unchanged(
        self, tmp_path: Path,
    ) -> None:
        # Projects that never overflow keep the pre-aggregates
        # document shape: no "aggregates" key at all.
        project = tmp_path / "project"
        run = _mk_run(project, "run1", 3)
        merge_into_index(project, run)
        doc = json.loads((project / INDEX_FILENAME).read_text())
        assert "aggregates" not in doc
        assert len(doc["entries"]) == 3

    def test_overflow_free_merge_preserves_prior_aggregates(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # A later in-cap merge (aggregates=None → preserve) must not
        # destroy an earlier run's overflow disclosure.
        monkeypatch.setattr(journal_mod, "_MAX_MERGE_ENTRIES", 5)
        project = tmp_path / "project"
        merge_into_index(project, _mk_run(project, "run1", 20))
        assert load_index_aggregates(project)
        merge_into_index(project, _mk_run(project, "run2", 2))
        aggregates = load_index_aggregates(project)
        (record,) = aggregates.values()
        assert record["identities"] == 15

    def test_direct_write_index_preserves_aggregates(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # Writers that never think about aggregates (the legacy
        # migration script calls _write_index(path, index) directly)
        # keep the on-disk section verbatim.
        monkeypatch.setattr(journal_mod, "_MAX_MERGE_ENTRIES", 5)
        project = tmp_path / "project"
        merge_into_index(project, _mk_run(project, "run1", 20))
        path = project / INDEX_FILENAME
        journal_mod._write_index(path, {"k": _entry(0).to_dict()})
        assert load_index_aggregates(project), (
            "an aggregates-blind writer destroyed the disclosure"
        )
        assert len(load_index_full(project)) == 1


class TestGranularityCascade:
    def _overflow(self, files: list[str]) -> list[ReviewJournalEntry]:
        return [
            _entry(i, file=f) for i, f in enumerate(files)
        ]

    def test_file_granularity_within_bounds(self) -> None:
        record = journal_mod._aggregate_overflow(
            self._overflow(["src/a.c", "src/a.c", "src/b.c"]))
        assert record["granularity"] == "file"
        assert len(record["rollups"]) == 2
        assert record["identities"] == 3

    def test_cascades_to_directory(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # 9 distinct files > 2 rollup rows, but only 2 top-level
        # dirs: the cascade stops at directory granularity.
        monkeypatch.setattr(journal_mod, "_MAX_ROLLUP_ROWS", 2)
        files = [f"d{i % 2}/f{i}.c" for i in range(9)]
        record = journal_mod._aggregate_overflow(self._overflow(files))
        assert record["granularity"] == "dir"
        assert len(record["rollups"]) == 2
        assert sum(
            row["identities"] for row in record["rollups"]
        ) == 9, "cascade lost identities"

    def test_cascades_past_directory_to_total(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # 3 top-level dirs still exceed 2 rollup rows: one total row.
        monkeypatch.setattr(journal_mod, "_MAX_ROLLUP_ROWS", 2)
        files = [f"d{i % 3}/f{i}.c" for i in range(9)]
        record = journal_mod._aggregate_overflow(self._overflow(files))
        assert record["granularity"] == "total"
        (row,) = record["rollups"]
        assert row["identities"] == 9

    def test_total_row_is_the_floor(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(journal_mod, "_MAX_ROLLUP_ROWS", 1)
        files = [f"d{i}/f{i}.c" for i in range(5)]
        record = journal_mod._aggregate_overflow(self._overflow(files))
        assert record["granularity"] == "total"
        (row,) = record["rollups"]
        assert row["identities"] == 5

    def test_hostile_verdict_and_path_bounded(self) -> None:
        # Verdicts outside the enum bucket as "other" (bounded tally
        # key space); attacker-length paths truncate for display.
        long_path = "a/" + "x" * 10_000 + ".c"
        entries = [
            _entry(0, file=long_path, verdict="; DROP TABLE --"),
            _entry(1, file=long_path, verdict="clean"),
        ]
        record = journal_mod._aggregate_overflow(entries)
        (row,) = record["rollups"]
        assert row["verdicts"] == {"other": 1, "clean": 1}
        assert len(row["path"]) <= journal_mod._AGGREGATE_PATH_CHARS
        assert row["identities"] == 2


class TestSectionBounds:
    def test_record_count_bounded_newest_kept(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # The hostile direction: many overflowing run dirs accrete at
        # most _MAX_AGGREGATE_RECORDS records, newest-ts surviving.
        # (Byte-level hostility — fat rows the raised count cap now
        # admits — is bounded by the merge write ceiling, pinned in
        # test_merge_cap_scale.py.)
        monkeypatch.setattr(journal_mod, "_MAX_MERGE_ENTRIES", 2)
        monkeypatch.setattr(journal_mod, "_MAX_AGGREGATE_RECORDS", 3)
        project = tmp_path / "project"
        for n in range(5):
            merge_into_index(
                project, _mk_run(project, f"run{n}", 4))
        aggregates = load_index_aggregates(project)
        assert len(aggregates) == 3
        assert set(aggregates) == {
            "project/run2", "project/run3", "project/run4",
        }

    def test_byte_bound_evicts_largest_first(self) -> None:
        # A single hostile giant record dies before it starves the
        # honest ones.
        honest = {
            f"p/run{i}": {
                "ts": f"2026-01-01T00:00:0{i}.000000Z",
                "identities": 1,
                "granularity": "total",
                "rollups": [],
            }
            for i in range(3)
        }
        giant = dict(honest["p/run0"])
        giant["reason"] = "y" * (
            journal_mod._MAX_AGGREGATE_BYTES + 1)
        planted = {"p/giant": giant, **honest}
        bounded = journal_mod._bound_aggregates(planted)
        assert "p/giant" not in bounded
        assert set(bounded) == set(honest)

    def test_planted_shapes_dropped_and_rollups_truncated(
        self,
    ) -> None:
        planted = {
            "p/list": ["not", "a", "record"],
            "p/none": None,
            42: {"ts": "2026"},
            "p/fat": {
                "ts": "2026-01-01T00:00:00.000000Z",
                "rollups": [
                    {"scope": "file"}
                ] * (journal_mod._MAX_ROLLUP_ROWS + 7),
            },
        }
        bounded = journal_mod._bound_aggregates(planted)
        assert set(bounded) == {"p/fat"}
        assert (len(bounded["p/fat"]["rollups"])
                == journal_mod._MAX_ROLLUP_ROWS)
        assert bounded["p/fat"]["rollups_truncated"] is True

    def test_unserializable_record_dropped(self) -> None:
        planted = {
            "p/bad": {"ts": "2026", "reason": "\udcff lone surrogate"},
            "p/good": {"ts": "2026", "identities": 1},
        }
        bounded = journal_mod._bound_aggregates(planted)
        assert set(bounded) <= {"p/good", "p/bad"}
        assert "p/good" in bounded

    def test_write_over_budget_still_fail_closed(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # The IndexWriteOverBudget backstop is unchanged: aggregates
        # ride inside the same whole-document byte bound and a
        # refused write leaves the prior file untouched.
        project = tmp_path / "project"
        merge_into_index(project, _mk_run(project, "run1", 2))
        before = (project / INDEX_FILENAME).read_bytes()
        monkeypatch.setattr(journal_mod, "_MAX_JOURNAL_BYTES", 64)
        with pytest.raises(IndexWriteOverBudget):
            journal_mod._write_index(
                project / INDEX_FILENAME,
                {"k": _entry(0).to_dict()},
                aggregates={"p/run": {"ts": "2026"}},
            )
        assert (project / INDEX_FILENAME).read_bytes() == before


class TestReaderCompatibility:
    def test_readers_ignore_the_additive_key(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # Every index reader routes through _load_index → entries
        # only; an aggregates-carrying index must read identically.
        monkeypatch.setattr(journal_mod, "_MAX_MERGE_ENTRIES", 5)
        project = tmp_path / "project"
        merge_into_index(project, _mk_run(project, "run1", 20))
        doc = json.loads((project / INDEX_FILENAME).read_text())
        assert "aggregates" in doc
        assert len(load_index_full(project)) == 5
        assert len(load_index(project)) == 5
        # The write path (for_write round-trip proof) still accepts
        # the document: a second merge works.
        assert merge_into_index(
            project, _mk_run(project, "run2", 2)) == 2

    def test_hostile_aggregates_section_degrades(
        self, tmp_path: Path,
    ) -> None:
        # A planted non-object aggregates value reads as empty and
        # never crashes readers or the next writer.
        project = tmp_path / "project"
        merge_into_index(project, _mk_run(project, "run1", 2))
        path = project / INDEX_FILENAME
        doc = json.loads(path.read_text())
        doc["aggregates"] = ["planted"]
        path.write_text(json.dumps(doc))
        assert load_index_aggregates(project) == {}
        assert len(load_index_full(project)) == 2
        assert merge_into_index(
            project, _mk_run(project, "run2", 1)) == 1
