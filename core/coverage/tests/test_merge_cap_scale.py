"""Two-direction regression tests for the per-run merge cap and the
merge byte ceiling.

``_MAX_MERGE_ENTRIES`` is sized so legitimate mega-runs reach the
project index as FULL rows (a self-audit measures ~22k distinct
identities; a kernel-scope audit ~10^5) — full rows carry the verdict
detail that cross-run $0 reuse imports, aggregates carry only tallies.
The other direction is bounded by BYTES, not the count cap: the merge
write ceiling sheds a fat run's oldest identities to the aggregates
section instead of freezing the index, so raising the count cap never
re-opens the frozen-index failure the byte gate closed.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import core.coverage.journal as journal_mod
from core.coverage.journal import (
    INDEX_FILENAME,
    JOURNAL_FILENAME,
    IndexWriteOverBudget,
    ReviewJournalEntry,
    load_index,
    load_index_aggregates,
    load_index_full,
    merge_into_index,
    now_iso,
)


def _write_run(project: Path, name: str, n: int,
               verdict: str = "clean") -> Path:
    """A run journal of n distinct tiny identities, written directly
    (append_entry at this row count would dominate the test)."""
    run = project / name
    run.mkdir(parents=True)
    ts = now_iso()
    lines = (
        json.dumps({
            "ts": ts, "run_id": "run-x",
            "file": f"src/d{i % 97}/f{i}.c", "function": f"fn{i}",
            "verdict": verdict, "source_hash": f"h{i}",
            "schema_version": 1,
        })
        for i in range(n)
    )
    (run / JOURNAL_FILENAME).write_text("\n".join(lines) + "\n")
    return run


def _claim_row(i: int, *, ts: str | None = None,
               body_bytes: int = 900) -> dict:
    """A suspicious (claim) row: the write-boundary slim never touches
    it, so its inline body genuinely occupies index bytes."""
    return {
        "ts": ts or now_iso(), "run_id": "run-x",
        "file": f"src/g{i}.c", "function": f"gfn{i}",
        "verdict": "suspicious", "source_hash": f"h{i}",
        "schema_version": 1, "body": "x" * body_bytes,
    }


def _write_claim_run(project: Path, name: str,
                     rows: list[dict]) -> Path:
    run = project / name
    run.mkdir(parents=True)
    (run / JOURNAL_FILENAME).write_text(
        "\n".join(json.dumps(r) for r in rows) + "\n")
    return run


class TestCapValue:
    def test_cap_admits_mega_runs(self) -> None:
        # Too-low direction: the cap must clear real mega-run shapes
        # (a 22k-identity self-audit, a ~10^5-function kernel-scope
        # audit) so their verdicts reach the index as full rows.
        assert journal_mod._MAX_MERGE_ENTRIES >= 150_000

    def test_cap_stays_under_reader_memory_precedent(self) -> None:
        # Too-high direction: the merge holds one parsed entry object
        # (~1 KiB overhead) per identity in memory; the established
        # reader-side bound for that shape is _MAX_RETAINED_ENTRIES.
        assert (journal_mod._MAX_MERGE_ENTRIES
                <= journal_mod._MAX_RETAINED_ENTRIES)


class TestMegaRunFullRows:
    def test_self_audit_scale_run_merges_as_full_rows(
        self, tmp_path: Path,
    ) -> None:
        # The real, un-monkeypatched cap: a 22k-identity run (the
        # measured self-audit shape) merges every identity as a full
        # row — no aggregates, no truncation disclosure needed.
        project = tmp_path / "project"
        run = _write_run(project, "run1", 22_000)
        assert merge_into_index(project, run) == 22_000
        doc = json.loads((project / INDEX_FILENAME).read_text())
        assert len(doc["entries"]) == 22_000
        assert "aggregates" not in doc

    # Real-cap beyond-cap run: genuinely heavy (a 150k-row parse +
    # 80 MB index write, ~5s unloaded — past the default tier's
    # budget under loaded-runner variance). Trade-off, both
    # directions: unmarking it puts a multi-second test in every PR
    # run; marking it WITHOUT the scaled conservation tests in
    # test_index_aggregates.py (same lane, monkeypatched cap) would
    # leave the beyond-cap aggregate lane unasserted until nightly.
    # The scaled tests exercise the identical collapse → cap-slice →
    # _aggregate_overflow path daily; only the at-the-real-cap
    # magnitudes wait for nightly.
    @pytest.mark.slow
    def test_beyond_cap_lane_alive_at_the_real_cap(
        self, tmp_path: Path,
    ) -> None:
        # One identity past the REAL cap: the newest cap-full merge
        # as full rows, the overflow reaches the aggregates section,
        # counts conserved — the beyond-cap lane is alive at the new
        # cap value, not only under monkeypatched miniatures.
        cap = journal_mod._MAX_MERGE_ENTRIES
        project = tmp_path / "project"
        run = _write_run(project, "run1", cap + 1)
        assert merge_into_index(project, run) == cap
        full = load_index_full(project)
        assert len(full) == cap
        (record,) = load_index_aggregates(project).values()
        assert record["identities"] == 1
        assert len(full) + record["identities"] == cap + 1


class TestMergeByteCeiling:
    """The byte-bound direction the raised count cap hands over to
    the merge write ceiling: fat runs degrade to aggregates, the
    index never freezes."""

    def _scale(self, monkeypatch: pytest.MonkeyPatch,
               budget: int = 8 * 1024) -> int:
        # Scaled budget stands in for the 256 MiB default; the merge
        # ceiling floors at half of it.
        monkeypatch.setattr(journal_mod, "_MAX_JOURNAL_BYTES", budget)
        return budget // 2

    def test_fat_flood_degrades_and_never_freezes(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # 16 KiB budget (ceiling 8 KiB): the monkeypatched budget also
        # bounds the run-journal READER, so the flood must stay under
        # the reader's retained-byte budget to arrive whole.
        self._scale(monkeypatch, budget=16 * 1024)
        project = tmp_path / "project"
        project.mkdir()
        rows = [_claim_row(i, body_bytes=1500) for i in range(8)]
        run = _write_claim_run(project, "run1", rows)
        merged = merge_into_index(project, run)
        index_path = project / INDEX_FILENAME
        # Written document honours the read budget; shed identities
        # are disclosed with counts conserved.
        assert index_path.stat().st_size <= 16 * 1024
        assert 0 < merged < 8
        assert merged == len(load_index_full(project))
        (record,) = load_index_aggregates(project).values()
        assert merged + record["identities"] == 8
        # NEWEST identities survive as full rows (eviction sheds
        # oldest-first, matching the count-cap convention).
        survivors = {e.function for e in load_index_full(project).values()}
        assert survivors == {
            f"gfn{i}" for i in range(8 - merged, 8)}
        # Never frozen: a later merge still lands.
        run2 = _write_claim_run(
            project, "run2", [_claim_row(100, body_bytes=10)])
        assert merge_into_index(project, run2) == 1

    def test_count_and_byte_overflow_share_one_disclosure(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # Both degradations at once: the count cap rolls up the
        # oldest identities, the byte ceiling then sheds more — one
        # aggregates record accounts for all of them.
        self._scale(monkeypatch, budget=16 * 1024)
        monkeypatch.setattr(journal_mod, "_MAX_MERGE_ENTRIES", 5)
        project = tmp_path / "project"
        project.mkdir()
        rows = [_claim_row(i, ts=f"2026-01-01T00:00:{i:02d}.000000Z",
                           body_bytes=1500)
                for i in range(7)]
        run = _write_claim_run(project, "run1", rows)
        merged = merge_into_index(project, run)
        (record,) = load_index_aggregates(project).values()
        assert merged == len(load_index_full(project))
        assert merged + record["identities"] == 7
        assert record["identities"] >= 2   # at least the count overflow
        assert merged < 5                  # …and the byte ceiling shed more

    def test_eviction_restores_the_displaced_prior_row(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # An evicted incoming identity must not take pre-existing
        # history with it: the row it displaced comes back.
        self._scale(monkeypatch, budget=16 * 1024)
        project = tmp_path / "project"
        project.mkdir()
        old = _claim_row(0, ts="2026-01-01T00:00:00.000000Z",
                         body_bytes=10)
        old_key = ReviewJournalEntry(**{
            k: v for k, v in old.items() if k != "schema_version"
        }).index_key
        journal_mod._write_index(
            project / INDEX_FILENAME, {old_key: dict(old)})
        # The same identity re-reviewed (oldest incoming ts, so it is
        # shed first) plus enough fat siblings to breach the ceiling.
        rows = [_claim_row(0, ts="2026-01-02T00:00:00.000000Z")] + [
            _claim_row(i, ts=f"2026-01-03T00:00:{i:02d}.000000Z")
            for i in range(1, 12)
        ]
        run = _write_claim_run(project, "run1", rows)
        merged = merge_into_index(project, run)
        (record,) = load_index_aggregates(project).values()
        assert merged + record["identities"] == 12
        doc = json.loads((project / INDEX_FILENAME).read_text())
        restored = doc["entries"][old_key]
        # gfn0's incoming fat row was shed; the pre-run row is back.
        assert restored["ts"] == old["ts"]
        assert restored["body"] == old["body"]

    def test_giant_single_row_run_sheds_everything(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # A run whose ONE row exceeds the ceiling on its own: the
        # merge sheds it (merged == 0), history survives, and the
        # disclosure still reaches the index.
        self._scale(monkeypatch)
        project = tmp_path / "project"
        project.mkdir()
        seed = _write_claim_run(
            project, "seed", [_claim_row(50, body_bytes=10)])
        assert merge_into_index(project, seed) == 1
        run = _write_claim_run(
            project, "run1", [_claim_row(0, body_bytes=6_000)])
        assert merge_into_index(project, run) == 0
        assert (project / INDEX_FILENAME).stat().st_size <= 8 * 1024
        assert "src/g50.c:gfn50" in set(load_index(project))
        (record,) = load_index_aggregates(project).values()
        assert record["identities"] == 1

    def test_preexisting_over_ceiling_index_still_refuses(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # Nothing of THIS run left to shed and the document still
        # over the ceiling (a legacy fat index of unsheddable claim
        # rows): the loud-refusal arm is intact — on-disk bytes
        # untouched, the run journal keeps its rows.
        project = tmp_path / "project"
        project.mkdir()
        legacy = {
            f"src/g{i}.c:gfn{i}::empty:audit@0": _claim_row(i)
            for i in range(6)
        }
        journal_mod._write_index(project / INDEX_FILENAME, legacy)
        before = (project / INDEX_FILENAME).read_bytes()
        self._scale(monkeypatch)  # ceiling now far below the file
        run = _write_claim_run(
            project, "run1", [_claim_row(100, body_bytes=10)])
        assert merge_into_index(project, run) == 0
        assert (project / INDEX_FILENAME).read_bytes() == before

    def test_remerge_at_headroom_drops_the_stale_disclosure(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # Byte eviction is state-dependent (unlike the deterministic
        # count cap): a tight-budget merge sheds identities and
        # records the disclosure; re-merging the SAME run dir at more
        # headroom lands every identity as a full row — the record
        # ("reached the index as aggregates only") is now FALSE and
        # must not survive the write.
        self._scale(monkeypatch, budget=16 * 1024)
        project = tmp_path / "project"
        project.mkdir()
        rows = [_claim_row(i, ts=f"2026-01-01T00:00:{i:02d}.000000Z",
                           body_bytes=1100)
                for i in range(10)]
        run = _write_claim_run(project, "run1", rows)
        merged = merge_into_index(project, run)
        assert 0 < merged < 10
        (record,) = load_index_aggregates(project).values()
        assert merged + record["identities"] == 10
        # Raise headroom, re-merge the same run dir: the previously
        # evicted identities land, the stale record goes with them.
        monkeypatch.setattr(
            journal_mod, "_MAX_JOURNAL_BYTES", 1024 * 1024)
        assert merge_into_index(project, run) == 10 - merged
        assert len(load_index_full(project)) == 10
        assert load_index_aggregates(project) == {}

    def test_remerge_that_still_evicts_refreshes_the_counts(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # The inverse direction: a re-merge whose headroom is larger
        # but still binding refreshes the run's record to the NEW
        # eviction counts — conservation holds against the index as
        # written, never against the first merge's state.
        self._scale(monkeypatch, budget=16 * 1024)
        project = tmp_path / "project"
        project.mkdir()
        rows = [_claim_row(i, ts=f"2026-01-01T00:00:{i:02d}.000000Z",
                           body_bytes=1100)
                for i in range(10)]
        run = _write_claim_run(project, "run1", rows)
        merge_into_index(project, run)
        full_before = len(load_index_full(project))
        (before,) = load_index_aggregates(project).values()
        assert full_before + before["identities"] == 10
        monkeypatch.setattr(
            journal_mod, "_MAX_JOURNAL_BYTES", 24 * 1024)
        assert merge_into_index(project, run) > 0
        full_after = len(load_index_full(project))
        assert full_after > full_before        # non-vacuous: fewer evict
        (after,) = load_index_aggregates(project).values()
        assert after["identities"] < before["identities"]
        assert full_after + after["identities"] == 10

    def test_write_index_budget_param_two_arms(
        self, tmp_path: Path,
    ) -> None:
        # Direct-writer backstop unchanged (default budget = read
        # budget); an explicit lower budget refuses with the sized
        # exception the merge's eviction arm consumes.
        path = tmp_path / INDEX_FILENAME
        entries = {"k": _claim_row(0)}
        journal_mod._write_index(path, entries)  # default arm fits
        assert path.is_file()
        with pytest.raises(IndexWriteOverBudget) as exc:
            journal_mod._write_index(path, entries, budget=64)
        assert exc.value.size > 64
