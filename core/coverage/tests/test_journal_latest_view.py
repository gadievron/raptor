"""Cache-maintained latest-per-key view behind ``latest_entries``.

The audit context builder calls ``latest_entries`` per reviewed
function (twice), and each call used to re-collapse the WHOLE loaded
journal — quadratic once the journal itself scales with the reviewed
set. The view now memoizes on the load-cache record: built once per
cached parse, carried incrementally across active-shard extensions
by folding only the delta rows, and dropped whenever the fold cannot
locally prove equivalence.

The invariant under test (differential equivalence): the maintained
view is always equal — same keys, same chosen rows — to a
from-scratch collapse of the same load, including across appends,
rolls, re-emission pruning, hostile back-dated rows, and shed
records; and every guard fails toward a full recollapse, never
toward a wrong view.
"""

from __future__ import annotations

import json
import os
from collections.abc import Iterable
from pathlib import Path
from typing import Any

import pytest

from core.coverage import journal as journal_mod
from core.coverage.journal import (
    ReviewJournalEntry,
    append_entry,
    invalidate_load_cache,
    journal_shard_paths,
    latest_entries,
    load_entries,
    now_iso,
)


@pytest.fixture(autouse=True)
def _clean_cache():
    """Each test starts and ends with an empty load cache."""
    with journal_mod._load_cache_lock:
        journal_mod._load_cache.clear()
    yield
    with journal_mod._load_cache_lock:
        journal_mod._load_cache.clear()


# ── helpers ──────────────────────────────────────────────────────────

def _ts(i: int) -> str:
    """Strictly monotone microsecond ISO stamp for row *i*."""
    return f"2026-01-01T00:{i // 60:02d}:{i % 60:02d}.{i % 1_000_000:06d}Z"


def _line(i: int, *, key: int | None = None, verdict: str = "clean",
          reused: bool = False, body: str | None = None,
          ts: str | None = None) -> bytes:
    """One raw journal line; ``key`` reuses row *key*'s identity
    fields (file/function/source_hash) so twins and supersedes can be
    built explicitly while ``ts`` stays row-*i*'s."""
    ident = key if key is not None else i
    d: dict[str, Any] = {
        "ts": ts if ts is not None else _ts(i),
        "run_id": "run-x",
        "file": f"src/f{ident}.c",
        "function": f"fn{ident}",
        "verdict": verdict,
        "source_hash": f"hash{ident}",
        "schema_version": 1,
    }
    if reused:
        d["reused"] = True
    if body is not None:
        d["body"] = body
    return json.dumps(d).encode() + b"\n"


def _age_all(out_dir: Path, seconds: int = 60) -> None:
    """Back-date every shard past the racy window so identity-serves
    and sealed pins are eligible."""
    for shard in journal_shard_paths(out_dir):
        if shard.is_file():
            st = os.stat(shard)
            ns = st.st_mtime_ns - seconds * 1_000_000_000
            os.utime(shard, ns=(ns, ns))


def _record(out_dir: Path) -> journal_mod._CachedLoad | None:
    with journal_mod._load_cache_lock:
        return journal_mod._load_cache.get(os.path.realpath(out_dir))


def _scratch_collapse(out_dir: Path) -> dict[str, ReviewJournalEntry]:
    """The from-scratch oracle: a fresh parse collapsed by the shared
    fold — never the memoized view (fresh bypasses it by contract)."""
    return journal_mod._latest_collapse(load_entries(out_dir, fresh=True))


def _assert_equivalent(
    maintained: dict[str, ReviewJournalEntry],
    scratch: dict[str, ReviewJournalEntry],
) -> None:
    """Same keys AND same chosen rows (field-wise entry equality)."""
    assert maintained.keys() == scratch.keys()
    for k, entry in scratch.items():
        assert maintained[k] == entry, f"view chose a different row for {k}"


@pytest.fixture
def collapse_counter(monkeypatch: pytest.MonkeyPatch) -> dict[str, int]:
    """Count full latest-per-key collapses: the incremental carry's
    whole point is that extensions do NOT add to this."""
    counter = {"calls": 0}
    real = journal_mod._latest_collapse

    def counting(
        entries: Iterable[ReviewJournalEntry],
    ) -> dict[str, ReviewJournalEntry]:
        counter["calls"] += 1
        return real(entries)

    monkeypatch.setattr(journal_mod, "_latest_collapse", counting)
    return counter


class TestDifferentialEquivalence:
    def test_multishard_duplicates_and_supersedes(
        self, tmp_path: Path,
    ) -> None:
        # Duplicates (reused re-emission twins, pruned at load),
        # superseded rows (same key, newer ts), spread over 3 shards.
        run = tmp_path / "run"
        run.mkdir()
        shard1 = b"".join([
            _line(0, reused=True), _line(1), _line(2), _line(3),
        ])
        shard2 = b"".join([
            _line(4, key=1, verdict="suspicious"),   # supersedes fn1
            _line(5, key=0, reused=True),            # twin of row 0
            _line(6),
        ])
        shard3 = b"".join([
            _line(7, key=2, verdict="error"),        # supersedes fn2
            _line(8),
        ])
        (run / "review-journal.jsonl").write_bytes(shard1)
        (run / "review-journal.002.jsonl").write_bytes(shard2)
        (run / "review-journal.003.jsonl").write_bytes(shard3)
        _age_all(run)

        maintained = latest_entries(run)          # builds the view
        served = latest_entries(run)              # serves the view
        scratch = _scratch_collapse(run)

        _assert_equivalent(maintained, scratch)
        _assert_equivalent(served, scratch)
        assert maintained["src/f1.c:fn1"].verdict == "suspicious"
        assert maintained["src/f2.c:fn2"].verdict == "error"

    def test_equivalence_survives_extension(
        self, tmp_path: Path,
    ) -> None:
        run = tmp_path / "run"
        run.mkdir()
        (run / "review-journal.jsonl").write_bytes(b"".join([
            _line(0, reused=True), _line(1), _line(2),
        ]))
        (run / "review-journal.002.jsonl").write_bytes(b"".join([
            _line(3),
        ]))
        _age_all(run)
        latest_entries(run)                       # view built

        # Append: a supersede, a new key, and a re-emission twin the
        # final prune folds against the OLD shard's row.
        with open(run / "review-journal.002.jsonl", "ab") as fh:
            fh.write(_line(10, key=1, verdict="finding"))
            fh.write(_line(11))
            fh.write(_line(12, key=0, reused=True))
        _age_all(run)

        maintained = latest_entries(run)
        _assert_equivalent(maintained, _scratch_collapse(run))
        assert maintained["src/f1.c:fn1"].verdict == "finding"
        assert "src/f11.c:fn11" in maintained

    def test_returned_dict_is_the_callers_own(
        self, tmp_path: Path,
    ) -> None:
        run = tmp_path / "run"
        run.mkdir()
        (run / "review-journal.jsonl").write_bytes(_line(0))
        _age_all(run)
        first = latest_entries(run)
        first.clear()                             # caller mutation
        assert latest_entries(run), (
            "a caller's dict mutation leaked into the cached view"
        )


class TestIncrementalMaintenance:
    def test_extension_folds_without_recollapse(
        self, tmp_path: Path, collapse_counter: dict[str, int],
    ) -> None:
        # The load-bearing incrementality proof: after the one build,
        # append → latest_entries cycles never run a full collapse.
        run = tmp_path / "run"
        run.mkdir()
        for i in range(4):
            append_entry(run, _entry(f"fn{i}"))
        _age_all(run)
        latest_entries(run)
        assert collapse_counter["calls"] == 1     # the build

        for i in range(3):
            append_entry(run, _entry(f"fn{i}", verdict="suspicious"))
            append_entry(run, _entry(f"new{i}"))
            _age_all(run)
            view = latest_entries(run)
            assert view[f"src/a.c:fn{i}"].verdict == "suspicious"
            assert f"src/a.c:new{i}" in view
        assert collapse_counter["calls"] == 1, (
            "an extension re-ran the full collapse instead of folding "
            "the delta"
        )
        _assert_equivalent(latest_entries(run), _scratch_collapse(run))

    def test_roll_during_extension_still_folds(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
        collapse_counter: dict[str, int],
    ) -> None:
        monkeypatch.setattr(
            journal_mod, "_JOURNAL_SHARD_ROLL_BYTES", 256)
        run = tmp_path / "run"
        run.mkdir()
        append_entry(run, _entry("fn0"))
        _age_all(run)
        latest_entries(run)
        assert collapse_counter["calls"] == 1
        for i in range(1, 6):                     # forces shard rolls
            append_entry(run, _entry(f"fn{i}"))
        _age_all(run)
        view = latest_entries(run)
        assert len(journal_shard_paths(run)) > 1, "no roll happened"
        assert collapse_counter["calls"] == 1, (
            "a shard roll broke the incremental fold"
        )
        _assert_equivalent(view, _scratch_collapse(run))

    def test_identity_serve_reuses_the_view(
        self, tmp_path: Path, collapse_counter: dict[str, int],
    ) -> None:
        run = tmp_path / "run"
        run.mkdir()
        append_entry(run, _entry("fn0"))
        _age_all(run)
        for _ in range(5):
            latest_entries(run)
        assert collapse_counter["calls"] == 1


class TestGuardsFailToRecollapse:
    def test_backdated_delta_row_rebuilds_from_scratch(
        self, tmp_path: Path, collapse_counter: dict[str, int],
    ) -> None:
        # A hostile back-dated row can flip which twin the positional
        # prune keeps vs which row the ts-collapse picks — the fold
        # must refuse and rebuild, and the rebuilt view must equal
        # the from-scratch collapse.
        run = tmp_path / "run"
        run.mkdir()
        (run / "review-journal.jsonl").write_bytes(b"".join([
            _line(0), _line(1),
        ]))
        _age_all(run)
        latest_entries(run)
        assert collapse_counter["calls"] == 1
        with open(run / "review-journal.jsonl", "ab") as fh:
            fh.write(_line(2, key=0, verdict="suspicious",
                           ts="2020-01-01T00:00:00.000000Z"))
        _age_all(run)
        view = latest_entries(run)
        assert collapse_counter["calls"] == 2, (
            "the fold accepted a non-monotone delta row"
        )
        _assert_equivalent(view, _scratch_collapse(run))
        # Strict > : the back-dated supersede attempt loses.
        assert view["src/f0.c:fn0"].verdict == "clean"

    def test_tied_ts_first_in_file_wins_both_paths(
        self, tmp_path: Path,
    ) -> None:
        # The consumer tie-break convention (matching merge_into_index):
        # strict > on ts, first-in-file wins the tie.
        run = tmp_path / "run"
        run.mkdir()
        tie = "2026-01-01T00:00:01.000001Z"
        (run / "review-journal.jsonl").write_bytes(b"".join([
            _line(0, body="first", ts=tie),
            _line(1, key=0, body="second", ts=tie),
        ]))
        _age_all(run)
        maintained = latest_entries(run)
        scratch = _scratch_collapse(run)
        assert maintained["src/f0.c:fn0"].body == "first"
        _assert_equivalent(maintained, scratch)

    def test_instream_prune_during_delta_rebuilds(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
        collapse_counter: dict[str, int],
    ) -> None:
        # The retained-entry budget prune rewrites the active list in
        # place mid-extension: the positional delta slice is then
        # unusable and the fold must rebuild instead of guessing.
        monkeypatch.setattr(journal_mod, "_MAX_RETAINED_ENTRIES", 4)
        run = tmp_path / "run"
        run.mkdir()
        (run / "review-journal.jsonl").write_bytes(b"".join([
            _line(0, reused=True), _line(1, reused=True),
            _line(2, reused=True),
        ]))
        _age_all(run)
        latest_entries(run)
        assert collapse_counter["calls"] == 1
        with open(run / "review-journal.jsonl", "ab") as fh:
            fh.write(_line(3, key=0, reused=True))
            fh.write(_line(4, key=1, reused=True))
            fh.write(_line(5, key=2, reused=True))
        _age_all(run)
        view = latest_entries(run)
        record = _record(run)
        assert record is not None
        assert record.shard_states[-1].pruned > 0, (
            "test setup: the in-stream prune never fired"
        )
        assert collapse_counter["calls"] == 2, (
            "the fold used a positional delta the in-stream prune "
            "invalidated"
        )
        _assert_equivalent(view, _scratch_collapse(run))


class TestFreshAndInvalidation:
    def test_fresh_never_serves_the_memoized_view(
        self, tmp_path: Path,
    ) -> None:
        run = tmp_path / "run"
        run.mkdir()
        append_entry(run, _entry("fn0"))
        _age_all(run)
        latest_entries(run)
        record = _record(run)
        assert record is not None and record.latest_view is not None
        # Poison the memoized view: a spend-side fresh read must
        # reflect disk truth, never this.
        poison = _entry("fn0", verdict="dormant")
        with journal_mod._load_cache_lock:
            record.latest_view["src/a.c:fn0"] = poison
        fresh = latest_entries(run, fresh=True)
        assert fresh["src/a.c:fn0"].verdict == "clean"
        # fresh repopulated the record; the next cached call rebuilds
        # an honest view rather than resurrecting the poisoned one.
        assert latest_entries(run)["src/a.c:fn0"].verdict == "clean"

    def test_invalidate_drops_the_view_with_the_record(
        self, tmp_path: Path,
    ) -> None:
        # The compaction seam: shard swaps call invalidate_load_cache
        # explicitly; the maintained view rides the same record drop.
        run = tmp_path / "run"
        run.mkdir()
        (run / "review-journal.jsonl").write_bytes(_line(0))
        _age_all(run)
        assert latest_entries(run)["src/f0.c:fn0"].verdict == "clean"
        (run / "review-journal.jsonl").write_bytes(
            _line(1, key=0, verdict="finding"))
        _age_all(run)
        invalidate_load_cache(run)
        view = latest_entries(run)
        assert view["src/f0.c:fn0"].verdict == "finding"
        _assert_equivalent(view, _scratch_collapse(run))


class TestShedInteraction:
    def _sharded(self, tmp_path: Path) -> Path:
        run = tmp_path / "run"
        run.mkdir()
        (run / "review-journal.jsonl").write_bytes(
            b"".join(_line(i, body="x" * 64) for i in range(4)))
        (run / "review-journal.002.jsonl").write_bytes(
            b"".join(_line(i, body="x" * 64) for i in range(4, 8)))
        (run / "review-journal.003.jsonl").write_bytes(
            b"".join(_line(i, body="x" * 64) for i in range(8, 10)))
        _age_all(run)
        return run

    def test_shed_record_pins_no_view_and_stays_correct(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        run = self._sharded(tmp_path)
        sizes = [
            (run / n).stat().st_size
            for n in ("review-journal.jsonl", "review-journal.002.jsonl",
                      "review-journal.003.jsonl")
        ]
        # Cap forces the first sealed shard's rows to shed.
        monkeypatch.setattr(
            journal_mod, "_LOAD_CACHE_MAX_BYTES",
            sizes[1] + sizes[2] + 5)
        view = latest_entries(run)
        record = _record(run)
        assert record is not None
        assert record.shard_states[0].rows_evicted
        assert record.latest_view is None, (
            "a shed record kept a view that pins the freed rows"
        )
        _assert_equivalent(view, _scratch_collapse(run))
        # Steady state: repeated calls stay correct, still no pin.
        again = latest_entries(run)
        record = _record(run)
        assert record is not None and record.latest_view is None
        _assert_equivalent(again, _scratch_collapse(run))

    def test_shedding_an_existing_record_drops_its_view(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        run = self._sharded(tmp_path)
        latest_entries(run)
        record = _record(run)
        assert record is not None and record.latest_view is not None
        with journal_mod._load_cache_lock:
            monkeypatch.setattr(
                journal_mod, "_LOAD_CACHE_MAX_BYTES", 1)
            journal_mod._shed_sealed_rows(record)
        assert record.latest_view is None
        assert record.latest_view_ts_max == ""


def _entry(function: str, *, verdict: str = "clean") -> ReviewJournalEntry:
    return ReviewJournalEntry(
        ts=now_iso(),
        run_id="run-x",
        file="src/a.c",
        function=function,
        verdict=verdict,
        source_hash="h",
    )
