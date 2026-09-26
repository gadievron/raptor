"""Journal shard-set tests: roll-over, discovery, load aggregation,
spend reconciliation, and shard-aware compaction."""

from __future__ import annotations

import pytest

import core.coverage.journal as journal_mod
from core.coverage.journal import (
    JOURNAL_FILENAME,
    ReviewJournalEntry,
    append_entry,
    journal_shard_paths,
    load_entries,
    load_entries_checked,
    now_iso,
    require_complete_entries,
)


def _entry(i: int, *, cost: float | None = None,
           reused: bool | None = None,
           pad: int = 0) -> ReviewJournalEntry:
    return ReviewJournalEntry(
        ts=now_iso(),
        run_id="run-1",
        file=f"src/f{i}.c",
        function=f"fn{i}",
        verdict="clean",
        source_hash="ab" * 8,
        line_start=1,
        line_end=5,
        cost_usd=cost,
        reused=reused,
        body="x" * pad,
    )


@pytest.fixture
def tiny_roll(monkeypatch):
    monkeypatch.setattr(journal_mod, "_JOURNAL_SHARD_ROLL_BYTES", 600)


def test_single_file_below_threshold_never_rolls(tmp_path):
    for i in range(5):
        append_entry(tmp_path, _entry(i))
    assert (tmp_path / JOURNAL_FILENAME).is_file()
    assert not (tmp_path / "review-journal.002.jsonl").exists()
    assert journal_shard_paths(tmp_path) == [tmp_path / JOURNAL_FILENAME]


def test_roll_creates_numbered_shards(tmp_path, tiny_roll):
    for i in range(12):
        append_entry(tmp_path, _entry(i, cost=0.25, pad=64))
    shards = journal_shard_paths(tmp_path)
    assert len(shards) > 1
    assert shards[0].name == JOURNAL_FILENAME
    assert shards[1].name == "review-journal.002.jsonl"
    # Every sealed shard stays near the roll threshold, far below
    # the reader budget.
    for shard in shards[:-1]:
        assert shard.stat().st_size < 600 + 2048


def test_load_reads_all_shards_in_order(tmp_path, tiny_roll):
    for i in range(12):
        append_entry(tmp_path, _entry(i, cost=0.25, pad=64))
    loaded = load_entries_checked(tmp_path)
    assert loaded.complete
    assert [e.function for e in loaded.entries] == [
        f"fn{i}" for i in range(12)]


def test_journal_spend_usd_exact_across_shards(tmp_path, tiny_roll):
    from core.audit.resume import journal_spend_usd
    for i in range(12):
        append_entry(tmp_path, _entry(i, cost=0.5, pad=64))
    assert journal_spend_usd(tmp_path) == pytest.approx(6.0)


def test_reviewed_set_and_latest_across_shards(tmp_path, tiny_roll):
    from core.coverage.journal import latest_entries, reviewed_set
    for i in range(12):
        append_entry(tmp_path, _entry(i, pad=64))
    # A newer verdict for fn0 lands in a LATER shard.
    correction = _entry(0)
    correction.verdict = "suspicious"
    append_entry(tmp_path, correction)
    keys = reviewed_set(tmp_path)
    assert "src/f0.c:fn0" in keys and len(keys) == 12
    assert latest_entries(tmp_path)["src/f0.c:fn0"].verdict == "suspicious"


def test_require_complete_refuses_missing_interior_shard(
        tmp_path, tiny_roll):
    from core.coverage.journal import JournalIncomplete
    for i in range(12):
        append_entry(tmp_path, _entry(i, pad=64))
    shards = journal_shard_paths(tmp_path)
    assert len(shards) >= 3
    shards[1].unlink()   # delete an interior shard
    with pytest.raises(JournalIncomplete):
        require_complete_entries(tmp_path)


def test_orphan_shard_flags_incomplete(tmp_path):
    append_entry(tmp_path, _entry(0))
    # Planted non-contiguous shard: evidence of deletion, or a plant —
    # either way the survivors are not provably the whole journal.
    (tmp_path / "review-journal.005.jsonl").write_text("")
    loaded = load_entries_checked(tmp_path)
    assert not loaded.complete
    assert "non-contiguous" in (loaded.reason or "")


def test_missing_base_with_numbered_shard_incomplete(tmp_path):
    (tmp_path / "review-journal.002.jsonl").write_text(
        "")
    loaded = load_entries_checked(tmp_path)
    assert not loaded.complete


def test_cross_shard_reemission_prune_is_lossless(tmp_path, tiny_roll):
    # The same reused zero-cost verdict re-emitted across shard
    # boundaries collapses to one row; $-bearing rows all survive.
    from core.audit.resume import journal_spend_usd
    live = _entry(0, cost=1.25)
    append_entry(tmp_path, live)
    for _ in range(10):
        append_entry(tmp_path, _entry(0, reused=True, pad=64))
    assert len(journal_shard_paths(tmp_path)) > 1
    loaded = load_entries_checked(tmp_path)
    assert loaded.complete
    reused_rows = [e for e in loaded.entries if e.reused]
    assert len(reused_rows) == 1
    assert journal_spend_usd(tmp_path) == pytest.approx(1.25)


def test_flush_journal_syncs_all_shards(tmp_path, tiny_roll):
    from core.coverage.journal import flush_journal
    for i in range(8):
        append_entry(tmp_path, _entry(i, pad=64))
    flush_journal(tmp_path)   # must not raise across the shard set


def test_compact_journal_shard_aware(tmp_path, tiny_roll, monkeypatch):
    from core.coverage.journal_compact import compact_journal
    append_entry(tmp_path, _entry(0, cost=2.0))
    for _ in range(10):
        append_entry(tmp_path, _entry(0, reused=True, pad=64))
    shards_before = journal_shard_paths(tmp_path)
    assert len(shards_before) > 1
    stats = compact_journal(tmp_path)
    assert stats.dropped_reemissions > 0
    assert stats.spend_usd_after == pytest.approx(stats.spend_usd_before)
    # Every shard file survives (possibly smaller), backups exist.
    for shard in shards_before:
        assert shard.exists()
    assert stats.backup_path
    loaded = load_entries_checked(tmp_path)
    assert loaded.complete
    assert [e.cost_usd for e in loaded.entries if e.cost_usd] == [2.0]


def test_compact_refused_when_no_journal(tmp_path):
    from core.coverage.journal_compact import CompactRefused, compact_journal
    with pytest.raises(CompactRefused):
        compact_journal(tmp_path)


def test_shard_discovery_ignores_gap_files(tmp_path):
    append_entry(tmp_path, _entry(0))
    (tmp_path / "review-journal.004.jsonl").write_text("")
    # Contiguity by construction: 002/003 absent, so 004 is not part
    # of the append set (and the loader flags it separately).
    assert journal_shard_paths(tmp_path) == [tmp_path / JOURNAL_FILENAME]


def test_shard_bound_appends_to_final_shard(tmp_path, tiny_roll,
                                            monkeypatch):
    monkeypatch.setattr(journal_mod, "_MAX_JOURNAL_SHARDS", 2)
    for i in range(12):
        append_entry(tmp_path, _entry(i, pad=64))
    shards = journal_shard_paths(tmp_path)
    assert len(shards) == 2
    # Nothing lost: all rows load.
    assert len(load_entries(tmp_path)) == 12


def test_compact_supersede_multi_shard_spend_carriers(tmp_path, tiny_roll):
    """Supersede across a shard set: the aggregated stats must stay
    internally consistent (one spend carrier per dropped cost-bearing
    row, summed over EVERY shard — not just the first), backups use
    the .pre-supersede family per shard, and spend is bit-exact."""
    from core.coverage.journal_compact import compact_journal
    # Three cost-bearing versions per function, appended consecutively
    # so each function's versions co-locate in one shard (pad sizes
    # the rows so a shard holds roughly one function's group).
    for i in range(8):
        for _ in range(3):
            append_entry(tmp_path, _entry(i, cost=0.25, pad=96))
    shards_before = journal_shard_paths(tmp_path)
    assert len(shards_before) > 2
    stats = compact_journal(tmp_path, supersede=True)
    assert stats.dropped_superseded >= 4  # multiple shards dropped
    # The finding this pins: carriers aggregate across ALL shards.
    assert stats.spend_carriers == stats.dropped_superseded
    assert stats.spend_usd_after == pytest.approx(stats.spend_usd_before)
    assert stats.spend_usd_before == pytest.approx(8 * 3 * 0.25)
    backups = list(tmp_path.glob("*.pre-supersede*"))
    assert backups and not list(tmp_path.glob("*.pre-compact*"))
    loaded = load_entries_checked(tmp_path)
    assert loaded.complete
    from core.audit.resume import journal_spend_usd
    assert journal_spend_usd(tmp_path) == pytest.approx(8 * 3 * 0.25)


class TestSnapshotConsistentShardView:
    """The orphan race fix: one directory snapshot feeds BOTH the
    contiguity walk and the orphan classification, so a concurrent
    appender roll is wholly in or wholly after the view — never
    split across the pair (previously: fresh shard visible to the
    orphan listing but not the contiguity probes → transient
    one-load incomplete flag)."""

    def test_roll_after_snapshot_is_invisible_to_both(self, tmp_path):
        from core.coverage.journal import (
            _journal_dir_snapshot,
            _orphan_shard_names,
            journal_shard_paths,
        )
        append_entry(tmp_path, _entry(0))
        snap = _journal_dir_snapshot(tmp_path)
        # A roll lands AFTER the snapshot (the race window).
        (tmp_path / "review-journal.002.jsonl").write_text("")
        paths = journal_shard_paths(tmp_path, snapshot=snap)
        assert len(paths) == 1  # pre-roll view
        # Same snapshot → the fresh shard is NOT an orphan.
        assert _orphan_shard_names(
            tmp_path, len(paths), snapshot=snap) == []
        # The OLD two-read behavior (self-listing) misreads it —
        # pinned so the fix is revert-detectable.
        assert _orphan_shard_names(tmp_path, len(paths)) == [
            "review-journal.002.jsonl"]

    def test_roll_before_snapshot_is_in_the_set_not_orphan(
            self, tmp_path):
        from core.coverage.journal import (
            _journal_dir_snapshot,
            _orphan_shard_names,
            journal_shard_paths,
        )
        append_entry(tmp_path, _entry(0))
        (tmp_path / "review-journal.002.jsonl").write_text("")
        snap = _journal_dir_snapshot(tmp_path)
        paths = journal_shard_paths(tmp_path, snapshot=snap)
        assert len(paths) == 2  # roll included in the view
        assert _orphan_shard_names(
            tmp_path, len(paths), snapshot=snap) == []

    def test_true_orphan_still_flagged_under_snapshot(self, tmp_path):
        # A genuine gap (interior shard deleted) must still flag —
        # the snapshot changes VIEW consistency, never the
        # deletion-evidence semantics.
        from core.coverage.journal import (
            _journal_dir_snapshot,
            _orphan_shard_names,
            journal_shard_paths,
        )
        append_entry(tmp_path, _entry(0))
        (tmp_path / "review-journal.004.jsonl").write_text("")
        snap = _journal_dir_snapshot(tmp_path)
        paths = journal_shard_paths(tmp_path, snapshot=snap)
        assert len(paths) == 1  # 002/003 absent: 004 not contiguous
        assert _orphan_shard_names(
            tmp_path, len(paths), snapshot=snap) == [
            "review-journal.004.jsonl"]

    def test_warm_serve_with_race_roll_stays_cached(self, tmp_path,
                                                    monkeypatch):
        # Serve path: a roll landing between the warm-serve's snapshot
        # and its orphan re-check must not read as an anomaly (which
        # would refuse the serve and force a full cold reparse of an
        # otherwise-unchanged journal — the reload-storm cost this
        # snapshot threading exists to prevent).
        import os as _os

        import core.coverage.journal as jm
        append_entry(tmp_path, _entry(0, cost=1.0))
        shard = tmp_path / JOURNAL_FILENAME
        st = _os.stat(shard)
        aged = st.st_mtime_ns - 60 * 1_000_000_000
        _os.utime(shard, ns=(aged, aged))   # past the racy window
        warm = load_entries_checked(tmp_path)
        assert warm.complete
        cold_parses: list[str] = []
        real_cold = jm._load_shard_cold

        def counting_cold(path):
            cold_parses.append(path.name)
            return real_cold(path)

        real_snapshot = jm._journal_dir_snapshot

        def snap_then_roll(out_dir):
            snap = real_snapshot(out_dir)
            (tmp_path / "review-journal.002.jsonl").write_text("")
            return snap

        monkeypatch.setattr(jm, "_load_shard_cold", counting_cold)
        monkeypatch.setattr(jm, "_journal_dir_snapshot", snap_then_roll)
        got = load_entries_checked(tmp_path)
        assert got.complete, got.reason
        assert [e.function for e in got.entries] == ["fn0"]
        # Identity-served from the cache: the race roll must not have
        # been classified an orphan (which returns None from the serve
        # and cold-reparses every shard).
        assert cold_parses == []

    def test_warm_extend_with_race_roll_reads_complete(self, tmp_path,
                                                       monkeypatch):
        # Extend path: the delta parse's finalize must consume the
        # SAME snapshot as the serve walk — a roll landing after the
        # snapshot previously re-flagged the load incomplete
        # ("non-contiguous"), the original bug one layer up.
        import os as _os

        import core.coverage.journal as jm
        append_entry(tmp_path, _entry(0, cost=1.0))
        shard = tmp_path / JOURNAL_FILENAME
        st = _os.stat(shard)
        aged = st.st_mtime_ns - 60 * 1_000_000_000
        _os.utime(shard, ns=(aged, aged))   # past the racy window
        warm = load_entries_checked(tmp_path)
        assert warm.complete
        append_entry(tmp_path, _entry(1, cost=1.0))   # grow the shard
        real_snapshot = jm._journal_dir_snapshot

        def snap_then_roll(out_dir):
            snap = real_snapshot(out_dir)
            (tmp_path / "review-journal.002.jsonl").write_text("")
            return snap

        monkeypatch.setattr(jm, "_journal_dir_snapshot", snap_then_roll)
        got = load_entries_checked(tmp_path)
        assert got.complete, got.reason
        assert [e.function for e in got.entries] == ["fn0", "fn1"]

    def test_cold_load_with_race_roll_reads_complete(self, tmp_path,
                                                     monkeypatch):
        # End-to-end: a roll injected DURING the cold load (planted
        # right after the snapshot is taken) must not flag the load
        # incomplete.
        import core.coverage.journal as jm
        append_entry(tmp_path, _entry(0, cost=1.0))
        real_snapshot = jm._journal_dir_snapshot

        def snap_then_roll(out_dir):
            snap = real_snapshot(out_dir)
            (tmp_path / "review-journal.002.jsonl").write_text("")
            return snap

        monkeypatch.setattr(jm, "_journal_dir_snapshot", snap_then_roll)
        got = load_entries_checked(tmp_path)
        assert got.complete, got.reason
