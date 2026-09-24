"""``journal compact`` — on-disk twin of the loader's re-emission
prune.

The loss contract under test: compaction may drop ONLY duplicate
zero-cost reused re-emission rows whose newest identity sibling
survives. The final verdict per function, the reviewed-key set, the
journal spend floor, every claim (finding/suspicious) row, every
correction, and every unparseable line survive byte-for-byte (kept
rows are copied verbatim, so row MACs stay valid).
"""

from __future__ import annotations

import json
import os
import random
from pathlib import Path

import pytest

from core.coverage.journal import (
    JOURNAL_FILENAME,
    ReviewJournalEntry,
    append_entry,
    latest_entries,
    load_entries,
    now_iso,
    reviewed_set,
)
from core.coverage.journal_compact import (
    CompactRefused,
    compact_journal,
)


def _entry(i: int, **over) -> ReviewJournalEntry:
    fields = dict(
        ts=now_iso(),
        run_id="audit-run",
        file=f"src/f{i % 7}.c",
        function=f"fn{i}",
        verdict="clean",
        source_hash=f"{i:08x}",
        line_start=1 + i,
        line_end=5 + i,
        strategies=["bounds"],
        model="model-a",
        body="review body " * 20,
    )
    fields.update(over)
    return ReviewJournalEntry(**fields)


def _reemission_run(out: Path, n_functions: int = 12,
                    n_segments: int = 5) -> float:
    """Segment 1 reviews live ($-bearing); each later segment
    re-emits every verdict as a reused $0 row. Returns live spend."""
    spend = 0.0
    for i in range(n_functions):
        cost = 0.25 + i / 100
        spend += cost
        append_entry(out, _entry(i, cost_usd=cost))
    for _seg in range(2, n_segments + 1):
        for i in range(n_functions):
            append_entry(out, _entry(
                i, reused=True, reused_from_run="audit-run",
                cost_usd=0.0,
                body="[reused: verdict imported]",
            ))
    return spend


def _spend(out: Path) -> float:
    return sum(e.cost_usd or 0.0 for e in load_entries(out))


class TestCompaction:
    def test_reemission_fixture_compacts_3x_floors_preserved(
        self, tmp_path: Path,
    ) -> None:
        # 7 segments — the shape of the motivating incident (a long
        # resume chain re-emitting every verdict per segment).
        live_spend = _reemission_run(tmp_path, n_segments=7)
        before_bytes = (tmp_path / JOURNAL_FILENAME).stat().st_size
        before_latest = {
            k: (e.verdict, e.ts) for k, e in latest_entries(tmp_path).items()
        }
        before_reviewed = reviewed_set(tmp_path)

        stats = compact_journal(tmp_path)

        assert stats.bytes_before == before_bytes
        assert stats.ratio >= 3.0, (
            f"only {stats.ratio:.2f}x on a 7-segment re-emission run"
        )
        # 12 live + 12 newest reused survive.
        assert stats.rows_after == 24
        assert stats.dropped_reemissions == 12 * 5
        # Spend floor bit-identical.
        assert _spend(tmp_path) == pytest.approx(live_spend)
        assert stats.spend_usd_after == pytest.approx(live_spend)
        # Verdict semantics identical.
        assert {
            k: (e.verdict, e.ts) for k, e in latest_entries(tmp_path).items()
        } == before_latest
        assert reviewed_set(tmp_path) == before_reviewed
        # Backup is the untouched original.
        backup = Path(stats.backup_path)
        assert backup.name == "review-journal.jsonl.pre-compact"
        assert backup.stat().st_size == before_bytes

    def test_kept_rows_are_verbatim_original_lines(
        self, tmp_path: Path,
    ) -> None:
        """Every surviving line is byte-identical to an original line
        (MAC-preserving; no re-serialization)."""
        _reemission_run(tmp_path, n_functions=4, n_segments=3)
        original = set(
            (tmp_path / JOURNAL_FILENAME).read_bytes().splitlines())
        compact_journal(tmp_path)
        for line in (tmp_path / JOURNAL_FILENAME).read_bytes().splitlines():
            assert line in original

    def test_claim_corrections_errors_unparseable_survive(
        self, tmp_path: Path,
    ) -> None:
        journal = tmp_path / JOURNAL_FILENAME
        append_entry(tmp_path, _entry(1, verdict="finding", cwe="CWE-787",
                                      cost_usd=0.5))
        # Duplicate reused FINDING re-emissions: claim rows keep
        # every emission.
        for _ in range(3):
            append_entry(tmp_path, _entry(
                1, verdict="finding", cwe="CWE-787", reused=True,
                cost_usd=0.0))
        # Correction-bearing reused row: survives (validate_verdict).
        for _ in range(2):
            append_entry(tmp_path, _entry(
                2, reused=True, cost_usd=0.0,
                validate_verdict="disproven", prior_review="finding"))
        append_entry(tmp_path, _entry(3, verdict="error", cost_usd=0.0))
        with journal.open("ab") as fh:
            fh.write(b"{corrupt json\n")
            fh.write(b'"not a dict"\n')

        rows_before = len(journal.read_bytes().splitlines())
        stats = compact_journal(tmp_path)
        rows_after = len(journal.read_bytes().splitlines())
        assert stats.dropped_reemissions == 0
        assert rows_after == rows_before
        assert b"{corrupt json" in journal.read_bytes()

    def test_idempotent_second_pass_drops_nothing(
        self, tmp_path: Path,
    ) -> None:
        _reemission_run(tmp_path, n_functions=3, n_segments=4)
        compact_journal(tmp_path)
        first = (tmp_path / JOURNAL_FILENAME).read_bytes()
        stats = compact_journal(tmp_path)
        assert stats.dropped_reemissions == 0
        assert (tmp_path / JOURNAL_FILENAME).read_bytes() == first
        # Second backup name never clobbers the first.
        assert Path(stats.backup_path).name.endswith(".pre-compact.2")

    def test_live_run_refused(self, tmp_path: Path) -> None:
        from core.run.metadata import RUN_METADATA_FILE
        append_entry(tmp_path, _entry(1))
        (tmp_path / RUN_METADATA_FILE).write_text(json.dumps({
            "command": "audit",
            "status": "running",
            "tool_pid": os.getpid(),
            "timestamp": "2026-09-20T00:00:00+00:00",
        }))
        before = (tmp_path / JOURNAL_FILENAME).read_bytes()
        with pytest.raises(CompactRefused, match="in flight"):
            compact_journal(tmp_path)
        assert (tmp_path / JOURNAL_FILENAME).read_bytes() == before

    def test_dead_worker_running_status_compacts(
        self, tmp_path: Path,
    ) -> None:
        """A stale 'running' stamp with a dead pid (SIGKILLed segment
        — the state an aborted resume leaves behind) must not wedge
        the remedy."""
        from core.run.metadata import RUN_METADATA_FILE
        _reemission_run(tmp_path, n_functions=2, n_segments=3)
        (tmp_path / RUN_METADATA_FILE).write_text(json.dumps({
            "command": "audit",
            "status": "running",
            "tool_pid": 2 ** 22 + 12345,   # beyond default pid_max
            "timestamp": "2026-09-20T00:00:00+00:00",
        }))
        stats = compact_journal(tmp_path)
        assert stats.dropped_reemissions > 0

    def test_missing_journal_refused(self, tmp_path: Path) -> None:
        with pytest.raises(CompactRefused, match="nothing to compact"):
            compact_journal(tmp_path)


class TestCompactionLosslessProperty:
    """Property test for the loss contract: over randomized journals
    (live rows, reused duplicates at random multiplicities,
    corrections, claims, errors, corrupt lines), verdict semantics
    and the spend floor are IDENTICAL before and after compaction."""

    @pytest.mark.parametrize("seed", [7, 23, 1291])
    def test_semantics_identical(self, tmp_path: Path, seed: int) -> None:
        rng = random.Random(seed)
        out = tmp_path / f"run{seed}"
        out.mkdir()
        verdicts = ["clean", "clean", "clean", "suspicious",
                    "finding", "dormant", "error", "dark"]
        for i in range(rng.randint(20, 60)):
            verdict = rng.choice(verdicts)
            cost = round(rng.random() / 2, 4)
            append_entry(out, _entry(i, verdict=verdict, cost_usd=cost))
            for _ in range(rng.randint(0, 5)):
                dup = _entry(
                    i, verdict=verdict, reused=True,
                    cost_usd=0.0 if rng.random() < 0.9
                    else round(rng.random() / 10, 4),
                )
                if rng.random() < 0.15:
                    dup.validate_verdict = "survived"
                    dup.prior_review = verdict
                if rng.random() < 0.1:
                    dup.lesson = "keep"
                append_entry(out, dup)
        journal = out / JOURNAL_FILENAME
        with journal.open("ab") as fh:
            fh.write(b"{torn\n")

        before_entries = load_entries(out)
        before_latest = {
            k: (e.verdict, e.ts) for k, e in latest_entries(out).items()
        }
        before_reviewed = reviewed_set(out)
        before_spend = _spend(out)
        before_claims = sorted(
            e.ts for e in before_entries
            if e.verdict in ("finding", "suspicious")
        )
        before_corrections = sorted(
            e.ts for e in before_entries if e.validate_verdict or e.lesson
        )

        compact_journal(out)

        after_entries = load_entries(out)
        assert {
            k: (e.verdict, e.ts) for k, e in latest_entries(out).items()
        } == before_latest
        assert reviewed_set(out) == before_reviewed
        assert _spend(out) == pytest.approx(before_spend)
        assert sorted(
            e.ts for e in after_entries
            if e.verdict in ("finding", "suspicious")
        ) == before_claims
        assert sorted(
            e.ts for e in after_entries if e.validate_verdict or e.lesson
        ) == before_corrections
        assert b"{torn" in journal.read_bytes()
