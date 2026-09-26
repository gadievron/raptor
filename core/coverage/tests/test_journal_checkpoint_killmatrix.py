"""Checkpoint crash atomicity — the kill matrix.

A child process (``killmatrix_child.py``) runs one journal checkpoint
with a hook planted at a named seam; the hook signals readiness and
hangs, and this parent SIGKILLs it there. Four legs, one per seam of
the compactor's swap protocol:

* ``tmp-write``   — mid pass-2 rewrite (tmp partially written);
* ``pre-rename``  — at the backup hardlink (tmp complete, no backup);
* ``mid-archive`` — between backup hardlink and swap rename;
* ``post-rename`` — after the swap, before cache invalidation and the
  directory fsync.

Every leg asserts the same recovery contract: the live journal is
either the OLD bytes or the NEW bytes, never a mixture; the resume
gate's loader (``require_complete_entries``) accepts it; the journal
spend floor is bit-preserved; any archive that exists holds the full
original bytes; no hysteresis state was written (a killed attempt
must re-fire); and a follow-up compaction succeeds and sweeps any
leaked ``.~compact-*`` tmp file.
"""

from __future__ import annotations

import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

from core.coverage.journal import (
    JOURNAL_FILENAME,
    ReviewJournalEntry,
    append_entry,
    now_iso,
    require_complete_entries,
)
from core.coverage.journal_checkpoint import CHECKPOINT_STATE_FILENAME
from core.coverage.journal_compact import _file_spend, compact_journal

_CHILD = Path(__file__).resolve().parent / "killmatrix_child.py"
_REPO_ROOT = Path(__file__).resolve().parents[3]
_READY_TIMEOUT_S = 30.0


def _entry(i: int, **over) -> ReviewJournalEntry:
    fields = dict(
        ts=now_iso(),
        run_id="audit-run",
        file=f"src/f{i % 5}.c",
        function=f"fn{i}",
        verdict="clean",
        source_hash=f"{i:08x}",
        strategies=["bounds"],
        body="review body " * 20,
    )
    fields.update(over)
    return ReviewJournalEntry(**fields)


def _seed_run(out: Path) -> None:
    """Live $-rows plus reused re-emissions: both automatic tiers
    have work, and superseding must mint spend carriers (the
    tmp-write leg's hook sits in the carrier build)."""
    for i in range(8):
        append_entry(out, _entry(i, cost_usd=0.25 + i / 100))
    for _seg in range(3):
        for i in range(8):
            append_entry(out, _entry(
                i, reused=True, reused_from_run="audit-run",
                cost_usd=0.0, body="[reused: verdict imported]",
            ))


def _kill_at(phase: str, out: Path, tmp_path: Path) -> None:
    """Run the child checkpoint to the named seam, then SIGKILL it."""
    ready = tmp_path / f"ready-{phase}"
    proc = subprocess.Popen(
        [sys.executable, str(_CHILD), str(_REPO_ROOT), str(out),
         phase, str(ready)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    deadline = time.monotonic() + _READY_TIMEOUT_S
    try:
        while not ready.exists():
            if proc.poll() is not None:
                _out, err = proc.communicate()
                pytest.fail(
                    f"child exited (rc={proc.returncode}) before the "
                    f"{phase} seam: {err.decode(errors='replace')}",
                )
            if time.monotonic() > deadline:
                pytest.fail(f"child never reached the {phase} seam")
            time.sleep(0.02)
    finally:
        if proc.poll() is None:
            proc.send_signal(signal.SIGKILL)
        proc.wait(timeout=30)
    assert proc.returncode == -signal.SIGKILL


def _leaked_tmp(out: Path) -> list[Path]:
    return sorted(out.glob(".~compact-*.jsonl"))


def _reviewed_functions(out: Path) -> set[str]:
    """Function names the resume gate's loader sees for real review
    rows (spend carriers ride ``error`` verdicts and are excluded)."""
    return {
        e.function
        for e in require_complete_entries(out)
        if e.verdict != "error"
    }


def _assert_recovered(out: Path, spend_before: float) -> None:
    """The recovery contract shared by every leg: resume-gate load
    succeeds with every reviewed identity present, spend floor holds,
    no hysteresis state, and a follow-up compaction runs clean and
    sweeps leaked tmp files."""
    journal = out / JOURNAL_FILENAME
    expected = {f"fn{i}" for i in range(8)}
    # Old journal or new, every reviewed identity is loadable — a
    # resumed segment re-imports every prior verdict.
    assert _reviewed_functions(out) == expected
    assert _file_spend(journal) == pytest.approx(spend_before)
    # A killed attempt never arms hysteresis — the next boundary
    # re-evaluates from scratch.
    assert not (out / CHECKPOINT_STATE_FILENAME).exists()
    # Recovery: the next compaction (what a resumed run's checkpoint
    # performs) succeeds and sweeps any leaked tmp under its flock.
    compact_journal(out, supersede=True)
    assert _leaked_tmp(out) == []
    assert _file_spend(journal) == pytest.approx(spend_before)
    assert _reviewed_functions(out) == expected


class TestKillMatrix:
    def _setup(self, tmp_path: Path) -> tuple[Path, bytes, float]:
        out = tmp_path / "run"
        out.mkdir()
        _seed_run(out)
        journal = out / JOURNAL_FILENAME
        return out, journal.read_bytes(), _file_spend(journal)

    def test_sigkill_mid_tmp_write(self, tmp_path: Path) -> None:
        out, before, spend = self._setup(tmp_path)
        _kill_at("tmp-write", out, tmp_path)
        journal = out / JOURNAL_FILENAME
        # Journal untouched: the kill landed while the replacement
        # tmp was mid-write, before backup and swap.
        assert journal.read_bytes() == before
        assert not (out / f"{JOURNAL_FILENAME}.pre-supersede").exists()
        assert _leaked_tmp(out), "leg missed its seam: no tmp leaked"
        _assert_recovered(out, spend)

    def test_sigkill_pre_rename(self, tmp_path: Path) -> None:
        out, before, spend = self._setup(tmp_path)
        _kill_at("pre-rename", out, tmp_path)
        journal = out / JOURNAL_FILENAME
        # Tmp fully written but neither backup nor swap happened.
        assert journal.read_bytes() == before
        assert not (out / f"{JOURNAL_FILENAME}.pre-supersede").exists()
        assert _leaked_tmp(out), "leg missed its seam: no tmp leaked"
        _assert_recovered(out, spend)

    def test_sigkill_mid_archive(self, tmp_path: Path) -> None:
        out, before, spend = self._setup(tmp_path)
        _kill_at("mid-archive", out, tmp_path)
        journal = out / JOURNAL_FILENAME
        backup = out / f"{JOURNAL_FILENAME}.pre-supersede"
        # Backup hardlink landed, swap did not: journal is the old
        # bytes and the archive holds the same full original.
        assert journal.read_bytes() == before
        assert backup.read_bytes() == before
        assert _leaked_tmp(out), "leg missed its seam: no tmp leaked"
        _assert_recovered(out, spend)

    def test_sigkill_post_rename(self, tmp_path: Path) -> None:
        out, before, spend = self._setup(tmp_path)
        _kill_at("post-rename", out, tmp_path)
        journal = out / JOURNAL_FILENAME
        backup = out / f"{JOURNAL_FILENAME}.pre-supersede"
        after = journal.read_bytes()
        # Swap completed: journal is the NEW bytes (strictly smaller
        # — re-emissions and superseded rows dropped), the archive
        # holds the full original, and the tmp was consumed by the
        # rename itself.
        assert after != before and len(after) < len(before)
        assert backup.read_bytes() == before
        assert _leaked_tmp(out) == []
        _assert_recovered(out, spend)
