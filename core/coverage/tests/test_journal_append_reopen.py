"""Foreign-appender rename-race protection in ``append_entry``.

The contract under test: a compactor's tempfile+rename swap between
an appender's ``open`` and its ``flock`` must never make the append
land on the renamed-away (archived) inode — the post-flock
``(dev, ino)`` re-validation releases the stale fd and retries the
open by name, bounded, failing loud when the journal keeps being
swapped from under it.
"""

from __future__ import annotations

import fcntl
import json
import os
from pathlib import Path

import pytest

import core.coverage.journal as journal_mod
from core.coverage.journal import (
    JOURNAL_FILENAME,
    ReviewJournalEntry,
    append_entry,
    load_entries,
    now_iso,
)


def _entry(i: int) -> ReviewJournalEntry:
    return ReviewJournalEntry(
        ts=now_iso(),
        run_id="run-1",
        file=f"src/f{i}.c",
        function=f"fn{i}",
        verdict="clean",
        source_hash="abc123",
        line_start=i + 1,
    )


def _functions_in(path: Path) -> list[str]:
    return [
        json.loads(line)["function"]
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


class TestRenameRace:
    def test_swap_between_open_and_flock_lands_on_live_inode(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Stage the race deterministically: the appender opens the
        journal, a 'compactor' renames it away and installs a
        replacement, THEN the appender's flock is granted. The row
        must land in the file the journal NAME resolves to — never
        the archived inode."""
        journal = tmp_path / JOURNAL_FILENAME
        archived = tmp_path / (JOURNAL_FILENAME + ".pre-compact")
        append_entry(tmp_path, _entry(0))
        original_line = journal.read_bytes()

        real_flock = fcntl.flock
        state = {"swapped": False}

        def racing_flock(fd: int, op: int) -> None:
            # First exclusive acquisition: simulate the compactor's
            # swap AFTER the appender's open but BEFORE its lock is
            # granted (the compactor held the flock across its swap
            # and released it just before we were woken).
            if op == fcntl.LOCK_EX and not state["swapped"]:
                state["swapped"] = True
                os.rename(journal, archived)
                journal.write_bytes(original_line)  # "compacted" live file
            real_flock(fd, op)

        monkeypatch.setattr(fcntl, "flock", racing_flock)
        append_entry(tmp_path, _entry(1))

        # The new row is in the LIVE journal (by name), not the archive.
        assert "fn1" in _functions_in(journal)
        assert "fn1" not in _functions_in(archived)
        # Every line in both files is intact JSON (no torn writes).
        entries = load_entries(tmp_path, fresh=True)
        assert {e.function for e in entries} == {"fn0", "fn1"}

    def test_reopen_retry_is_bounded_and_loud(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A journal that reads as swapped on EVERY attempt exhausts
        the bounded retries and raises — with the journal bytes
        untouched (no torn tail, no row on any inode)."""
        journal = tmp_path / JOURNAL_FILENAME
        append_entry(tmp_path, _entry(0))
        before = journal.read_bytes()

        calls = {"n": 0}

        def never_live(fd: int, path: Path) -> bool:
            calls["n"] += 1
            return False

        monkeypatch.setattr(journal_mod, "_fd_at_path", never_live)
        with pytest.raises(OSError, match="swapped from under"):
            append_entry(tmp_path, _entry(1))

        assert calls["n"] == journal_mod._APPEND_REOPEN_ATTEMPTS
        assert journal.read_bytes() == before

    def test_fast_path_single_open_and_lock_cycle(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """No compactor interference: exactly one open/flock cycle,
        one identity check, and the row round-trips — the re-stat is
        a two-syscall overlay on the historical fast path."""
        append_entry(tmp_path, _entry(0))

        real_fd_at_path = journal_mod._fd_at_path
        checks = {"n": 0}

        def counting(fd: int, path: Path) -> bool:
            checks["n"] += 1
            return real_fd_at_path(fd, path)

        real_flock = fcntl.flock
        ex_locks = {"n": 0}

        def counting_flock(fd: int, op: int) -> None:
            if op == fcntl.LOCK_EX:
                ex_locks["n"] += 1
            real_flock(fd, op)

        monkeypatch.setattr(journal_mod, "_fd_at_path", counting)
        monkeypatch.setattr(fcntl, "flock", counting_flock)
        append_entry(tmp_path, _entry(1))

        assert checks["n"] == 1
        assert ex_locks["n"] == 1
        entries = load_entries(tmp_path, fresh=True)
        assert {e.function for e in entries} == {"fn0", "fn1"}

    def test_retry_reresolves_the_active_shard(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The reopen retry re-derives the shard path instead of
        assuming the pre-wait one — a swap implies the shard set may
        have been rewritten while this appender waited."""
        append_entry(tmp_path, _entry(0))

        real_resolve = journal_mod._append_shard_path
        resolves = {"n": 0}

        def counting_resolve(out_dir: Path) -> Path:
            resolves["n"] += 1
            return real_resolve(out_dir)

        state = {"failed_once": False}
        real_fd_at_path = journal_mod._fd_at_path

        def fail_once(fd: int, path: Path) -> bool:
            if not state["failed_once"]:
                state["failed_once"] = True
                return False
            return real_fd_at_path(fd, path)

        monkeypatch.setattr(
            journal_mod, "_append_shard_path", counting_resolve)
        monkeypatch.setattr(journal_mod, "_fd_at_path", fail_once)
        append_entry(tmp_path, _entry(1))

        assert resolves["n"] == 2  # one per attempt
        entries = load_entries(tmp_path, fresh=True)
        assert {e.function for e in entries} == {"fn0", "fn1"}
