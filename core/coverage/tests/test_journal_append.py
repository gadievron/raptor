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
