"""fd discipline for the manifest and journal readers.

Both files sit inside the sandbox write grant, so check-by-name
probes race a swap (a symlink swapped in between ``lstat`` and
``open`` ingested a FOREIGN file's lines into coverage records), a
planted FIFO wedges a plain ``open()`` forever, and unbounded line
iteration materialises one huge line whole before any byte budget
fires. These tests pin the ``open_regular`` discipline (O_NOFOLLOW +
O_NONBLOCK + fstat-S_ISREG on the opened fd), byte-counted caps, and
line-granular budget enforcement.
"""

from __future__ import annotations

import os
import threading
import time
import tracemalloc

import pytest

from core.coverage.record import read_manifest_lines
from core.coverage.journal import load_entries


class TestManifestReader:
    def test_symlink_manifest_refused(self, tmp_path):
        foreign = tmp_path / "foreign.txt"
        foreign.write_text("/etc/FOREIGN\n")
        manifest = tmp_path / ".reads-manifest"
        manifest.symlink_to(foreign)
        assert read_manifest_lines(manifest) == set()

    def test_fifo_manifest_refused_without_blocking(self, tmp_path):
        manifest = tmp_path / ".reads-manifest"
        os.mkfifo(manifest)
        done = threading.Event()
        result: list[set] = []

        def _read() -> None:
            result.append(read_manifest_lines(manifest))
            done.set()

        t = threading.Thread(target=_read, daemon=True)
        t.start()
        assert done.wait(5), "manifest read wedged on a planted FIFO"
        assert result == [set()]

    def test_missing_manifest_is_silent_empty(self, tmp_path):
        assert read_manifest_lines(tmp_path / ".reads-manifest") == set()

    def test_cap_counts_bytes_not_chars(self, tmp_path, monkeypatch):
        # 20 lines of 3-byte chars: 100 CHARS total but 260 bytes.
        # A char-counted cap of 100 admitted every line (~4x byte
        # overshoot on multi-byte content); the byte-counted cap
        # stops partway.
        monkeypatch.setattr("core.coverage.record._MANIFEST_CAP", 100)
        manifest = tmp_path / ".reads-manifest"
        manifest.write_bytes(
            b"".join(f"€€€{i:02d}\n".encode()
                     for i in range(20)))
        files = read_manifest_lines(manifest)
        assert 0 < len(files) <= 8, (
            f"{len(files)} lines admitted under a 100-BYTE cap — "
            "the cap is counting decoded characters"
        )

    @pytest.mark.slow
    def test_swap_race_never_ingests_foreign_lines(self, tmp_path):
        # Bounded race harness: a swapper flips
        # the manifest between a regular file and a symlink to a
        # foreign file while the reader loops. The by-name-check
        # reader lost this race within seconds; the fd-checked reader
        # must never ingest the foreign line.
        manifest = tmp_path / ".reads-manifest"
        foreign = tmp_path / "foreign.txt"
        foreign.write_text("/etc/FOREIGN-INGESTED\n")
        stop = threading.Event()

        def swapper() -> None:
            while not stop.is_set():
                try:
                    with open(manifest, "w") as f:
                        f.write("benign.c\n")
                    os.unlink(manifest)
                    os.symlink(foreign, manifest)
                    os.unlink(manifest)
                except OSError:
                    pass

        t = threading.Thread(target=swapper, daemon=True)
        t.start()
        try:
            deadline = time.time() + 5
            while time.time() < deadline:
                files = read_manifest_lines(manifest)
                assert not any("FOREIGN" in f for f in files), (
                    "foreign lines ingested past the regularity check"
                )
        finally:
            stop.set()
            t.join(2)


class TestJournalReader:
    def test_fifo_journal_refused_without_blocking(self, tmp_path):
        os.mkfifo(tmp_path / "review-journal.jsonl")
        done = threading.Event()
        result: list[list] = []

        def _read() -> None:
            result.append(load_entries(tmp_path))
            done.set()

        t = threading.Thread(target=_read, daemon=True)
        t.start()
        assert done.wait(5), "journal read wedged on a planted FIFO"
        assert result == [[]]

    def test_symlink_journal_refused(self, tmp_path):
        foreign = tmp_path / "foreign.jsonl"
        foreign.write_text("{}\n")
        (tmp_path / "review-journal.jsonl").symlink_to(foreign)
        assert load_entries(tmp_path) == []

    def test_budget_holds_at_line_granularity(self, tmp_path, monkeypatch):
        # A file that grows past the size gate after the open (raced
        # writer) used to be re-capped only BETWEEN lines: one huge
        # line materialised whole before the budget fired. Simulate
        # the race deterministically by under-reporting st_size, and
        # pin the reader's own peak memory.
        from pathlib import Path

        journal = tmp_path / "review-journal.jsonl"
        journal.write_bytes(b'{"pad": "' + b"A" * (30 * 1024 * 1024)
                            + b'"}\n')

        def _shrink(st: os.stat_result) -> os.stat_result:
            fields = list(st)
            fields[6] = 100          # st_size: pass the size gate
            return os.stat_result(fields)

        real_fstat = os.fstat
        monkeypatch.setattr(
            "core.coverage.journal.os.fstat",
            lambda fd: _shrink(real_fstat(fd)))
        # The size gate must under-report through EVERY stat spelling
        # a reader generation used (fd-based fstat and by-name
        # Path.stat), so the pin measures the line-materialisation
        # behaviour, not which gate variant runs.
        real_stat = Path.stat

        def _small_stat(self: Path, **kw: bool) -> os.stat_result:
            st = real_stat(self, **kw)
            if self.name == "review-journal.jsonl":
                return _shrink(st)
            return st

        monkeypatch.setattr(Path, "stat", _small_stat)
        monkeypatch.setattr(
            "core.coverage.journal._MAX_JOURNAL_BYTES", 64 * 1024)
        tracemalloc.start()
        try:
            entries = load_entries(tmp_path)
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        assert entries == []
        assert peak < 5 * 1024 * 1024, (
            f"reader peaked at {peak} bytes on a 30 MB line under a "
            "64 KiB budget — the line was materialised before the cap"
        )
