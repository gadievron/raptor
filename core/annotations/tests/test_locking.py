"""Tests for cross-process locking on annotation writes.

Without the lock, two concurrent writers can lose each other's
data via the read-modify-write race: both load state A, both write
A+B1 / A+B2, one of B1/B2 is dropped. The lock serialises them.

These tests fork real subprocesses (not threads) — fcntl.flock is
process-level, and POSIX semantics are what we actually rely on.
"""

from __future__ import annotations

import multiprocessing as mp
import os
import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[3]


def _writer_proc(base_str: str, file: str, prefix: str, count: int):
    """Worker: write ``count`` annotations to ``file`` with names
    ``<prefix>_001`` ... ``<prefix>_NNN``."""
    sys.path.insert(0, str(REPO_ROOT))
    from core.annotations import Annotation, write_annotation
    base = Path(base_str)
    for i in range(count):
        write_annotation(base, Annotation(
            file=file,
            function=f"{prefix}_{i:03d}",
            body=f"body for {prefix}_{i:03d}",
            metadata={"source": "llm", "status": "clean"},
        ))


class TestConcurrentWrites:
    """Two processes hammer the same file. With locking, all writes
    survive. Without it, ~half would be lost to the read-modify-write
    race."""

    def test_two_writers_no_data_loss(self, tmp_path):
        base = tmp_path / "annotations"
        # 50 annotations per writer, two writers — 100 total.
        # Without locking this used to lose roughly half on real systems.
        per_writer = 50
        ctx = mp.get_context("fork")
        p1 = ctx.Process(
            target=_writer_proc,
            args=(str(base), "src/concur.py", "alice", per_writer),
        )
        p2 = ctx.Process(
            target=_writer_proc,
            args=(str(base), "src/concur.py", "bob", per_writer),
        )
        p1.start()
        p2.start()
        p1.join(timeout=30)
        p2.join(timeout=30)
        assert p1.exitcode == 0, "writer 1 crashed"
        assert p2.exitcode == 0, "writer 2 crashed"

        from core.annotations import read_file_annotations
        annotations = read_file_annotations(base, "src/concur.py")
        names = {a.function for a in annotations}
        # 100 unique names expected. Race-induced losses would mean
        # we see fewer; the lock guarantees we see all.
        expected = (
            {f"alice_{i:03d}" for i in range(per_writer)}
            | {f"bob_{i:03d}" for i in range(per_writer)}
        )
        missing = expected - names
        assert not missing, (
            f"{len(missing)} annotations lost to read-modify-write "
            f"race — locking didn't serialise. Missing: "
            f"{sorted(list(missing))[:5]}..."
        )


class TestLockFileCleanup:
    """The .lock sibling file is left in place — this is OK and
    expected. Pin the behaviour so a future "clean it up" change
    doesn't introduce a race window between unlock and unlink."""

    def test_lock_file_persists(self, tmp_path):
        from core.annotations import Annotation, write_annotation
        write_annotation(tmp_path, Annotation(
            file="src/foo.py", function="f", body="x",
        ))
        # The .md.lock sibling is a normal file we just leave there.
        # If we tried to unlink it after release, another process
        # could acquire a lock on a since-deleted file and not see
        # contention.
        lock_path = tmp_path / "src" / "foo.py.md.lock"
        # On POSIX it'll exist; on a hypothetical no-fcntl platform
        # the test is skipped.
        from core.annotations.storage import _HAS_FCNTL
        if _HAS_FCNTL:
            assert lock_path.exists()
        else:
            pytest.skip("fcntl unavailable; locking is a no-op")
