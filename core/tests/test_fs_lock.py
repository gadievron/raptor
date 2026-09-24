"""Tests for core.fs_lock — the shared load → merge → write lock.

The lock file lives in directories broader write grants reach, so a
planted symlink or FIFO at the ``.lock`` path must degrade to the
loud unlocked path — never steer the flock to an attacker-chosen
inode and never block the writer on the open.
"""

import os
import stat
from pathlib import Path

import pytest

from core.fs_lock import artifact_lock


class TestArtifactLock:

    def test_locks_and_yields(self, tmp_path: Path):
        artifact = tmp_path / "store.json"
        with artifact_lock(artifact):
            pass
        lock = tmp_path / "store.json.lock"
        assert lock.is_file()
        assert stat.S_ISREG(lock.lstat().st_mode)

    def test_planted_symlink_degrades_without_following(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture,
    ):
        victim = tmp_path / "victim.txt"
        artifact = tmp_path / "store.json"
        (tmp_path / "store.json.lock").symlink_to(victim)
        entered = False
        with caplog.at_level("WARNING"):
            with artifact_lock(artifact):
                entered = True
        assert entered
        # The symlink target must not have been created through the
        # planted link.
        assert not victim.exists()
        assert any("WITHOUT" in r.message for r in caplog.records)

    @pytest.mark.skipif(
        not hasattr(os, "mkfifo"), reason="mkfifo unavailable (non-POSIX)")
    def test_planted_readerless_fifo_degrades_without_blocking(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture,
    ):
        """A reader-less FIFO at the lock path fails the open fast
        (ENXIO via O_NONBLOCK) instead of wedging the writer."""
        artifact = tmp_path / "store.json"
        os.mkfifo(tmp_path / "store.json.lock")
        entered = False
        with caplog.at_level("WARNING"):
            with artifact_lock(artifact):
                entered = True
        assert entered
        assert any("WITHOUT" in r.message for r in caplog.records)

    @pytest.mark.skipif(
        not hasattr(os, "mkfifo"), reason="mkfifo unavailable (non-POSIX)")
    def test_planted_fifo_with_reader_refused_by_regularity_check(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture,
    ):
        """A FIFO that HAS a reader opens fine — the post-open fstat
        regularity refusal is what keeps the flock off it."""
        artifact = tmp_path / "store.json"
        fifo = tmp_path / "store.json.lock"
        os.mkfifo(fifo)
        reader = os.open(str(fifo), os.O_RDONLY | os.O_NONBLOCK)
        try:
            entered = False
            with caplog.at_level("WARNING"):
                with artifact_lock(artifact):
                    entered = True
            assert entered
            assert any(
                "not a regular file" in r.getMessage()
                for r in caplog.records
            )
        finally:
            os.close(reader)

    def test_uncreatable_lock_degrades(self, tmp_path: Path):
        """Pre-existing degrade contract: a lock the writer cannot
        create still yields (best-effort writers must not fail)."""
        ro_dir = tmp_path / "ro"
        ro_dir.mkdir()
        artifact = ro_dir / "store.json"
        ro_dir.chmod(0o500)
        try:
            if os.access(ro_dir, os.W_OK):
                pytest.skip("cannot make directory read-only (root?)")
            entered = False
            with artifact_lock(artifact):
                entered = True
            assert entered
        finally:
            ro_dir.chmod(0o700)
