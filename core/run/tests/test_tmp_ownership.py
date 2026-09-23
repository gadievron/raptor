"""Tests for :mod:`core.run.tmp_ownership` (dead-owner reclamation)."""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest

from core.run.tmp_ownership import (
    LEGACY_MAX_AGE_S,
    OWNER_MARKER_NAME,
    remove_owner_marker,
    sweep_dead_owner_dirs,
    write_owner_marker,
)

PREFIX = "raptor-test-owned-"


@pytest.fixture
def tmp_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point :func:`tempfile.gettempdir` at a per-test dir."""
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
    return tmp_path


def _dead_pid() -> int:
    proc = subprocess.Popen([sys.executable, "-c", "pass"])
    proc.wait()
    return proc.pid


def _mkdir(tmp_root: Path, name: str, pid: int | None = None) -> Path:
    d = tmp_root / name
    d.mkdir()
    if pid is not None:
        (d / OWNER_MARKER_NAME).write_text(
            json.dumps({"pid": pid, "created": time.time()}),
            encoding="utf-8",
        )
    return d


def _age(d: Path, seconds: float) -> None:
    t = time.time() - seconds
    os.utime(d, (t, t))


class TestOwnerMarker:
    def test_marker_written_with_pid_and_0600(self, tmp_root: Path):
        d = tmp_root / f"{PREFIX}fresh"
        d.mkdir()
        write_owner_marker(d)
        marker = d / OWNER_MARKER_NAME
        assert marker.is_file()
        data = json.loads(marker.read_text(encoding="utf-8"))
        assert data["pid"] == os.getpid()
        assert isinstance(data["created"], float)
        assert stat.S_IMODE(marker.stat().st_mode) == 0o600

    def test_write_failure_is_swallowed(self, tmp_root: Path):
        # Nonexistent parent — must not raise.
        write_owner_marker(tmp_root / "does-not-exist")

    def test_remove_marker_tolerates_missing(self, tmp_root: Path):
        d = tmp_root / f"{PREFIX}nomarker"
        d.mkdir()
        remove_owner_marker(d)  # no marker present
        remove_owner_marker(tmp_root / "does-not-exist")

    def test_remove_marker_removes(self, tmp_root: Path):
        d = tmp_root / f"{PREFIX}marked"
        d.mkdir()
        write_owner_marker(d)
        remove_owner_marker(d)
        assert not (d / OWNER_MARKER_NAME).exists()


class TestSweep:
    def test_removes_dead_owner_dir(self, tmp_root: Path):
        dead = _mkdir(tmp_root, f"{PREFIX}dead", pid=_dead_pid())
        removed = sweep_dead_owner_dirs(PREFIX)
        assert dead in removed
        assert not dead.exists()

    def test_keeps_live_owner_dir(self, tmp_root: Path):
        live = _mkdir(tmp_root, f"{PREFIX}live", pid=os.getpid())
        assert sweep_dead_owner_dirs(PREFIX) == []
        assert live.is_dir()

    def test_keeps_young_markerless_dir(self, tmp_root: Path):
        young = _mkdir(tmp_root, f"{PREFIX}young")
        assert sweep_dead_owner_dirs(PREFIX) == []
        assert young.is_dir()

    def test_removes_old_markerless_dir(self, tmp_root: Path):
        old = _mkdir(tmp_root, f"{PREFIX}old")
        _age(old, LEGACY_MAX_AGE_S + 3600)
        removed = sweep_dead_owner_dirs(PREFIX)
        assert old in removed
        assert not old.exists()

    def test_keeps_malformed_marker_young_dir(self, tmp_root: Path):
        d = _mkdir(tmp_root, f"{PREFIX}junkmarker")
        (d / OWNER_MARKER_NAME).write_text("not json", encoding="utf-8")
        assert sweep_dead_owner_dirs(PREFIX) == []
        assert d.is_dir()

    def test_symlink_escape_not_followed(self, tmp_root: Path,
                                          tmp_path_factory):
        outside = tmp_path_factory.mktemp("outside")
        victim = outside / "victim.txt"
        victim.write_text("keep me", encoding="utf-8")
        link = tmp_root / f"{PREFIX}escape"
        link.symlink_to(outside)
        # Age the target well past the floor: the symlink must be
        # skipped on its own lstat, not saved by a young target.
        _age(outside, LEGACY_MAX_AGE_S + 3600)
        assert sweep_dead_owner_dirs(PREFIX) == []
        assert victim.read_text(encoding="utf-8") == "keep me"
        assert link.is_symlink()

    def test_excluded_dir_survives(self, tmp_root: Path):
        old = _mkdir(tmp_root, f"{PREFIX}mine")
        _age(old, LEGACY_MAX_AGE_S + 3600)
        assert sweep_dead_owner_dirs(PREFIX, exclude=old) == []
        assert old.is_dir()

    def test_nonmatching_prefix_untouched(self, tmp_root: Path):
        other = _mkdir(tmp_root, "other-scratch", pid=_dead_pid())
        _age(other, LEGACY_MAX_AGE_S + 3600)
        assert sweep_dead_owner_dirs(PREFIX) == []
        assert other.is_dir()

    def test_never_raises_on_bad_tempdir(self, tmp_path: Path,
                                         monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(
            tempfile, "tempdir", str(tmp_path / "gone"),
        )
        assert sweep_dead_owner_dirs(PREFIX) == []


class TestOwnerPidGatedRead:
    """Markers live in world-writable /tmp — the type/size gate must
    hold on the inode actually read (a FIFO swapped in after a
    by-name lstat blocked the reaper forever), and symlinked markers
    stay refused (O_NOFOLLOW keeps the lstat semantics)."""

    def test_fifo_marker_none_not_hung(self, tmp_path: Path):
        import signal as _signal

        from core.run.tmp_ownership import _owner_pid

        if not hasattr(os, "mkfifo"):
            pytest.skip("platform lacks mkfifo")
        marker = tmp_path / OWNER_MARKER_NAME
        os.mkfifo(marker)

        def _on_alarm(signum, frame):
            msg = "_owner_pid blocked on a planted FIFO"
            raise AssertionError(msg)

        old = _signal.signal(_signal.SIGALRM, _on_alarm)
        _signal.alarm(30)
        try:
            assert _owner_pid(marker) is None
        finally:
            _signal.alarm(0)
            _signal.signal(_signal.SIGALRM, old)

    def test_symlinked_marker_refused(self, tmp_path: Path):
        from core.run.tmp_ownership import _owner_pid

        real = tmp_path / "real.json"
        real.write_text(json.dumps({"pid": os.getpid()}))
        marker = tmp_path / OWNER_MARKER_NAME
        try:
            marker.symlink_to(real)
        except OSError:
            pytest.skip("platform lacks symlinks")
        assert _owner_pid(marker) is None

    def test_valid_marker_roundtrip(self, tmp_path: Path):
        from core.run.tmp_ownership import _owner_pid

        marker = tmp_path / OWNER_MARKER_NAME
        marker.write_text(json.dumps({"pid": os.getpid()}))
        assert _owner_pid(marker) == os.getpid()
