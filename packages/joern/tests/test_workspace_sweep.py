"""Tests for the Joern server's workspace ownership marker + sweep.

The per-boot workspace is removed on ``stop()``, which a hard-killed
owner skips — these confirm the creation-time marker and the
boot-time reclamation of dead-owner siblings.
"""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import time
from pathlib import Path

import pytest

from core.run.tmp_ownership import LEGACY_MAX_AGE_S, OWNER_MARKER_NAME
from packages.joern.server import (
    _WORKSPACE_PREFIX,
    _new_workspace,
    sweep_stale_workspaces,
)

import packages.joern.server as _tempfile_owner


@pytest.fixture(autouse=True)
def _owned_tempfile_namespace(monkeypatch):
    """Share temporary-root faults only among this file's consumers."""
    from core.testing.tempdirs import private_tempfile_module
    import packages.joern.server as consumer_0
    import core.run.tmp_ownership as consumer_1
    import packages.joern.client as consumer_2

    private = private_tempfile_module(consumer_0.tempfile)
    monkeypatch.setattr(consumer_0, "tempfile", private)
    monkeypatch.setattr(consumer_1, "tempfile", private)
    monkeypatch.setattr(consumer_2, "tempfile", private)
    monkeypatch.setitem(globals(), "tempfile", private)
    # These tests model a bare caller selecting its current temporary root.
    monkeypatch.setattr(consumer_2, "_INITIAL_BASE", None)


@pytest.fixture
def tmp_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, _owned_tempfile_namespace) -> Path:
    monkeypatch.setattr(_tempfile_owner.tempfile, 'tempdir', str(tmp_path))
    return tmp_path


def _dead_pid() -> int:
    proc = subprocess.Popen([sys.executable, "-c", "pass"])
    proc.wait()
    return proc.pid


def _workspace(tmp_root: Path, name: str, pid: int | None = None) -> Path:
    d = tmp_root / f"{_WORKSPACE_PREFIX}{name}"
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


def test_new_workspace_writes_owner_marker(tmp_root: Path):
    ws = Path(_new_workspace())
    assert ws.is_dir()
    assert ws.name.startswith(_WORKSPACE_PREFIX)
    marker = ws / OWNER_MARKER_NAME
    assert marker.is_file()
    data = json.loads(marker.read_text(encoding="utf-8"))
    assert data["pid"] == os.getpid()
    assert stat.S_IMODE(marker.stat().st_mode) == 0o600


def test_sweep_removes_dead_owner_workspace(tmp_root: Path):
    dead = _workspace(tmp_root, "dead", pid=_dead_pid())
    removed = sweep_stale_workspaces()
    assert dead in removed
    assert not dead.exists()


def test_sweep_keeps_live_owner_workspace(tmp_root: Path):
    live = _workspace(tmp_root, "live", pid=os.getpid())
    assert sweep_stale_workspaces() == []
    assert live.is_dir()


def test_sweep_keeps_young_markerless_workspace(tmp_root: Path):
    young = _workspace(tmp_root, "young")
    assert sweep_stale_workspaces() == []
    assert young.is_dir()


def test_sweep_removes_old_markerless_workspace(tmp_root: Path):
    old = _workspace(tmp_root, "old")
    _age(old, LEGACY_MAX_AGE_S + 3600)
    removed = sweep_stale_workspaces()
    assert old in removed
    assert not old.exists()


def test_sweep_shields_workspace_being_created(tmp_root: Path):
    old = _workspace(tmp_root, "mine")
    _age(old, LEGACY_MAX_AGE_S + 3600)
    assert sweep_stale_workspaces(exclude=str(old)) == []
    assert old.is_dir()


def test_sweep_does_not_follow_symlink_escape(tmp_root: Path,
                                              tmp_path_factory):
    outside = tmp_path_factory.mktemp("outside")
    victim = outside / "victim.txt"
    victim.write_text("keep me", encoding="utf-8")
    link = tmp_root / f"{_WORKSPACE_PREFIX}escape"
    link.symlink_to(outside)
    _age(outside, LEGACY_MAX_AGE_S + 3600)
    assert sweep_stale_workspaces() == []
    assert victim.read_text(encoding="utf-8") == "keep me"
    assert link.is_symlink()


@pytest.fixture(autouse=True)
def _idle_fixture_cwds(monkeypatch):
    # These tests own isolated directories; cwd discovery is a separate
    # native integration concern. An unrelated lsof warning must not
    # turn their dead-owner/age assertions into host-dependent results.
    monkeypatch.setattr("core.run.tmp_ownership._live_cwds", lambda: set())
