"""project_file_lock: the hoisted hardened idiom flows through.

Migrating to core.atomic_fs.fs_lock's artifact_lock adds the
foreign-uid refusal and the bounded announce-once wait the local copy
lacked; both degrade loudly to the unlocked path (project mutations
stay best-effort).
"""

from __future__ import annotations

import os
import threading
from pathlib import Path

import pytest

from core.testing.module_bindings import patch_module_attribute
from core.testing.poll_clock import install_poll_clock

import core.atomic_fs.fs_lock as fs_lock
from core.project.project import project_file_lock

pytest.importorskip("fcntl", reason="fcntl unavailable (non-POSIX)")


def test_foreign_uid_lock_file_degrades_loudly(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
):
    project_file = tmp_path / "project.json"
    (tmp_path / "project.json.lock").write_bytes(b"")
    real_euid = os.geteuid()
    patch_module_attribute(monkeypatch, fs_lock, "os", "geteuid", lambda: real_euid + 1)
    entered = False
    with caplog.at_level("WARNING"):
        with project_file_lock(project_file):
            entered = True
    assert entered
    assert any(
        "WITHOUT" in r.message and "uid" in r.getMessage()
        for r in caplog.records
    )


def test_wedged_holder_degrades_after_bounded_wait(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
):
    import fcntl
    clock = install_poll_clock(monkeypatch, fs_lock)
    monkeypatch.setattr(fs_lock, "_ACQUIRE_DEADLINE_S", 0.5,
                        raising=False)
    monkeypatch.setattr(fs_lock, "_ACQUIRE_POLL_S", 0.05,
                        raising=False)
    project_file = tmp_path / "project.json"
    lock = tmp_path / "project.json.lock"
    holder_fd = os.open(str(lock), os.O_WRONLY | os.O_CREAT, 0o600)
    entered = threading.Event()

    def mutator() -> None:
        with project_file_lock(project_file):
            entered.set()

    thread = threading.Thread(target=mutator, daemon=True)
    try:
        fcntl.flock(holder_fd, fcntl.LOCK_EX)
        with caplog.at_level("WARNING"):
            thread.start()
            assert entered.wait(timeout=10), (
                "project mutation still blocked on a wedged holder"
            )
        assert any("held by another process" in r.message
                   for r in caplog.records)
        assert any("WITHOUT" in r.message for r in caplog.records)
    finally:
        os.close(holder_fd)
        if thread.ident is not None:
            thread.join(timeout=10)
            assert not thread.is_alive(), "lock waiter survived holder cleanup"

    assert clock.seconds >= 0.5
    assert len(clock.sleeps) > 1, "caller bypassed the polling wait"



def test_missing_parent_dir_is_not_conjured(
    tmp_path: Path, caplog: pytest.LogCaptureFixture,
):
    """A missing projects dir means the owner removed it: the lock
    degrades loudly to the unlocked path and must NOT resurrect the
    directory as a side effect."""
    missing = tmp_path / "gone" / "projects.json"
    entered = False
    with caplog.at_level("WARNING"):
        with project_file_lock(missing):
            entered = True
    assert entered
    assert not missing.parent.exists(), (
        "the lock conjured the removed parent directory"
    )
    assert any("WITHOUT" in r.message for r in caplog.records)
