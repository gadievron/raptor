"""pack_write_lock: the hoisted hardened idiom flows through.

Delegating to core.atomic_fs.fs_lock's artifact_lock adds the
foreign-uid refusal and the bounded announce-once wait the local flock
lacked; both degrade loudly to the unlocked path (harvest merges are
additive-only, so a lost single-writer guarantee never corrupts a
pack — it can only drop a concurrent contribution, which the warning
makes visible).
"""

from __future__ import annotations

import os
import threading
from pathlib import Path

import pytest

import core.atomic_fs.fs_lock as fs_lock
from core.dataflow.parser_pack_harvest import pack_write_lock

pytest.importorskip("fcntl", reason="fcntl unavailable (non-POSIX)")


def test_foreign_uid_lock_file_degrades_loudly(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
):
    pack = tmp_path / "pack.json"
    (tmp_path / "pack.json.lock").write_bytes(b"")
    real_euid = os.geteuid()
    monkeypatch.setattr(os, "geteuid", lambda: real_euid + 1)
    entered = False
    with caplog.at_level("WARNING"):
        with pack_write_lock(pack):
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
    monkeypatch.setattr(fs_lock, "_ACQUIRE_DEADLINE_S", 0.5,
                        raising=False)
    monkeypatch.setattr(fs_lock, "_ACQUIRE_POLL_S", 0.05,
                        raising=False)
    pack = tmp_path / "pack.json"
    lock = tmp_path / "pack.json.lock"
    holder_fd = os.open(str(lock), os.O_WRONLY | os.O_CREAT, 0o600)
    entered = threading.Event()

    def harvester() -> None:
        with pack_write_lock(pack):
            entered.set()

    thread = threading.Thread(target=harvester, daemon=True)
    try:
        fcntl.flock(holder_fd, fcntl.LOCK_EX)
        with caplog.at_level("WARNING"):
            thread.start()
            assert entered.wait(timeout=10), (
                "harvest writer still blocked on a wedged holder"
            )
        assert any("held by another process" in r.message
                   for r in caplog.records)
        assert any("WITHOUT" in r.message for r in caplog.records)
    finally:
        os.close(holder_fd)
        thread.join(timeout=10)
