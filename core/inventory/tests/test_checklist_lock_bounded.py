"""_checklist_lock: foreign-uid refusal and bounded waiting.

The checklist lock's contract is raise-on-failure (updates must not
proceed unserialised), so both hostile shapes fail the update loudly:
a pre-created foreign-uid lock file is never adopted, and a holder
that outlives the bounded wait raises instead of parking every
checklist writer silently and forever.
"""

from __future__ import annotations

import os
import threading
from pathlib import Path

import pytest

import core.atomic_fs.fs_lock as fs_lock
from core.inventory import _checklist_lock

pytest.importorskip("fcntl", reason="fcntl unavailable (non-POSIX)")


def test_foreign_uid_lock_file_fails_the_update(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
):
    checklist = tmp_path / "checklist.json"
    (tmp_path / "checklist.lock").write_bytes(b"")
    real_euid = os.geteuid()
    monkeypatch.setattr(os, "geteuid", lambda: real_euid + 1)
    with pytest.raises(OSError, match="foreign lock file"):
        with _checklist_lock(checklist):
            pass


def test_wedged_holder_fails_the_update_after_bounded_wait(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
):
    import fcntl
    monkeypatch.setattr(fs_lock, "_ACQUIRE_DEADLINE_S", 0.5,
                        raising=False)
    monkeypatch.setattr(fs_lock, "_ACQUIRE_POLL_S", 0.05,
                        raising=False)
    checklist = tmp_path / "checklist.json"
    lock = tmp_path / "checklist.lock"
    holder_fd = os.open(str(lock), os.O_WRONLY | os.O_CREAT, 0o600)
    errors: list[BaseException] = []
    done = threading.Event()

    def updater() -> None:
        try:
            with _checklist_lock(checklist):
                pass
        except OSError as exc:
            errors.append(exc)
        finally:
            done.set()

    thread = threading.Thread(target=updater, daemon=True)
    try:
        fcntl.flock(holder_fd, fcntl.LOCK_EX)
        thread.start()
        assert done.wait(timeout=10), (
            "checklist updater still blocked on a wedged holder"
        )
        assert errors, "update neither raised nor was refused"
        assert "refusing to proceed unserialised" in str(errors[0])
    finally:
        os.close(holder_fd)
        thread.join(timeout=10)
