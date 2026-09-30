"""_model_write_lock: foreign-uid refusal and bounded waiting.

This lock's contract is raise-on-failure (save_model must not proceed
unserialised), so both hostile shapes fail the save loudly: a
pre-created foreign-uid lock file is never adopted, and a holder that
outlives the bounded wait raises instead of stalling the saver
silently and forever.
"""

from __future__ import annotations

import os
import threading
from pathlib import Path

import pytest

import core.atomic_fs.fs_lock as fs_lock
from core.threat_model import _model_write_lock

pytest.importorskip("fcntl", reason="fcntl unavailable (non-POSIX)")


def test_foreign_uid_lock_file_fails_the_save(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
):
    json_path = tmp_path / "threat-model.json"
    (tmp_path / "threat-model.json.lock").write_bytes(b"")
    real_euid = os.geteuid()
    monkeypatch.setattr(os, "geteuid", lambda: real_euid + 1)
    with pytest.raises(OSError, match="foreign lock file"):
        with _model_write_lock(json_path):
            pass


def test_wedged_holder_fails_the_save_after_bounded_wait(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
):
    import fcntl
    monkeypatch.setattr(fs_lock, "_ACQUIRE_DEADLINE_S", 0.5,
                        raising=False)
    monkeypatch.setattr(fs_lock, "_ACQUIRE_POLL_S", 0.05,
                        raising=False)
    json_path = tmp_path / "threat-model.json"
    lock = tmp_path / "threat-model.json.lock"
    holder_fd = os.open(str(lock), os.O_WRONLY | os.O_CREAT, 0o600)
    errors: list[BaseException] = []
    done = threading.Event()

    def saver() -> None:
        try:
            with _model_write_lock(json_path):
                pass
        except OSError as exc:
            errors.append(exc)
        finally:
            done.set()

    thread = threading.Thread(target=saver, daemon=True)
    try:
        fcntl.flock(holder_fd, fcntl.LOCK_EX)
        thread.start()
        assert done.wait(timeout=10), (
            "saver still blocked on a wedged holder — no bounded "
            "deadline fired"
        )
        assert errors, "save neither raised nor was refused"
        assert "refusing to save unserialised" in str(errors[0])
    finally:
        os.close(holder_fd)
        thread.join(timeout=10)
