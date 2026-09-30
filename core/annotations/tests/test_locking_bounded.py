"""Annotation write lock: bounded waiting, cross-uid adoption kept.

The annotation lock is the documented two-operator rendezvous — a
lock file created by ANOTHER uid is legitimately taken (0o666 mode,
read-only open), so there is deliberately no foreign-uid refusal
here. The protection against a wedged or hostile holder is the
bounded announce-once wait: expiry raises AnnotationFileError instead
of stalling the writer silently and forever.
"""

from __future__ import annotations

import os
import threading
from pathlib import Path

import pytest

import core.atomic_fs.fs_lock as fs_lock
from core.annotations.storage import AnnotationFileError, _file_lock

pytest.importorskip("fcntl", reason="fcntl unavailable (non-POSIX)")


def test_cross_uid_lock_file_is_still_adopted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
):
    """Two-operator contract: a foreign-uid lock file is taken, not
    refused — the annotation lock is shared across uids by design."""
    target = tmp_path / "notes.md"
    (tmp_path / "notes.md.lock").write_bytes(b"")
    real_euid = os.geteuid()
    monkeypatch.setattr(os, "geteuid", lambda: real_euid + 1)
    entered = False
    with _file_lock(target):
        entered = True
    assert entered


def test_wedged_holder_raises_after_bounded_wait(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
):
    import fcntl
    monkeypatch.setattr(fs_lock, "_ACQUIRE_DEADLINE_S", 0.5,
                        raising=False)
    monkeypatch.setattr(fs_lock, "_ACQUIRE_POLL_S", 0.05,
                        raising=False)
    target = tmp_path / "notes.md"
    lock = tmp_path / "notes.md.lock"
    holder_fd = os.open(str(lock), os.O_WRONLY | os.O_CREAT, 0o600)
    errors: list[BaseException] = []
    done = threading.Event()

    def writer() -> None:
        try:
            with _file_lock(target):
                pass
        except AnnotationFileError as exc:
            errors.append(exc)
        finally:
            done.set()

    thread = threading.Thread(target=writer, daemon=True)
    try:
        fcntl.flock(holder_fd, fcntl.LOCK_EX)
        with caplog.at_level("WARNING"):
            thread.start()
            assert done.wait(timeout=10), (
                "annotation writer still blocked on a wedged holder"
            )
        assert errors, "write neither raised nor was refused"
        assert "bounded wait" in str(errors[0])
        assert any("held by another process" in r.message
                   for r in caplog.records)
    finally:
        os.close(holder_fd)
        thread.join(timeout=10)
