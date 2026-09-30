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


@pytest.mark.skipif(not hasattr(os, "mkfifo"),
                    reason="mkfifo unavailable (non-POSIX)")
def test_fifo_at_lock_path_is_refused_loudly(tmp_path: Path):
    """A planted reader-less FIFO at the predictable lock path must be
    refused promptly — a blocking open would stall the writer forever
    BEFORE the bounded wait even starts."""
    md = tmp_path / "notes.md"
    md.write_text("x")
    os.mkfifo(tmp_path / "notes.md.lock")
    errors: list[BaseException] = []
    done = threading.Event()

    def writer() -> None:
        try:
            with _file_lock(md):
                pass
        except AnnotationFileError as exc:
            errors.append(exc)
        finally:
            done.set()

    thread = threading.Thread(target=writer, daemon=True)
    thread.start()
    try:
        assert done.wait(timeout=10), (
            "writer wedged opening the planted FIFO lock path"
        )
        assert errors, "the FIFO lock path was neither refused nor hung"
        assert "not a regular file" in str(errors[0])
    finally:
        thread.join(timeout=10)
