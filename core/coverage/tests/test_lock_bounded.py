"""Coverage store / journal locks: foreign-uid refusal and bounded
waiting.

The store and index sidecars live in run directories sandboxed target
code may hold a write grant on — a pre-created foreign-uid lock file
must degrade to the loud no-lock path, never be adopted. The journal
appender flocks the shard DATA file; a wedged holder must fail the
append loudly instead of parking every journal writer forever.
"""

from __future__ import annotations

import os
import threading
from pathlib import Path

import pytest

import core.atomic_fs.fs_lock as fs_lock
from core.coverage.journal import (
    ReviewJournalEntry,
    _flock,
    append_entry,
    now_iso,
)
from core.coverage.store import _HAS_FCNTL, coverage_store_lock

if not _HAS_FCNTL:  # pragma: no cover — non-POSIX
    pytest.skip("fcntl unavailable (non-POSIX)", allow_module_level=True)


def _entry(i: int) -> ReviewJournalEntry:
    return ReviewJournalEntry(
        ts=now_iso(),
        run_id="run-1",
        file=f"src/f{i}.c",
        function=f"fn{i}",
        verdict="clean",
        source_hash="abc123",
        line_start=i + 1,
    )


def test_store_lock_refuses_foreign_uid_lock_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
):
    (tmp_path / "coverage.json.lock").write_bytes(b"")
    real_euid = os.geteuid()
    monkeypatch.setattr(os, "geteuid", lambda: real_euid + 1)
    entered = False
    with caplog.at_level("WARNING"):
        with coverage_store_lock(tmp_path / "coverage.json"):
            entered = True
    assert entered
    assert any(
        "WITHOUT" in r.message and "uid" in r.getMessage()
        for r in caplog.records
    )


def test_index_flock_refuses_foreign_uid_lock_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
):
    idx = tmp_path / "review-journal-index.json"
    (tmp_path / "review-journal-index.json.lock").write_bytes(b"")
    real_euid = os.geteuid()
    monkeypatch.setattr(os, "geteuid", lambda: real_euid + 1)
    entered = False
    with caplog.at_level("WARNING"):
        with _flock(idx):
            entered = True
    assert entered
    assert any(
        "WITHOUT" in r.message and "uid" in r.getMessage()
        for r in caplog.records
    )


def test_store_lock_degrades_after_bounded_wait(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
):
    """A wedged holder of the store sidecar degrades the snapshot
    writer loudly after the deadline instead of stalling it forever."""
    import fcntl
    monkeypatch.setattr(fs_lock, "_ACQUIRE_DEADLINE_S", 0.5,
                        raising=False)
    monkeypatch.setattr(fs_lock, "_ACQUIRE_POLL_S", 0.05,
                        raising=False)
    lock = tmp_path / "coverage.json.lock"
    holder_fd = os.open(str(lock), os.O_WRONLY | os.O_CREAT, 0o600)
    entered = threading.Event()

    def writer() -> None:
        with coverage_store_lock(tmp_path / "coverage.json"):
            entered.set()

    thread = threading.Thread(target=writer, daemon=True)
    try:
        fcntl.flock(holder_fd, fcntl.LOCK_EX)
        with caplog.at_level("WARNING"):
            thread.start()
            assert entered.wait(timeout=10), (
                "snapshot writer still blocked on a wedged holder"
            )
        assert any("held by another process" in r.message
                   for r in caplog.records)
        assert any("WITHOUT" in r.message for r in caplog.records)
    finally:
        os.close(holder_fd)
        thread.join(timeout=10)


def test_journal_append_fails_loudly_after_bounded_wait(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
):
    """The appender flocks the shard DATA file; a wedged holder makes
    the append raise (row NOT appended) instead of blocking forever."""
    import fcntl
    monkeypatch.setattr(fs_lock, "_ACQUIRE_DEADLINE_S", 0.5,
                        raising=False)
    monkeypatch.setattr(fs_lock, "_ACQUIRE_POLL_S", 0.05,
                        raising=False)
    append_entry(tmp_path, _entry(0))  # create the shard
    shard = tmp_path / "review-journal.jsonl"
    holder_fd = os.open(str(shard), os.O_WRONLY | os.O_APPEND)
    errors: list[BaseException] = []
    done = threading.Event()

    def appender() -> None:
        try:
            append_entry(tmp_path, _entry(1))
        except OSError as exc:
            errors.append(exc)
        finally:
            done.set()

    thread = threading.Thread(target=appender, daemon=True)
    try:
        fcntl.flock(holder_fd, fcntl.LOCK_EX)
        thread.start()
        assert done.wait(timeout=10), (
            "journal appender still blocked on a wedged holder"
        )
        assert errors, "append neither raised nor was refused"
        assert "row NOT appended" in str(errors[0])
    finally:
        os.close(holder_fd)
        thread.join(timeout=10)


def test_journal_append_expiry_warning_carries_row_loss(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
):
    """The expiry warning (helper-emitted) states the row-loss fact —
    the raise alone can be swallowed by broad best-effort handlers on
    the producer side, turning a lost row silent."""
    monkeypatch.setattr(fs_lock, "_ACQUIRE_DEADLINE_S", 0.5,
                        raising=False)
    monkeypatch.setattr(fs_lock, "_ACQUIRE_POLL_S", 0.05,
                        raising=False)
    import fcntl
    append_entry(tmp_path, _entry(0))  # create the shard
    shard = tmp_path / "review-journal.jsonl"
    holder_fd = os.open(str(shard), os.O_WRONLY | os.O_APPEND)
    try:
        fcntl.flock(holder_fd, fcntl.LOCK_EX)
        with caplog.at_level("WARNING"):
            with pytest.raises(OSError, match="row NOT appended"):
                append_entry(tmp_path, _entry(1))
        assert any(
            "still held after" in r.getMessage()
            and "row NOT appended" in r.getMessage()
            for r in caplog.records
        ), "expiry warning must carry the row-loss consequence"
    finally:
        os.close(holder_fd)
