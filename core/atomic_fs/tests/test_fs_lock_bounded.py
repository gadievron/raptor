"""Bounded, owner-checked acquisition for core.atomic_fs.fs_lock.

The sidecar lock file lives in directories broader write grants
reach, and cooperating writers queue on it. Two hostile/degenerate
shapes must never stall a writer silently:

- a PRE-EXISTING lock file owned by another uid is never adopted —
  anything that can create the predictable ``.lock`` sibling could
  otherwise hold ``LOCK_EX`` and park every cooperating writer
  behind a successful open (the tamper-degrade arm only fires when
  the open FAILS);
- a held lock is waited on LOUDLY and BOUNDEDLY — one warning naming
  the subject and lock path, then a polled deadline that degrades to
  the unlocked path instead of blocking forever.
"""

from __future__ import annotations

import os
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

import core.atomic_fs.fs_lock as fs_lock
from core.atomic_fs.fs_lock import artifact_lock

if not fs_lock._HAS_FCNTL:  # pragma: no cover — non-POSIX
    pytest.skip("fcntl unavailable (non-POSIX)", allow_module_level=True)


_HOLDER_SCRIPT = """\
import fcntl, os, sys, time
fd = os.open(sys.argv[1], os.O_WRONLY | os.O_CREAT, 0o600)
try:
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
except OSError:
    sys.exit(3)
print("held", flush=True)
time.sleep(float(sys.argv[2]))
"""


def _spawn_holder(
    lock_path: Path, hold_s: float, tmp_path: Path,
) -> subprocess.Popen:
    """Child process that flocks *lock_path* and holds it *hold_s*."""
    script = tmp_path / "holder.py"
    script.write_text(_HOLDER_SCRIPT)
    proc = subprocess.Popen(
        [sys.executable, str(script), str(lock_path), str(hold_s)],
        stdout=subprocess.PIPE, text=True,
    )
    assert proc.stdout is not None
    line = proc.stdout.readline().strip()
    assert line == "held", f"holder failed to take the lock: {line!r}"
    return proc


def _flock_is_free(lock_path: Path) -> bool:
    """True when nothing holds LOCK_EX on *lock_path* right now."""
    import fcntl
    fd = os.open(str(lock_path), os.O_WRONLY | os.O_CREAT, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            return False
        fcntl.flock(fd, fcntl.LOCK_UN)
        return True
    finally:
        os.close(fd)


class TestForeignUidRefusal:

    def test_foreign_uid_lock_file_is_not_adopted(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ):
        """A pre-existing lock file owned by another uid degrades to
        the loud unlocked path — the flock is never taken on it."""
        artifact = tmp_path / "store.json"
        lock = tmp_path / "store.json.lock"
        lock.write_bytes(b"")
        # Simulate the foreign owner: the file's real uid is ours, so
        # shift what the checker believes OUR euid is.
        real_euid = os.geteuid()
        monkeypatch.setattr(os, "geteuid", lambda: real_euid + 1)
        entered = False
        with caplog.at_level("WARNING"):
            with artifact_lock(artifact):
                entered = True
                # Degraded path: the foreign file must NOT be flocked.
                assert _flock_is_free(lock), (
                    "foreign-uid lock file was adopted and flocked"
                )
        assert entered
        assert any(
            "WITHOUT" in r.message and "uid" in r.getMessage()
            for r in caplog.records
        )

    def test_own_uid_lock_file_is_adopted_silently(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture,
    ):
        """A pre-existing same-uid lock file stays the normal path."""
        artifact = tmp_path / "store.json"
        (tmp_path / "store.json.lock").write_bytes(b"")
        with caplog.at_level("WARNING"):
            with artifact_lock(artifact):
                pass
        assert not caplog.records

    def test_validate_lock_fd_raises_on_foreign_uid(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ):
        lock = tmp_path / "x.lock"
        lock.write_bytes(b"")
        real_euid = os.geteuid()
        monkeypatch.setattr(os, "geteuid", lambda: real_euid + 1)
        fd = os.open(str(lock), os.O_WRONLY)
        try:
            with pytest.raises(OSError, match="foreign lock file"):
                fs_lock.validate_lock_fd(fd, lock)
        finally:
            os.close(fd)


class TestBoundedAcquisition:

    def test_contention_warns_once_then_acquires(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ):
        """A briefly-held lock produces exactly ONE 'waiting' warning,
        then the waiter acquires — never a silent block."""
        monkeypatch.setattr(fs_lock, "_ACQUIRE_POLL_S", 0.05,
                            raising=False)
        artifact = tmp_path / "store.json"
        lock = tmp_path / "store.json.lock"
        holder = _spawn_holder(lock, 1.0, tmp_path)
        try:
            entered = False
            with caplog.at_level("WARNING"):
                with artifact_lock(artifact):
                    entered = True
            assert entered
            waiting = [
                r for r in caplog.records
                if "held by another process" in r.message
            ]
            assert len(waiting) == 1, (
                "contended acquire must announce the wait exactly once"
            )
            record = waiting[0]
            assert str(lock) in record.getMessage()
            # The holder released within the deadline: acquired, so no
            # degrade fired.
            assert not any("WITHOUT" in r.message for r in caplog.records)
        finally:
            holder.wait(timeout=10)

    def test_wedged_holder_never_blocks_unboundedly(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ):
        """Deadline expiry against a wedged holder degrades LOUDLY to
        the unlocked path instead of stalling the writer forever."""
        monkeypatch.setattr(fs_lock, "_ACQUIRE_DEADLINE_S", 0.5,
                            raising=False)
        monkeypatch.setattr(fs_lock, "_ACQUIRE_POLL_S", 0.05,
                            raising=False)
        artifact = tmp_path / "store.json"
        lock = tmp_path / "store.json.lock"
        # A parseable stale stamp: the wait diagnostic must echo it.
        lock.write_bytes(b"99999\n")
        holder = _spawn_holder(lock, 30.0, tmp_path)
        entered = threading.Event()

        def waiter() -> None:
            with artifact_lock(artifact):
                entered.set()

        thread = threading.Thread(target=waiter, daemon=True)
        try:
            with caplog.at_level("WARNING"):
                start = time.monotonic()
                thread.start()
                assert entered.wait(timeout=10), (
                    "writer still blocked on a wedged holder — "
                    "no bounded deadline fired"
                )
                elapsed = time.monotonic() - start
            assert elapsed < 10
            waiting = [
                r for r in caplog.records
                if "held by another process" in r.message
            ]
            assert len(waiting) == 1
            assert "99999" in waiting[0].getMessage()
            assert any(
                "still held" in r.message and "WITHOUT" in r.message
                for r in caplog.records
            )
        finally:
            holder.kill()
            holder.wait(timeout=10)
            thread.join(timeout=10)

    def test_holder_pid_is_stamped_into_lock_file(self, tmp_path: Path):
        """The acquirer records its pid (advisory, possibly stale)."""
        artifact = tmp_path / "store.json"
        with artifact_lock(artifact):
            pass
        content = (tmp_path / "store.json.lock").read_text()
        assert content == f"{os.getpid()}\n"

    def test_hostile_stamp_content_is_never_echoed(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ):
        """Non-integer lock-file bytes (attacker-writable) never reach
        the log — the hint is a strict pid parse."""
        monkeypatch.setattr(fs_lock, "_ACQUIRE_DEADLINE_S", 0.3,
                            raising=False)
        monkeypatch.setattr(fs_lock, "_ACQUIRE_POLL_S", 0.05,
                            raising=False)
        artifact = tmp_path / "store.json"
        lock = tmp_path / "store.json.lock"
        lock.write_bytes(b"\x1b]0;pwned\x07 not-a-pid")
        holder = _spawn_holder(lock, 30.0, tmp_path)
        entered = threading.Event()

        def waiter() -> None:
            with artifact_lock(artifact):
                entered.set()

        thread = threading.Thread(target=waiter, daemon=True)
        try:
            with caplog.at_level("WARNING"):
                thread.start()
                assert entered.wait(timeout=10)
            assert not any(
                "pwned" in r.getMessage() for r in caplog.records
            )
        finally:
            holder.kill()
            holder.wait(timeout=10)
            thread.join(timeout=10)


class TestLimits:

    def test_wait_limits_pinned(self):
        """Regression pin for the bounded-wait constants — the inline
        rationale in fs_lock.py argues both directions; a change there
        must consciously update this pin with it."""
        assert fs_lock._ACQUIRE_DEADLINE_S == 60.0
        assert fs_lock._ACQUIRE_POLL_S == 0.1
