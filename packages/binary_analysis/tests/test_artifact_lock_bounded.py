"""run_artifacts_lock inherits the shared lock hardening.

The run dir is (or was) inside a sandboxed child's write grant, so
the dir-level ``.binary-artifacts.lock`` is exactly the pre-creatable
sidecar the hoisted idiom defends: a foreign-uid lock file must never
be adopted, and a held lock must be waited on loudly and boundedly.
"""

from __future__ import annotations

import os
import threading
from pathlib import Path

import pytest

import core.atomic_fs.fs_lock as fs_lock
from packages.binary_analysis._artifact_lock import run_artifacts_lock

if not fs_lock._HAS_FCNTL:  # pragma: no cover — non-POSIX
    pytest.skip("fcntl unavailable (non-POSIX)", allow_module_level=True)


def test_foreign_uid_lock_file_degrades_loudly(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
):
    (tmp_path / ".binary-artifacts.lock").write_bytes(b"")
    real_euid = os.geteuid()
    monkeypatch.setattr(os, "geteuid", lambda: real_euid + 1)
    entered = False
    with caplog.at_level("WARNING"):
        with run_artifacts_lock(tmp_path):
            entered = True
    assert entered
    assert any(
        "WITHOUT" in r.message and "uid" in r.getMessage()
        for r in caplog.records
    )


def test_held_lock_never_blocks_appenders_unboundedly(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
):
    """A wedged same-uid holder (hostile or stuck) degrades after the
    deadline instead of parking every artifact append forever."""
    import fcntl
    monkeypatch.setattr(fs_lock, "_ACQUIRE_DEADLINE_S", 0.5,
                        raising=False)
    monkeypatch.setattr(fs_lock, "_ACQUIRE_POLL_S", 0.05,
                        raising=False)
    lock = tmp_path / ".binary-artifacts.lock"
    holder_fd = os.open(str(lock), os.O_WRONLY | os.O_CREAT, 0o600)
    entered = threading.Event()

    def waiter() -> None:
        with run_artifacts_lock(tmp_path):
            entered.set()

    thread = threading.Thread(target=waiter, daemon=True)
    try:
        fcntl.flock(holder_fd, fcntl.LOCK_EX)
        with caplog.at_level("WARNING"):
            thread.start()
            assert entered.wait(timeout=10), (
                "appender still blocked on a wedged holder — "
                "no bounded deadline fired"
            )
        assert any(
            "held by another process" in r.message
            for r in caplog.records
        )
        assert any(
            "still held" in r.message and "WITHOUT" in r.message
            for r in caplog.records
        )
    finally:
        os.close(holder_fd)
        thread.join(timeout=10)
