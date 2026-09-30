"""_metadata_lock: foreign-uid refusal and bounded waiting.

The `.lock` sibling lives inside the sandbox child's write grant (the
metadata FILE is masked; the sibling is not), so a pre-created
foreign-uid lock file must degrade to the loud UNSERIALISED path —
never be adopted — and a held lock must never stall a lifecycle
finaliser silently or unboundedly.
"""

from __future__ import annotations

import os
import threading
from pathlib import Path

import pytest

import core.atomic_fs.fs_lock as fs_lock
from core.run.metadata import _HAS_FCNTL, _metadata_lock

if not _HAS_FCNTL:  # pragma: no cover — non-POSIX
    pytest.skip("fcntl unavailable (non-POSIX)", allow_module_level=True)


def test_foreign_uid_lock_sibling_degrades_unserialised(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
):
    meta = tmp_path / ".raptor-run.json"
    (tmp_path / ".raptor-run.json.lock").write_bytes(b"")
    real_euid = os.geteuid()
    monkeypatch.setattr(os, "geteuid", lambda: real_euid + 1)
    entered = False
    with caplog.at_level("WARNING"):
        with _metadata_lock(meta):
            entered = True
    assert entered
    assert any(
        "UNSERIALISED" in r.message and "uid" in r.getMessage()
        for r in caplog.records
    )


def test_wedged_holder_never_blocks_finalisers_unboundedly(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
):
    import fcntl
    monkeypatch.setattr(fs_lock, "_ACQUIRE_DEADLINE_S", 0.5,
                        raising=False)
    monkeypatch.setattr(fs_lock, "_ACQUIRE_POLL_S", 0.05,
                        raising=False)
    meta = tmp_path / ".raptor-run.json"
    lock = tmp_path / ".raptor-run.json.lock"
    holder_fd = os.open(str(lock), os.O_WRONLY | os.O_CREAT, 0o600)
    entered = threading.Event()

    def finaliser() -> None:
        with _metadata_lock(meta):
            entered.set()

    thread = threading.Thread(target=finaliser, daemon=True)
    try:
        fcntl.flock(holder_fd, fcntl.LOCK_EX)
        with caplog.at_level("WARNING"):
            thread.start()
            assert entered.wait(timeout=10), (
                "lifecycle finaliser still blocked on a wedged holder "
                "— no bounded deadline fired"
            )
        assert any(
            "held by another process" in r.message
            for r in caplog.records
        )
        assert any(
            "UNSERIALISED" in r.getMessage() for r in caplog.records
        )
    finally:
        os.close(holder_fd)
        thread.join(timeout=10)
