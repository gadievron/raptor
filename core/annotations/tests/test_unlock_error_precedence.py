"""Native read-only annotation sidecar unlock, without annotation writes."""
import errno
import os
from types import SimpleNamespace

import pytest

import core.atomic_fs.fs_lock as locking
from core.annotations import storage
from core.annotations.tests import test_lock_fd_ownership as ownership

lock_io = ownership.lock_io


@pytest.fixture
def unlock_io(lock_io, monkeypatch):
    native = storage.fcntl
    acquire = locking.acquire_flock_bounded
    lock_io.update(unlocks=0, unlock_error=None, acquires=0, native_fcntl=native)
    lock_io["lock"].write_bytes(b"")
    lock_io["lock"].chmod(0o400)

    def acquired(*args, **kwargs):
        assert kwargs == {"subject": "annotation store"}
        lock_io["acquires"] += 1
        return acquire(*args, **kwargs)

    def unlocked(fd, operation):
        assert fd == lock_io["fd"] and operation == native.LOCK_UN
        native.flock(fd, operation)
        lock_io["unlocks"] += 1
        if lock_io["unlock_error"] is not None:
            raise lock_io["unlock_error"]

    def forbidden(*args, **kwargs):
        pytest.fail("annotation rendezvous must not add UID validation or holder stamping")

    monkeypatch.setattr(locking, "acquire_flock_bounded", acquired)
    monkeypatch.setattr(locking, "validate_lock_fd", forbidden)
    monkeypatch.setattr(locking, "stamp_lock_holder", forbidden)
    monkeypatch.setattr(storage, "fcntl", SimpleNamespace(**{**vars(native), "flock": unlocked}))
    return lock_io


def _assert_held(state):
    assert state["flags"] & os.O_ACCMODE == os.O_RDONLY
    assert state["mode"] == 0o666
    fd = os.open(state["lock"], os.O_RDONLY)
    flags = state["native_fcntl"]
    try:
        with pytest.raises(OSError) as held:
            flags.flock(fd, flags.LOCK_EX | flags.LOCK_NB)
        assert held.value.errno in (errno.EACCES, errno.EAGAIN)
    finally:
        os.close(fd)


def _assert_released(state):
    ownership.assert_retired(state)
    assert state["acquires"] == state["unlocks"] == 1
    flags = state["native_fcntl"]
    fd = os.open(state["lock"], os.O_RDONLY)
    try:
        flags.flock(fd, flags.LOCK_EX | flags.LOCK_NB)
        flags.flock(fd, flags.LOCK_UN)
    finally:
        os.close(fd)
    assert state["lock"].read_bytes() == b""
    assert not state["path"].exists()


def test_unlock_fault_cannot_replace_body_interrupt(unlock_io):
    primary = KeyboardInterrupt("owned annotation body interrupted")
    unlock_io.update(unlock_error=OSError("after native unlock"), close_error=OSError("after native close"))
    with pytest.raises(KeyboardInterrupt) as raised:
        with storage._file_lock(unlock_io["path"]):
            _assert_held(unlock_io)
            raise primary
    assert raised.value is primary
    _assert_released(unlock_io)


@pytest.mark.parametrize("primary_type", [RuntimeError, MemoryError, SystemExit])
@pytest.mark.parametrize("unlock_type", [OSError, KeyboardInterrupt])
@pytest.mark.parametrize("close_type", [None, OSError])
def test_body_primary_identity_survives_unlock_and_close(unlock_io, primary_type, unlock_type, close_type):
    primary = primary_type("owned annotation body failed")
    unlock_io.update(unlock_error=unlock_type("after native unlock"),
                     close_error=close_type("after native close") if close_type else None)
    with pytest.raises(primary_type) as raised:
        with storage._file_lock(unlock_io["path"]):
            _assert_held(unlock_io)
            raise primary
    assert raised.value is primary
    _assert_released(unlock_io)


@pytest.mark.parametrize("unlock_type", [OSError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("close_type", [None, OSError, MemoryError])
def test_fresh_unlock_failure_keeps_precedence_over_close(unlock_io, unlock_type, close_type):
    primary = unlock_type("after native unlock")
    unlock_io.update(unlock_error=primary, close_error=close_type("after native close") if close_type else None)
    with pytest.raises(unlock_type) as raised:
        with storage._file_lock(unlock_io["path"]):
            _assert_held(unlock_io)
    assert raised.value is primary
    _assert_released(unlock_io)
