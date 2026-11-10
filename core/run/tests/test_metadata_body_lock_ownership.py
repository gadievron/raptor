"""Direct metadata sidecar teardown; no status or finalizer operations."""
import fcntl
from types import SimpleNamespace

import pytest

import core.atomic_fs.fs_lock as locking
from core.run import metadata as module
from core.run.tests import test_metadata_lock_ownership as ownership

lock_io = ownership.lock_io
_assert_held = ownership._assert_held
_assert_retired = ownership._assert_retired


@pytest.fixture
def teardown_io(lock_io, monkeypatch):
    lock_io.update(unlocks=0, unlock_error=None, acquire_error=None, refuse=False)
    native_acquire = locking.acquire_flock_bounded

    def acquire(*args, **kwargs):
        if lock_io["acquire_error"] is not None:
            raise lock_io["acquire_error"]
        if lock_io["refuse"]:
            return False
        return native_acquire(*args, **kwargs)

    def flock(fd, operation):
        assert operation == fcntl.LOCK_UN
        fcntl.flock(fd, operation)
        lock_io["unlocks"] += 1
        if lock_io["unlock_error"] is not None:
            raise lock_io["unlock_error"]

    monkeypatch.setattr(locking, "acquire_flock_bounded", acquire)
    monkeypatch.setattr(module, "fcntl", SimpleNamespace(**{**vars(fcntl), "flock": flock}))
    return lock_io


def test_body_interrupt_survives_unlock_and_close_faults(teardown_io):
    primary = KeyboardInterrupt("owned metadata body interrupted")
    teardown_io.update(unlock_error=MemoryError("after native unlock"), cleanup=OSError("after native close"))
    with pytest.raises(KeyboardInterrupt) as raised:
        with module._metadata_lock(teardown_io["path"]):
            _assert_held(teardown_io)
            raise primary
    assert raised.value is primary
    assert teardown_io["unlocks"] == 1
    _assert_retired(teardown_io)


@pytest.mark.parametrize("primary_type", [OSError, RuntimeError, SystemExit])
@pytest.mark.parametrize("unlock_type", [None, OSError, KeyboardInterrupt])
@pytest.mark.parametrize("close_type", [None, OSError])
def test_held_body_primary_keeps_identity(teardown_io, primary_type, unlock_type, close_type):
    primary = primary_type("owned metadata body failed")
    teardown_io.update(unlock_error=unlock_type("after native unlock") if unlock_type else None,
                       cleanup=close_type("after native close") if close_type else None)
    with pytest.raises(primary_type) as raised:
        with module._metadata_lock(teardown_io["path"]):
            _assert_held(teardown_io)
            raise primary
    assert raised.value is primary
    assert teardown_io["unlocks"] == 1
    _assert_retired(teardown_io)


@pytest.mark.parametrize("stage", ["acquisition", "unserialized"])
@pytest.mark.parametrize("close_type", [OSError, KeyboardInterrupt])
def test_nonheld_operation_errors_keep_identity(teardown_io, stage, close_type):
    primary = RuntimeError("owned metadata operation failed")
    teardown_io.update(refuse=stage == "unserialized", acquire_error=primary if stage == "acquisition" else None,
                       cleanup=close_type("after native close"))
    with pytest.raises(RuntimeError) as raised:
        with module._metadata_lock(teardown_io["path"]):
            assert stage == "unserialized"
            raise primary
    assert raised.value is primary
    assert teardown_io["unlocks"] == 0
    _assert_retired(teardown_io)


@pytest.mark.parametrize("unlock_type", [None, OSError, KeyboardInterrupt])
@pytest.mark.parametrize("close_type", [None, OSError, SystemExit])
def test_success_preserves_fresh_cleanup_order(teardown_io, unlock_type, close_type):
    unlock_error = unlock_type("after native unlock") if unlock_type else None
    close_error = close_type("after native close") if close_type else None
    teardown_io.update(unlock_error=unlock_error, cleanup=close_error)
    expected = close_error if close_error is not None else unlock_error

    def run():
        with module._metadata_lock(teardown_io["path"]):
            _assert_held(teardown_io)

    if expected is None:
        run()
    else:
        with pytest.raises(type(expected)) as raised:
            run()
        assert raised.value is expected
    assert teardown_io["unlocks"] == 1
    _assert_retired(teardown_io)
