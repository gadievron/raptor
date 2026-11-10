"""Direct owned metadata-sidecar setup; no metadata update/finalizer actions."""
import fcntl
import importlib
import os
from types import SimpleNamespace

import pytest

from core.run import metadata as module


@pytest.fixture
def lock_io(tmp_path, monkeypatch):
    path = tmp_path / "owned.json"
    state = {"path": path, "live": set(), "closes": 0, "primary": None,
             "cleanup": None, "acquires": 0, "warnings": 0}
    locking = importlib.import_module("core.atomic_fs.fs_lock")
    native_validate = locking.validate_lock_fd
    native_acquire = locking.acquire_flock_bounded
    native_warning = module.logger.warning

    def opened(*args, **kwargs):
        fd = os.open(*args, **kwargs)
        state["fd"] = fd
        state["live"].add(fd)
        st = os.fstat(fd)
        state["identity"] = st.st_dev, st.st_ino
        return fd

    def validated(fd, path):
        native_validate(fd, path)
        if state["primary"] is not None:
            raise state["primary"]

    def acquired(*args, **kwargs):
        state["acquires"] += 1
        return native_acquire(*args, **kwargs)

    def close(fd):
        os.close(fd)
        state["live"].remove(fd)
        state["closes"] += 1
        if state["cleanup"] is not None:
            raise state["cleanup"]

    def warning(*args, **kwargs):
        state["warnings"] += 1
        native_warning(*args, **kwargs)

    monkeypatch.setattr(module, "os", SimpleNamespace(**{**vars(os), "open": opened, "close": close}))
    monkeypatch.setattr(module, "logger", SimpleNamespace(warning=warning))
    monkeypatch.setattr(locking, "validate_lock_fd", validated)
    monkeypatch.setattr(locking, "acquire_flock_bounded", acquired)
    try:
        yield state
    finally:
        for fd in state["live"]:
            st = os.fstat(fd)
            assert (st.st_dev, st.st_ino) == state["identity"]
            os.close(fd)


def test_interrupted_validation_retires_owned_sidecar(lock_io):
    primary = KeyboardInterrupt("after native sidecar validation")
    lock_io["primary"] = primary
    with pytest.raises(KeyboardInterrupt) as raised:
        with module._metadata_lock(lock_io["path"]):
            pytest.fail("interrupted validation yielded")
    assert raised.value is primary
    live_native = [fd for fd in lock_io["live"] if os.fstat(fd)]
    assert live_native == []
    assert lock_io["closes"] == 1
    assert lock_io["acquires"] == lock_io["warnings"] == 0


def _assert_retired(state):
    assert state["closes"] == 1
    assert not state["live"]
    with pytest.raises(OSError):
        os.fstat(state["fd"])
    assert not state["path"].exists()


@pytest.mark.parametrize("primary_type", [RuntimeError, MemoryError, SystemExit])
@pytest.mark.parametrize("close_type", [None, OSError, KeyboardInterrupt])
def test_unexpected_validation_error_keeps_identity_and_closes(lock_io, primary_type, close_type):
    primary = primary_type("after native sidecar validation")
    lock_io.update(primary=primary, cleanup=close_type("after native close") if close_type else None)
    with pytest.raises(primary_type) as raised:
        with module._metadata_lock(lock_io["path"]):
            pytest.fail("failed validation yielded")
    assert raised.value is primary
    assert lock_io["acquires"] == lock_io["warnings"] == 0
    _assert_retired(lock_io)


@pytest.mark.parametrize("close_type", [None, OSError, KeyboardInterrupt])
def test_handled_metadata_io_keeps_unserialized_and_close_policy(lock_io, close_type):
    cleanup = close_type("after native close") if close_type else None
    lock_io.update(primary=OSError("after native validation"), cleanup=cleanup)
    entered = []

    def run():
        with module._metadata_lock(lock_io["path"]):
            entered.append(True)
            assert not lock_io["live"]

    if close_type is KeyboardInterrupt:
        with pytest.raises(KeyboardInterrupt) as raised:
            run()
        assert raised.value is cleanup
        assert entered == []
        assert lock_io["warnings"] == 0
    else:
        run()
        assert entered == [True]
        assert lock_io["warnings"] == 1
    assert lock_io["acquires"] == 0
    _assert_retired(lock_io)


def _assert_held(state):
    fd = os.open(state["path"].with_suffix(".json.lock"), os.O_WRONLY)
    try:
        with pytest.raises(BlockingIOError):
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    finally:
        os.close(fd)


@pytest.mark.parametrize("close_type", [None, OSError, KeyboardInterrupt])
def test_healthy_native_acquisition_retains_fresh_close_policy(lock_io, close_type):
    cleanup = close_type("after native close") if close_type else None
    lock_io["cleanup"] = cleanup

    def run():
        with module._metadata_lock(lock_io["path"]) as value:
            assert value is None
            _assert_held(lock_io)

    if cleanup is None:
        run()
    else:
        with pytest.raises(close_type) as raised:
            run()
        assert raised.value is cleanup
    assert lock_io["acquires"] == 1
    assert lock_io["warnings"] == 0
    _assert_retired(lock_io)


def test_body_interruption_with_healthy_close_releases_native_lease(lock_io):
    primary = KeyboardInterrupt("inside owned native sidecar lock")
    with pytest.raises(KeyboardInterrupt) as raised:
        with module._metadata_lock(lock_io["path"]):
            _assert_held(lock_io)
            raise primary
    assert raised.value is primary
    assert lock_io["acquires"] == 1
    assert lock_io["warnings"] == 0
    _assert_retired(lock_io)
