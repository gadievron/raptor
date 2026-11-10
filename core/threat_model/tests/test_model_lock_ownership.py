"""Direct owned sidecar controls, without model serialization or rendering."""
import errno
import fcntl
import os
from types import SimpleNamespace

import pytest

import core.atomic_fs.fs_lock as locking
import core.threat_model as module


@pytest.fixture
def lock_io(tmp_path, monkeypatch):
    path = tmp_path / "owned.json"
    state = {"path": path, "live": set(), "closes": 0, "acquires": 0,
             "primary": None, "cleanup": None, "stage": None, "refuse": False}
    native_validate = locking.validate_lock_fd
    native_acquire = locking.acquire_flock_bounded

    def opened(*args, **kwargs):
        fd = os.open(*args, **kwargs)
        state["fd"] = fd
        state["live"].add(fd)
        st = os.fstat(fd)
        state["identity"] = st.st_dev, st.st_ino
        return fd

    def validated(fd, path):
        native_validate(fd, path)
        if state["stage"] == "validation":
            raise state["primary"]

    def acquired(*args, **kwargs):
        state["acquires"] += 1
        assert kwargs == {"subject": "threat model", "stamp": True}
        if state["refuse"]:
            return False
        assert native_acquire(*args, **kwargs)
        if state["stage"] == "acquisition":
            raise state["primary"]
        return True

    def close(fd):
        os.close(fd)
        state["live"].remove(fd)
        state["closes"] += 1
        if state["cleanup"] is not None:
            raise state["cleanup"]

    monkeypatch.setattr(module, "os", SimpleNamespace(**{**vars(os), "open": opened, "close": close}))
    monkeypatch.setattr(locking, "validate_lock_fd", validated)
    monkeypatch.setattr(locking, "acquire_flock_bounded", acquired)
    try:
        yield state
    finally:
        for fd in state["live"]:
            st = os.fstat(fd)
            assert (st.st_dev, st.st_ino) == state["identity"]
            os.close(fd)


def _assert_retired(state):
    assert state["closes"] == 1
    assert not state["live"]
    with pytest.raises(OSError) as absent:
        os.fstat(state["fd"])
    assert absent.value.errno == errno.EBADF
    assert not state["path"].exists()
    sidecar = state["path"].with_name("owned.json.lock")
    assert sidecar.is_file()
    fd = os.open(sidecar, os.O_RDWR)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    finally:
        os.close(fd)


def _assert_held(state):
    fd = os.open(state["path"].with_name("owned.json.lock"), os.O_RDWR)
    try:
        with pytest.raises(BlockingIOError):
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    finally:
        os.close(fd)


def test_body_interrupt_survives_secondary_native_close_error(lock_io):
    primary = KeyboardInterrupt("owned lock body interrupted")
    lock_io["cleanup"] = OSError("after native close")
    with pytest.raises(KeyboardInterrupt) as raised:
        with module._model_write_lock(lock_io["path"]):
            _assert_held(lock_io)
            raise primary
    assert raised.value is primary
    _assert_retired(lock_io)


@pytest.mark.parametrize("stage", ["validation", "acquisition", "body"])
@pytest.mark.parametrize("primary_type", [OSError, RuntimeError, SystemExit])
@pytest.mark.parametrize("cleanup_type", [OSError, KeyboardInterrupt])
def test_primary_identity_survives_close_fault(lock_io, stage, primary_type, cleanup_type):
    primary = primary_type("owned operation error")
    lock_io.update(stage=stage, primary=primary, cleanup=cleanup_type("after native close"))
    with pytest.raises(primary_type) as raised:
        with module._model_write_lock(lock_io["path"]):
            assert stage == "body"
            _assert_held(lock_io)
            raise primary
    assert raised.value is primary
    assert lock_io["acquires"] == (stage != "validation")
    _assert_retired(lock_io)


@pytest.mark.parametrize("cleanup_type", [None, OSError, KeyboardInterrupt])
def test_success_retains_fresh_close_policy(lock_io, cleanup_type):
    cleanup = cleanup_type("after native close") if cleanup_type else None
    lock_io["cleanup"] = cleanup

    def run():
        with module._model_write_lock(lock_io["path"]) as value:
            assert value is None
            _assert_held(lock_io)

    if cleanup is None:
        run()
    else:
        with pytest.raises(cleanup_type) as raised:
            run()
        assert raised.value is cleanup
    _assert_retired(lock_io)


@pytest.mark.parametrize("cleanup_type", [OSError, KeyboardInterrupt])
def test_acquisition_refusal_still_prevents_body(lock_io, cleanup_type):
    lock_io.update(refuse=True, cleanup=cleanup_type("after native close"))
    with pytest.raises(OSError, match="refusing to save unserialised"):
        with module._model_write_lock(lock_io["path"]):
            pytest.fail("refused lock yielded")
    _assert_retired(lock_io)
