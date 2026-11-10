"""Private sidecar lock cleanup with native flock; no cache maintenance."""
import fcntl
import os
from types import SimpleNamespace

import pytest

from packages.sca import cache_budget as module


@pytest.fixture
def lock_io(tmp_path, monkeypatch):
    root = tmp_path / "owned-cache"
    root.mkdir()
    state = {"root": root, "path": root / module._LOCK, "primary": None,
             "cleanup": None, "live": set(), "closes": 0}
    native_validate = module.validate_lock_fd

    def opened(*args, **kwargs):
        fd = os.open(*args, **kwargs)
        state["live"].add(fd)
        state["fd"] = fd
        return fd

    def validated(fd, path):
        native_validate(fd, path)
        if state["primary"] is not None:
            raise state["primary"]

    def close(fd):
        os.close(fd)
        state["live"].remove(fd)
        state["closes"] += 1
        if state["cleanup"] is not None:
            raise state["cleanup"]

    monkeypatch.setattr(module, "os", SimpleNamespace(**{**vars(os), "open": opened, "close": close}))
    monkeypatch.setattr(module, "validate_lock_fd", validated)
    try:
        yield state
    finally:
        for fd in state["live"]:
            os.close(fd)


def _assert_held(state):
    independent = os.open(state["path"], os.O_WRONLY)
    try:
        with pytest.raises(BlockingIOError):
            fcntl.flock(independent, fcntl.LOCK_EX | fcntl.LOCK_NB)
    finally:
        os.close(independent)


def _assert_retired(state):
    assert state["closes"] == 1
    assert not state["live"]
    with pytest.raises(OSError):
        os.fstat(state["fd"])


def _assert_available(state):
    independent = os.open(state["path"], os.O_WRONLY)
    try:
        fcntl.flock(independent, fcntl.LOCK_EX | fcntl.LOCK_NB)
    finally:
        os.close(independent)


def test_body_interruption_survives_consumed_lock_close(lock_io):
    primary = KeyboardInterrupt("inside native held lock")
    lock_io["cleanup"] = OSError("after native lock close")
    with pytest.raises(KeyboardInterrupt) as raised:
        with module._lock(lock_io["root"]) as locked:
            assert locked is True
            _assert_held(lock_io)
            raise primary
    assert raised.value is primary
    _assert_retired(lock_io)
    _assert_available(lock_io)


@pytest.mark.parametrize("shared", [False, True])
@pytest.mark.parametrize("primary_type", [MemoryError, SystemExit])
@pytest.mark.parametrize("close_type", [OSError, KeyboardInterrupt])
def test_held_body_error_keeps_identity(lock_io, shared, primary_type, close_type):
    primary = primary_type("inside native held lock")
    lock_io["cleanup"] = close_type("after native close")
    with pytest.raises(primary_type) as raised:
        with module._lock(lock_io["root"], shared=shared) as locked:
            assert locked is True
            _assert_held(lock_io)
            raise primary
    assert raised.value is primary
    _assert_retired(lock_io)
    _assert_available(lock_io)


@pytest.mark.parametrize("primary_type", [RuntimeError, MemoryError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("close_type", [OSError, KeyboardInterrupt])
def test_validation_error_keeps_identity(lock_io, primary_type, close_type):
    primary = primary_type("after native lock metadata validation")
    lock_io.update(primary=primary, cleanup=close_type("after native close"))
    with pytest.raises(primary_type) as raised:
        with module._lock(lock_io["root"]):
            pytest.fail("failed validation yielded a lock")
    assert raised.value is primary
    _assert_retired(lock_io)
    _assert_available(lock_io)


@pytest.mark.parametrize("source", ["unavailable", "busy"])
@pytest.mark.parametrize("body_fails", [False, True])
@pytest.mark.parametrize("close_type", [None, OSError, KeyboardInterrupt])
def test_false_yield_retains_body_and_fresh_close_policy(lock_io, source, body_fails, close_type):
    holder = None
    if source == "unavailable":
        lock_io["primary"] = OSError("injected after native validation")
    else:
        holder = os.open(lock_io["path"], os.O_CREAT | os.O_WRONLY, 0o600)
        fcntl.flock(holder, fcntl.LOCK_EX | fcntl.LOCK_NB)
    body_error = KeyboardInterrupt("inside false-yield context") if body_fails else None
    cleanup = close_type("after native close") if close_type else None
    lock_io["cleanup"] = cleanup

    def run():
        with module._lock(lock_io["root"]) as locked:
            assert locked is False
            if body_error is not None:
                raise body_error

    try:
        expected = body_error if body_error is not None else cleanup
        if expected is None:
            run()
        else:
            with pytest.raises(type(expected)) as raised:
                run()
            assert raised.value is expected
        _assert_retired(lock_io)
    finally:
        if holder is not None:
            os.close(holder)
    _assert_available(lock_io)


@pytest.mark.parametrize("shared", [False, True])
@pytest.mark.parametrize("close_type", [None, OSError, KeyboardInterrupt])
def test_healthy_native_lock_retains_fresh_close_policy(lock_io, shared, close_type):
    cleanup = close_type("after native close") if close_type else None
    lock_io["cleanup"] = cleanup

    def run():
        with module._lock(lock_io["root"], shared=shared) as locked:
            assert locked is True
            _assert_held(lock_io)

    if cleanup is None:
        run()
    else:
        with pytest.raises(close_type) as raised:
            run()
        assert raised.value is cleanup
    _assert_retired(lock_io)
    _assert_available(lock_io)
