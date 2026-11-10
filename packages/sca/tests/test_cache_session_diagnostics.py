"""Session teardown diagnostics after a real owned lease; maintenance never runs."""
import fcntl
import os
from types import SimpleNamespace

import pytest

from packages.sca import cache_budget as module


@pytest.fixture
def session_io(tmp_path, monkeypatch):
    root = tmp_path / "owned-cache"
    state = {"root": root, "live": set(), "closes": 0, "maintenance": 0,
             "warnings": 0, "secondary": None, "diagnostic": None, "events": []}
    native_warning = module.logger.warning

    def opened(*args, **kwargs):
        fd = os.open(*args, **kwargs)
        state["live"].add(fd)
        state["fd"] = fd
        state["events"].append("open")
        return fd

    def close(fd):
        os.close(fd)
        state["live"].remove(fd)
        state["closes"] += 1
        state["events"].append("close")

    def maintenance(path):
        assert path == root
        assert not state["live"]
        with pytest.raises(OSError):
            os.fstat(state["fd"])
        _assert_available(state)
        state["maintenance"] += 1
        state["events"].append("maintenance")
        if state["secondary"] is not None:
            raise state["secondary"]

    def warning(*args, **kwargs):
        native_warning(*args, **kwargs)
        state["warnings"] += 1
        state["events"].append("warning")
        if state["diagnostic"] is not None:
            raise state["diagnostic"]

    monkeypatch.setattr(module, "os", SimpleNamespace(**{**vars(os), "open": opened, "close": close}))
    monkeypatch.setattr(module, "maintain_cache", maintenance)
    monkeypatch.setattr(module, "logger", SimpleNamespace(warning=warning))
    try:
        yield state
    finally:
        for fd in state["live"]:
            os.close(fd)


def _assert_available(state):
    fd = os.open(state["root"] / module._LOCK, os.O_WRONLY)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    finally:
        os.close(fd)


def _assert_held(state):
    fd = os.open(state["root"] / module._LOCK, os.O_WRONLY)
    try:
        with pytest.raises(BlockingIOError):
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    finally:
        os.close(fd)


def _assert_retired(state):
    assert state["closes"] == 1
    assert not state["live"]
    _assert_available(state)


def test_secondary_warning_failure_keeps_scan_interruption(session_io):
    primary = KeyboardInterrupt("inside native shared lease")
    session_io.update(secondary=OSError("maintenance callback refused"),
                      diagnostic=MemoryError("after native warning emission"))
    with pytest.raises(KeyboardInterrupt) as raised:
        with module.cache_session(session_io["root"]):
            _assert_held(session_io)
            raise primary
    assert raised.value is primary
    assert session_io["events"] == ["open", "close", "maintenance", "warning"]
    _assert_retired(session_io)


@pytest.mark.parametrize("primary_type", [RuntimeError, MemoryError, SystemExit])
@pytest.mark.parametrize("secondary_type", [OSError, SystemExit])
@pytest.mark.parametrize("diagnostic_type", [OSError, MemoryError, KeyboardInterrupt])
def test_secondary_diagnostic_never_replaces_active_scan_error(
        session_io, primary_type, secondary_type, diagnostic_type):
    primary = primary_type("inside native shared lease")
    session_io.update(secondary=secondary_type("maintenance callback failed"),
                      diagnostic=diagnostic_type("after native warning emission"))
    with pytest.raises(primary_type) as raised:
        with module.cache_session(session_io["root"]):
            _assert_held(session_io)
            raise primary
    assert raised.value is primary
    assert session_io["maintenance"] == session_io["warnings"] == 1
    assert session_io["events"] == ["open", "close", "maintenance", "warning"]
    _assert_retired(session_io)


@pytest.mark.parametrize("primary_type", [RuntimeError, KeyboardInterrupt])
def test_normal_secondary_warning_still_emits(session_io, primary_type):
    primary = primary_type("inside native shared lease")
    session_io["secondary"] = OSError("maintenance callback failed")
    with pytest.raises(primary_type) as raised:
        with module.cache_session(session_io["root"]):
            raise primary
    assert raised.value is primary
    assert session_io["warnings"] == 1
    _assert_retired(session_io)


@pytest.mark.parametrize("secondary_type", [OSError, KeyboardInterrupt, SystemExit, MemoryError])
def test_fresh_maintenance_failure_stays_visible(session_io, secondary_type):
    secondary = secondary_type("maintenance callback failed")
    session_io.update(secondary=secondary, diagnostic=MemoryError("must not reach warning"))
    with pytest.raises(secondary_type) as raised:
        with module.cache_session(session_io["root"]):
            _assert_held(session_io)
    assert raised.value is secondary
    assert session_io["maintenance"] == 1
    assert session_io["warnings"] == 0
    _assert_retired(session_io)


@pytest.mark.parametrize("body_fails", [False, True])
def test_maintenance_disabled_skips_callbacks(session_io, body_fails):
    primary = KeyboardInterrupt("inside native shared lease") if body_fails else None
    session_io.update(secondary=OSError("must not maintain"), diagnostic=MemoryError("must not warn"))

    def run():
        with module.cache_session(session_io["root"], maintain=False):
            _assert_held(session_io)
            if primary is not None:
                raise primary

    if primary is not None:
        with pytest.raises(KeyboardInterrupt) as raised:
            run()
        assert raised.value is primary
    else:
        run()
    assert session_io["maintenance"] == session_io["warnings"] == 0
    assert session_io["events"] == ["open", "close"]
    _assert_retired(session_io)


def test_healthy_session_retires_before_noop_callback(session_io):
    with module.cache_session(session_io["root"]) as value:
        assert value is None
        _assert_held(session_io)
    assert session_io["maintenance"] == 1
    assert session_io["warnings"] == 0
    assert session_io["events"] == ["open", "close", "maintenance"]
    _assert_retired(session_io)


@pytest.mark.parametrize("primary_type", [RuntimeError, KeyboardInterrupt])
def test_body_error_survives_healthy_noop_callback(session_io, primary_type):
    primary = primary_type("inside native shared lease")
    with pytest.raises(primary_type) as raised:
        with module.cache_session(session_io["root"]):
            raise primary
    assert raised.value is primary
    assert session_io["maintenance"] == 1
    assert session_io["warnings"] == 0
    _assert_retired(session_io)
