"""Resolver metadata diagnostics while the owned raw descriptor is still live."""
import os
from types import SimpleNamespace

import pytest

from packages.sca.resolvers import _safe_io as module


@pytest.fixture
def diagnostic_io(tmp_path, monkeypatch):
    path = tmp_path / "plain.txt"
    path.write_bytes(b"plain\n")
    state = {"path": path, "live": set(), "diagnostic": None, "cleanup": None,
             "closes": 0, "warnings": 0, "events": []}
    native_warning = module.logger.warning

    def opened(*args, **kwargs):
        fd = os.open(*args, **kwargs)
        state["fd"] = fd
        state["live"].add(fd)
        return fd

    def fstat(fd):
        os.fstat(fd)
        state["events"].append("metadata")
        raise OSError("injected after native metadata")

    def warning(*args, **kwargs):
        assert state["fd"] in state["live"]
        os.fstat(state["fd"])
        native_warning(*args, **kwargs)
        state["warnings"] += 1
        state["events"].append("warning")
        if state["diagnostic"] is not None:
            raise state["diagnostic"]

    def close(fd):
        os.close(fd)
        state["live"].remove(fd)
        state["closes"] += 1
        state["events"].append("close")
        if state["cleanup"] is not None:
            raise state["cleanup"]

    def no_adoption(*_args, **_kwargs):
        pytest.fail("metadata refusal reached stream adoption")

    monkeypatch.setattr(module, "os", SimpleNamespace(
        **{**vars(os), "open": opened, "fstat": fstat, "close": close, "fdopen": no_adoption}))
    monkeypatch.setattr(module, "logger", SimpleNamespace(warning=warning))
    try:
        yield state
    finally:
        for fd in state["live"]:
            os.close(fd)


def _assert_retired(state):
    assert state["events"] == ["metadata", "warning", "close"]
    assert state["closes"] == state["warnings"] == 1
    assert not state["live"]


def test_warning_interruption_survives_consumed_raw_close(diagnostic_io):
    primary = KeyboardInterrupt("after native warning emission")
    diagnostic_io.update(diagnostic=primary, cleanup=OSError("after native raw close"))
    with pytest.raises(KeyboardInterrupt) as raised:
        module.read_regular_bytes(diagnostic_io["path"], max_bytes=8)
    assert raised.value is primary
    _assert_retired(diagnostic_io)


@pytest.mark.parametrize("diagnostic_type", [RuntimeError, MemoryError, SystemExit])
@pytest.mark.parametrize("close_type", [OSError, KeyboardInterrupt])
def test_active_diagnostic_error_keeps_identity(diagnostic_io, diagnostic_type, close_type):
    primary = diagnostic_type("after native warning emission")
    diagnostic_io.update(diagnostic=primary, cleanup=close_type("after native raw close"))
    with pytest.raises(diagnostic_type) as raised:
        module.read_regular_bytes(diagnostic_io["path"], max_bytes=8)
    assert raised.value is primary
    _assert_retired(diagnostic_io)


def test_distinct_close_interruption_does_not_replace_warning_interruption(diagnostic_io):
    primary = KeyboardInterrupt("warning interruption")
    diagnostic_io.update(diagnostic=primary, cleanup=KeyboardInterrupt("later raw-close interruption"))
    with pytest.raises(KeyboardInterrupt) as raised:
        module.read_regular_bytes(diagnostic_io["path"], max_bytes=8)
    assert raised.value is primary
    _assert_retired(diagnostic_io)


@pytest.mark.parametrize("close_type", [None, OSError, KeyboardInterrupt, SystemExit])
def test_normal_warning_retains_fresh_raw_close_policy(diagnostic_io, close_type):
    cleanup = close_type("after native raw close") if close_type else None
    diagnostic_io["cleanup"] = cleanup
    if cleanup is None:
        assert module.read_regular_bytes(diagnostic_io["path"], max_bytes=8) is None
    else:
        with pytest.raises(close_type) as raised:
            module.read_regular_bytes(diagnostic_io["path"], max_bytes=8)
        assert raised.value is cleanup
    _assert_retired(diagnostic_io)
