"""Passive owned capture-file cleanup; no child or sandbox execution."""
import os
from types import SimpleNamespace

import pytest

from core.audit.dark_verify import _execute as module


@pytest.fixture
def capture_io(tmp_path, monkeypatch):
    path = tmp_path / "owned-capture.txt"
    payload = b"head--plain--tail\n"
    path.write_bytes(payload)
    state = {"path": path, "payload": payload, "site": "metadata", "primary": None,
             "cleanup": None, "closes": 0, "stream": None, "fd": None}
    native_open = module._open_untrusted_regular

    class Reader:
        def __init__(self, native):
            self.native = native

        def __getattr__(self, name):
            return getattr(self.native, name)

        def read(self, size):
            result = self.native.read(size)
            if state["site"] == "read" and state["primary"] is not None:
                raise state["primary"]
            return result

        def close(self):
            self.native.close()
            state["closes"] += 1
            if state["cleanup"] is not None:
                raise state["cleanup"]

    def opened(path):
        native = native_open(path)
        assert native is not None
        state["stream"] = native
        state["fd"] = native.fileno()
        return Reader(native)

    def fstat(fd):
        result = os.fstat(fd)
        if fd == state["fd"] and state["site"] == "metadata" and state["primary"] is not None:
            raise state["primary"]
        return result

    monkeypatch.setattr(module, "_open_untrusted_regular", opened)
    monkeypatch.setattr(module, "_CAPTURE_CAP_BYTES", 4)
    monkeypatch.setattr(module, "os", SimpleNamespace(**{**vars(os), "fstat": fstat}))
    try:
        yield state
    finally:
        if state["stream"] is not None:
            state["stream"].close()


def _assert_retired(state):
    assert state["closes"] == 1
    assert state["stream"].closed
    with pytest.raises(OSError):
        os.fstat(state["fd"])


def test_metadata_primary_survives_consumed_capture_close(capture_io):
    primary = KeyboardInterrupt("after native capture metadata")
    capture_io.update(primary=primary, cleanup=OSError("after native close"))
    with pytest.raises(KeyboardInterrupt) as raised:
        module._read_capped(capture_io["path"], keep_tail=True)
    assert raised.value is primary
    _assert_retired(capture_io)


@pytest.mark.parametrize("site", ["metadata", "read"])
@pytest.mark.parametrize("primary_type", [MemoryError, SystemExit])
@pytest.mark.parametrize("close_type", [OSError, KeyboardInterrupt])
def test_active_reader_error_keeps_identity(capture_io, site, primary_type, close_type):
    primary = primary_type("after native reader operation")
    capture_io.update(site=site, primary=primary, cleanup=close_type("after native close"))
    with pytest.raises(primary_type) as raised:
        module._read_capped(capture_io["path"], keep_tail=True)
    assert raised.value is primary
    _assert_retired(capture_io)


@pytest.mark.parametrize("site", ["metadata", "read"])
def test_handled_reader_io_still_returns_empty_result(capture_io, site):
    capture_io.update(site=site, primary=OSError("after native operation"))
    assert module._read_capped(capture_io["path"], keep_tail=True) == ("", False)
    _assert_retired(capture_io)


@pytest.mark.parametrize("site", ["metadata", "read"])
@pytest.mark.parametrize("close_type", [OSError, KeyboardInterrupt])
def test_fresh_close_after_handled_io_remains_visible(capture_io, site, close_type):
    cleanup = close_type("after native close")
    capture_io.update(site=site, primary=OSError("after native operation"), cleanup=cleanup)
    with pytest.raises(close_type) as raised:
        module._read_capped(capture_io["path"], keep_tail=True)
    assert raised.value is cleanup
    _assert_retired(capture_io)


@pytest.mark.parametrize("close_type", [OSError, KeyboardInterrupt, SystemExit])
def test_successful_reader_close_failure_stays_visible(capture_io, close_type):
    cleanup = close_type("after native close")
    capture_io["cleanup"] = cleanup
    with pytest.raises(close_type) as raised:
        module._read_capped(capture_io["path"], keep_tail=True)
    assert raised.value is cleanup
    _assert_retired(capture_io)


@pytest.mark.parametrize("keep_tail", [False, True])
def test_native_head_tail_windows_are_unchanged(capture_io, keep_tail):
    expected = capture_io["payload"][:4].decode() + module._TRUNCATION_MARKER
    if keep_tail:
        expected += capture_io["payload"][-4:].decode()
    assert module._read_capped(capture_io["path"], keep_tail=keep_tail) == (expected, True)
    _assert_retired(capture_io)


def test_native_small_capture_is_complete(capture_io, monkeypatch):
    monkeypatch.setattr(module, "_CAPTURE_CAP_BYTES", 16)
    assert module._read_capped(capture_io["path"], keep_tail=True) == (capture_io["payload"].decode(), False)
    _assert_retired(capture_io)
