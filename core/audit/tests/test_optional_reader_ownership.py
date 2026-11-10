"""Optional native file readers retain active errors and fresh close policy."""
import os
from types import SimpleNamespace

import pytest

from core.audit import validate
from core.run import target_types


@pytest.fixture(params=["magic", "tail"])
def reader_io(request, tmp_path, monkeypatch):
    path = tmp_path / "plain.txt"
    path.write_bytes(b"plain text\n")
    module, read = ((target_types, target_types._read_magic) if request.param == "magic"
                    else (validate, validate._read_child_tail_untrusted))
    state = {"path": path, "read": read, "kind": request.param, "live": set(),
             "primary": None, "cleanup": None, "closes": 0}

    def opened(*args, **kwargs):
        fd = os.open(*args, **kwargs)
        state["live"].add(fd)
        return fd

    def info(fd):
        result = os.fstat(fd)
        if state["primary"] is not None:
            raise state["primary"]
        return result

    def close(fd):
        os.close(fd)
        state["live"].remove(fd)
        state["closes"] += 1
        if state["cleanup"] is not None:
            raise state["cleanup"]

    monkeypatch.setattr(module, "os", SimpleNamespace(
        **{**vars(os), "open": opened, "fstat": info, "close": close}))
    try:
        yield state
    finally:
        for fd in state["live"]:
            os.close(fd)


def test_active_metadata_error_survives_close(reader_io):
    primary = KeyboardInterrupt("after native metadata")
    reader_io["primary"] = primary
    reader_io["cleanup"] = OSError("after native close")
    with pytest.raises(KeyboardInterrupt) as raised:
        reader_io["read"](reader_io["path"])
    assert raised.value is primary
    assert reader_io["closes"] == 1
    assert not reader_io["live"]


@pytest.mark.parametrize("primary_type", [MemoryError, SystemExit])
@pytest.mark.parametrize("close_type", [OSError, KeyboardInterrupt])
def test_unexpected_metadata_error_keeps_precedence(reader_io, primary_type, close_type):
    primary = primary_type("after native metadata")
    reader_io["primary"] = primary
    reader_io["cleanup"] = close_type("after native close")
    with pytest.raises(primary_type) as raised:
        reader_io["read"](reader_io["path"])
    assert raised.value is primary
    assert reader_io["closes"] == 1
    assert not reader_io["live"]


def test_handled_metadata_io_remains_optional(reader_io):
    reader_io["primary"] = OSError("after native metadata")
    assert reader_io["read"](reader_io["path"]) is None
    assert reader_io["closes"] == 1
    assert not reader_io["live"]


@pytest.mark.parametrize("close_type", [OSError, KeyboardInterrupt])
def test_close_failure_after_handled_io_is_still_fresh(reader_io, close_type):
    reader_io["primary"] = OSError("after native metadata")
    cleanup = close_type("after native close")
    reader_io["cleanup"] = cleanup
    with pytest.raises(close_type) as raised:
        reader_io["read"](reader_io["path"])
    assert raised.value is cleanup
    assert reader_io["closes"] == 1
    assert not reader_io["live"]


@pytest.mark.parametrize("close_type", [OSError, KeyboardInterrupt, SystemExit])
def test_successful_read_requires_successful_close(reader_io, close_type):
    cleanup = close_type("after native close")
    reader_io["cleanup"] = cleanup
    with pytest.raises(close_type) as raised:
        reader_io["read"](reader_io["path"])
    assert raised.value is cleanup
    assert reader_io["closes"] == 1
    assert not reader_io["live"]


def test_native_success_preserves_reader_content(reader_io):
    expected = b"plain te" if reader_io["kind"] == "magic" else "plain text\n"
    assert reader_io["read"](reader_io["path"]) == expected
    assert reader_io["closes"] == 1
    assert not reader_io["live"]
