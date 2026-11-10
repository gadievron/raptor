"""Direct byte-reader error precedence, not profiling or harness execution."""
import os
from types import SimpleNamespace

import pytest

from packages.binary_analysis import corpus_profile
from packages.fuzzing import harness_census


@pytest.fixture(params=["corpus", "harness"])
def reader_io(request, tmp_path, monkeypatch):
    path = tmp_path / "plain.txt"
    path.write_bytes(b"plain text\n")
    if request.param == "corpus":
        module, reader, expected = corpus_profile, lambda p: corpus_profile._bounded_read(p, 8), b"plain te"
    else:
        module, reader, expected = harness_census, harness_census._sniff, b"plain text\n"
    state = {"path": path, "read": reader, "expected": expected, "live": set(),
             "primary": None, "cleanup": None, "closes": 0}

    def opened(*args, **kwargs):
        fd = os.open(*args, **kwargs)
        state["live"].add(fd)
        return fd

    def read(fd, size):
        result = os.read(fd, size)
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
        **{**vars(os), "open": opened, "read": read, "close": close}))
    try:
        yield state
    finally:
        for fd in state["live"]:
            os.close(fd)


def test_active_read_error_survives_consumed_close(reader_io):
    primary = KeyboardInterrupt("after native read")
    reader_io["primary"] = primary
    reader_io["cleanup"] = OSError("after native close")
    with pytest.raises(KeyboardInterrupt) as raised:
        reader_io["read"](reader_io["path"])
    assert raised.value is primary
    assert reader_io["closes"] == 1
    assert not reader_io["live"]


@pytest.mark.parametrize("primary_type", [MemoryError, SystemExit])
@pytest.mark.parametrize("close_type", [OSError, KeyboardInterrupt])
def test_unexpected_read_primary_keeps_identity(reader_io, primary_type, close_type):
    primary = primary_type("after native read")
    reader_io["primary"] = primary
    reader_io["cleanup"] = close_type("after native close")
    with pytest.raises(primary_type) as raised:
        reader_io["read"](reader_io["path"])
    assert raised.value is primary
    assert reader_io["closes"] == 1
    assert not reader_io["live"]


def test_handled_read_io_still_returns_none(reader_io):
    reader_io["primary"] = OSError("after native read")
    assert reader_io["read"](reader_io["path"]) is None
    assert reader_io["closes"] == 1
    assert not reader_io["live"]


@pytest.mark.parametrize("close_type", [OSError, KeyboardInterrupt])
def test_handled_read_io_does_not_hide_fresh_close_failure(reader_io, close_type):
    reader_io["primary"] = OSError("after native read")
    cleanup = close_type("after native close")
    reader_io["cleanup"] = cleanup
    with pytest.raises(close_type) as raised:
        reader_io["read"](reader_io["path"])
    assert raised.value is cleanup
    assert reader_io["closes"] == 1
    assert not reader_io["live"]


@pytest.mark.parametrize("close_type", [OSError, KeyboardInterrupt, SystemExit])
def test_successful_read_close_failure_stays_visible(reader_io, close_type):
    cleanup = close_type("after native close")
    reader_io["cleanup"] = cleanup
    with pytest.raises(close_type) as raised:
        reader_io["read"](reader_io["path"])
    assert raised.value is cleanup
    assert reader_io["closes"] == 1
    assert not reader_io["live"]


def test_native_reader_content_and_cap_stay_unchanged(reader_io):
    assert reader_io["read"](reader_io["path"]) == reader_io["expected"]
    assert reader_io["closes"] == 1
    assert not reader_io["live"]
