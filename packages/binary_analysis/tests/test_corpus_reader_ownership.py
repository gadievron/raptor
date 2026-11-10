"""Metadata-only corpus reader ownership; no profiler or target runs."""
import errno
import os
from types import SimpleNamespace

import pytest

from packages.binary_analysis import corpus_profile as consumer


def test_nonregular_refusal_never_retries_consumed_descriptor(tmp_path, monkeypatch):
    path = tmp_path / "entry"
    path.write_bytes(b"inert")
    independent = tmp_path / "independent"
    independent.write_bytes(b"retained")
    live = set()
    state = {"closes": 0, "replacement": None}
    primary = OSError("after native refusal close")

    def opened(*args, **kwargs):
        # Actual race within our own temp tree: lstat saw a plain file;
        # the native nonblocking open and fstat now see an owned FIFO.
        path.unlink()
        os.mkfifo(path)
        fd = os.open(*args, **kwargs)
        live.add(fd)
        return fd

    def close(fd):
        os.close(fd)
        live.remove(fd)
        state["closes"] += 1
        if state["closes"] == 1:
            with pytest.raises(OSError) as retired:
                os.fstat(fd)
            assert retired.value.errno == errno.EBADF
            replacement = os.open(independent, os.O_RDONLY)
            live.add(replacement)
            state["replacement"] = replacement
            assert replacement == fd
            raise primary

    monkeypatch.setattr(consumer, "os", SimpleNamespace(
        **{**vars(os), "open": opened, "close": close}))
    try:
        assert consumer._open_regular_nofollow(path) is None
        assert state["closes"] == 1
        os.fstat(state["replacement"])
        assert os.read(state["replacement"], 8) == b"retained"
    finally:
        for fd in live:
            os.close(fd)


@pytest.fixture
def metadata_io(tmp_path, monkeypatch):
    path = tmp_path / "plain.txt"
    path.write_bytes(b"inert plain text")
    state = {"path": path, "live": set(), "primary": None, "cleanup": None,
             "closes": 0}

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

    monkeypatch.setattr(consumer, "os", SimpleNamespace(
        **{**vars(os), "open": opened, "fstat": info, "close": close}))
    try:
        yield state
    finally:
        for fd in state["live"]:
            os.close(fd)


@pytest.mark.parametrize("primary_type", [MemoryError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("close_type", [None, OSError, KeyboardInterrupt])
def test_metadata_interrupt_retires_unreturned_descriptor(metadata_io, primary_type, close_type):
    primary = primary_type("after native metadata")
    metadata_io["primary"] = primary
    metadata_io["cleanup"] = close_type("after native close") if close_type else None
    with pytest.raises(primary_type) as raised:
        consumer._open_regular_nofollow(metadata_io["path"])
    assert raised.value is primary
    assert metadata_io["closes"] == 1
    assert not metadata_io["live"]


@pytest.mark.parametrize("close_type", [OSError, KeyboardInterrupt, SystemExit])
def test_fresh_metadata_refusal_close_failure_remains_visible(metadata_io, close_type):
    metadata_io["primary"] = OSError("after native metadata")
    cleanup = close_type("after native close")
    metadata_io["cleanup"] = cleanup
    with pytest.raises(close_type) as raised:
        consumer._open_regular_nofollow(metadata_io["path"])
    assert raised.value is cleanup
    assert metadata_io["closes"] == 1
    assert not metadata_io["live"]


def test_metadata_io_refusal_closes_once(metadata_io):
    metadata_io["primary"] = OSError("after native metadata")
    assert consumer._open_regular_nofollow(metadata_io["path"]) is None
    assert metadata_io["closes"] == 1
    assert not metadata_io["live"]


def test_regular_descriptor_transfers_to_caller(metadata_io):
    fd = consumer._open_regular_nofollow(metadata_io["path"])
    assert fd in metadata_io["live"]
    assert metadata_io["closes"] == 0
    assert os.read(fd, 5) == b"inert"
    consumer.os.close(fd)
    assert metadata_io["closes"] == 1
    assert not metadata_io["live"]


def test_bounded_reader_retires_transferred_descriptor(metadata_io):
    assert consumer._bounded_read(metadata_io["path"], 5) == b"inert"
    assert metadata_io["closes"] == 1
    assert not metadata_io["live"]
