"""Exclusive seed writer cleanup with owned inert files only."""
import os
from types import SimpleNamespace

import pytest

from packages.binary_analysis import corpus_profile as module


@pytest.fixture
def writer_io(tmp_path, monkeypatch):
    state = {"dest": tmp_path / "seed.bin", "primary": None, "cleanup": None,
             "live": set(), "closes": 0}
    original = module.open_exclusive_artifact

    def opened(path):
        fd = original(path)
        state["live"].add(fd)
        return fd

    def write(fd, data):
        result = os.write(fd, data)
        if state["primary"] is not None:
            raise state["primary"]
        return result

    def close(fd):
        os.close(fd)
        state["live"].remove(fd)
        state["closes"] += 1
        if state["cleanup"] is not None:
            raise state["cleanup"]

    monkeypatch.setattr(module, "open_exclusive_artifact", opened)
    monkeypatch.setattr(module, "os", SimpleNamespace(**{**vars(os), "write": write, "close": close}))
    try:
        yield state
    finally:
        for fd in state["live"]:
            os.close(fd)


def test_write_primary_survives_consumed_close(writer_io):
    primary = KeyboardInterrupt("after native write")
    writer_io["primary"] = primary
    writer_io["cleanup"] = OSError("after native close")
    with pytest.raises(KeyboardInterrupt) as raised:
        module._write_seed_bytes(writer_io["dest"], b"plain\n")
    assert raised.value is primary
    assert writer_io["dest"].read_bytes() == b"plain\n"
    assert writer_io["closes"] == 1
    assert not writer_io["live"]


@pytest.mark.parametrize("primary_type", [MemoryError, SystemExit])
@pytest.mark.parametrize("close_type", [OSError, KeyboardInterrupt])
def test_unexpected_write_error_keeps_identity(writer_io, primary_type, close_type):
    primary = primary_type("after native write")
    writer_io["primary"] = primary
    writer_io["cleanup"] = close_type("after native close")
    with pytest.raises(primary_type) as raised:
        module._write_seed_bytes(writer_io["dest"], b"plain\n")
    assert raised.value is primary
    assert writer_io["closes"] == 1
    assert not writer_io["live"]


def test_handled_write_io_returns_reason(writer_io):
    writer_io["primary"] = OSError("after native write")
    assert module._write_seed_bytes(writer_io["dest"], b"plain\n") == "write failed: OSError"
    assert writer_io["closes"] == 1
    assert not writer_io["live"]


@pytest.mark.parametrize("handled_io", [False, True])
@pytest.mark.parametrize("close_type", [OSError, KeyboardInterrupt, SystemExit])
def test_fresh_close_failure_stays_visible(writer_io, handled_io, close_type):
    if handled_io:
        writer_io["primary"] = OSError("after native write")
    cleanup = close_type("after native close")
    writer_io["cleanup"] = cleanup
    with pytest.raises(close_type) as raised:
        module._write_seed_bytes(writer_io["dest"], b"plain\n")
    assert raised.value is cleanup
    assert writer_io["closes"] == 1
    assert not writer_io["live"]


def test_successful_native_write(writer_io):
    assert module._write_seed_bytes(writer_io["dest"], b"plain\n") is None
    assert writer_io["dest"].read_bytes() == b"plain\n"
    assert writer_io["closes"] == 1
    assert not writer_io["live"]


def test_existing_destination_refused_without_close(writer_io):
    writer_io["dest"].write_bytes(b"keep\n")
    assert module._write_seed_bytes(writer_io["dest"], b"plain\n") == "destination not exclusively creatable: FileExistsError"
    assert writer_io["dest"].read_bytes() == b"keep\n"
    assert writer_io["closes"] == 0
    assert not writer_io["live"]
