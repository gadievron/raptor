"""The format-sniff reader preserves interruption and optional-read policy."""
import io
import errno
import os
import struct
from pathlib import Path
from types import SimpleNamespace

import pytest

from core.binary import elf


@pytest.fixture
def sniff(tmp_path, monkeypatch):
    path = tmp_path / "owned.bin"
    payload = b"ordinary unknown-format bytes\n"
    path.write_bytes(payload)
    state = SimpleNamespace(primary=None, cleanup=None, native=[], readers=[],
                            reads=[], closes=0, fd=None, path=path, payload=payload)

    class Reader(io.BufferedReader):
        def read(self, size=-1):
            data = super().read(size)
            state.reads.append((size, data))
            if state.primary is not None:
                raise state.primary
            return data

        def close(self):
            if self.closed:
                return super().close()
            super().close()
            state.closes += 1
            if state.cleanup is not None:
                raise state.cleanup

    class OwnedPath(type(Path())):
        def open(self, mode="r", *args, **kwargs):
            assert mode == "rb" and not args and not kwargs
            native = super().open(mode)
            state.native.append(native)
            state.fd = native.fileno()
            reader = Reader(native)
            state.readers.append(reader)
            return reader

    monkeypatch.setattr(elf, "Path", OwnedPath)
    state.run = lambda: elf.parse_elf(path)
    try:
        yield state
    finally:
        for reader in state.readers:
            if not reader.closed:
                io.BufferedReader.close(reader)
        if path.exists():
            assert path.read_bytes() == payload


def assert_retired(state):
    assert state.reads == [(16, state.payload[:16])]
    assert state.closes == len(state.readers) == len(state.native) == 1
    assert all(reader.closed for reader in state.readers + state.native)
    with pytest.raises(OSError) as caught:
        os.fstat(state.fd)
    assert caught.value.errno == errno.EBADF


@pytest.mark.parametrize("primary", [KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("cleanup", [OSError, MemoryError])
def test_sniff_failure_survives_consumed_close(sniff, primary, cleanup):
    sniff.primary = primary("after native format sniff")
    sniff.cleanup = cleanup("after native sniff close")
    with pytest.raises(primary) as caught:
        sniff.run()
    assert caught.value is sniff.primary
    assert_retired(sniff)


@pytest.mark.parametrize("failure", [OSError, ValueError, OverflowError, struct.error])
def test_read_failure_keeps_optional_policy(sniff, failure):
    sniff.primary = failure("after native format sniff")
    sniff.cleanup = KeyboardInterrupt("after native sniff close")
    assert sniff.run() is None
    assert_retired(sniff)


@pytest.mark.parametrize("cleanup", [OSError, KeyboardInterrupt])
def test_fresh_close_failure_keeps_optional_policy(sniff, cleanup):
    sniff.cleanup = cleanup("after native sniff close")
    if cleanup is OSError:
        assert sniff.run() is None
    else:
        with pytest.raises(cleanup) as caught:
            sniff.run()
        assert caught.value is sniff.cleanup
    assert_retired(sniff)


def test_unknown_format_keeps_optional_facts(sniff):
    assert sniff.run() is None
    assert_retired(sniff)


def test_missing_file_keeps_optional_open_policy(sniff):
    sniff.path.unlink()
    assert sniff.run() is None
    assert not sniff.native and not sniff.readers and not sniff.reads
    assert sniff.closes == 0
