"""The format-sniff reader preserves interruption and optional-read policy."""
import io
import errno
import os
from types import SimpleNamespace

import pytest

from core.binary import pe


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

    def owned_open(candidate, mode="r", *args, **kwargs):
        assert candidate == path and mode == "rb" and not args and not kwargs
        native = path.open(mode)
        state.native.append(native)
        state.fd = native.fileno()
        reader = Reader(native)
        state.readers.append(reader)
        return reader

    monkeypatch.setattr(pe, "open", owned_open, raising=False)
    state.run = lambda: pe.is_pe(path)
    try:
        yield state
    finally:
        for reader in state.readers:
            if not reader.closed:
                io.BufferedReader.close(reader)
        if path.exists():
            assert path.read_bytes() == payload


def assert_retired(state):
    assert state.reads == [(2, state.payload[:2])]
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


@pytest.mark.parametrize("failure", [OSError, ValueError, OverflowError])
def test_read_failure_keeps_optional_policy(sniff, failure):
    sniff.primary = failure("after native format sniff")
    sniff.cleanup = KeyboardInterrupt("after native sniff close")
    assert sniff.run() is False
    assert_retired(sniff)


@pytest.mark.parametrize("cleanup", [OSError, KeyboardInterrupt])
def test_fresh_close_failure_keeps_optional_policy(sniff, cleanup):
    sniff.cleanup = cleanup("after native sniff close")
    if cleanup is OSError:
        assert sniff.run() is False
    else:
        with pytest.raises(cleanup) as caught:
            sniff.run()
        assert caught.value is sniff.cleanup
    assert_retired(sniff)


def test_unknown_format_keeps_optional_facts(sniff):
    assert sniff.run() is False
    assert_retired(sniff)


def test_missing_file_keeps_optional_open_policy(sniff):
    sniff.path.unlink()
    assert sniff.run() is False
    assert not sniff.native and not sniff.readers and not sniff.reads
    assert sniff.closes == 0


def test_valid_signature_and_truncated_coff_keep_probe_contract(tmp_path):
    payload = bytearray(88)
    payload[:2] = b"MZ"
    payload[60:64] = (64).to_bytes(4, "little")
    payload[64:68] = b"PE\0\0"
    path = tmp_path / "owned-header.bin"
    path.write_bytes(payload)
    assert pe.is_pe(path) is True
    path.write_bytes(payload[:68])
    assert pe.is_pe(path) is False
