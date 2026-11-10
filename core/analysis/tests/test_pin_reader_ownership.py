"""Identity-pin reader setup owns native streams until successful transfer."""
import hashlib

import pytest

import core.hash as hashing
import core.source as source
from core.analysis import binary_oracle as consumer


@pytest.fixture
def pin_io(tmp_path, monkeypatch):
    path = tmp_path / "plain.txt"
    path.write_bytes(b"inert plain text")
    info = path.stat()
    pin = (info.st_dev, info.st_ino, info.st_size,
           hashlib.sha256(path.read_bytes()).hexdigest())
    state = {"path": path, "pin": pin, "streams": [], "primary": None,
             "cleanup": None, "closes": 0, "hashes": 0}
    native_open = source.open_regular
    native_hash = hashing.sha256_fileobj

    class Stream:
        def __init__(self, native):
            self.native = native

        def __getattr__(self, name):
            return getattr(self.native, name)

        def close(self):
            self.native.close()
            state["closes"] += 1
            if state["cleanup"] is not None:
                raise state["cleanup"]

    def opened(*args, **kwargs):
        native = native_open(*args, **kwargs)
        assert native is not None
        wrapped = Stream(native)
        state["streams"].append(wrapped)
        return wrapped

    def hashed(stream):
        result = native_hash(stream)
        state["hashes"] += 1
        if state["primary"] is not None:
            raise state["primary"]
        return result

    monkeypatch.setattr(source, "open_regular", opened)
    monkeypatch.setattr(hashing, "sha256_fileobj", hashed)
    try:
        yield state
    finally:
        for stream in state["streams"]:
            stream.native.close()


@pytest.mark.parametrize("primary_type", [MemoryError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("close_type", [None, OSError, KeyboardInterrupt])
def test_failed_hash_retires_unreturned_native_reader(pin_io, primary_type, close_type):
    primary = primary_type("after native hashing")
    pin_io["primary"] = primary
    pin_io["cleanup"] = close_type("after native close") if close_type else None
    with pytest.raises(primary_type) as raised:
        consumer._pin_open_verified(pin_io["path"], pin_io["pin"])
    assert raised.value is primary
    assert pin_io["hashes"] == pin_io["closes"] == 1
    assert pin_io["streams"][0].closed


def test_success_transfers_native_reader_at_eof(pin_io):
    stream = consumer._pin_open_verified(pin_io["path"], pin_io["pin"])
    assert stream is pin_io["streams"][0]
    assert not stream.closed
    assert stream.read() == b""
    assert pin_io["closes"] == 0
    stream.close()
    assert pin_io["closes"] == 1


def test_mismatch_retires_reader_without_transfer(pin_io):
    pin = (*pin_io["pin"][:3], "0" * 64)
    assert consumer._pin_open_verified(pin_io["path"], pin) is None
    assert pin_io["streams"][0].closed
    assert pin_io["closes"] == 1


def test_handled_hash_io_failure_remains_none(pin_io):
    pin_io["primary"] = OSError("after native hashing")
    pin_io["cleanup"] = OSError("after native close")
    assert consumer._pin_open_verified(pin_io["path"], pin_io["pin"]) is None
    assert pin_io["streams"][0].closed
    assert pin_io["closes"] == 1
