"""Direct reader raw metadata cleanup; native adoption failure is outside scope."""
import os
from types import SimpleNamespace

import pytest

from packages.sca.parsers import _safe_read as prefix
from packages.sca.resolvers import _safe_io as resolver


@pytest.fixture(params=["resolver", "prefix"])
def reader_io(request, tmp_path, monkeypatch):
    path = tmp_path / "plain.txt"
    path.write_bytes(b"plain\n")
    if request.param == "resolver":
        module, reader, expected = resolver, lambda p: resolver.read_regular_bytes(p, max_bytes=8), b"plain\n"
    else:
        module, reader, expected = prefix, lambda p: prefix.read_head_bytes(p, max_bytes=4), b"plai"
    state = {"kind": request.param, "path": path, "read": reader, "expected": expected,
             "live": set(), "primary": None, "cleanup": None, "closes": 0,
             "stream_closes": 0, "adoptions": [], "streams": []}

    def opened(*args, **kwargs):
        fd = os.open(*args, **kwargs)
        state["live"].add(fd)
        return fd

    def fstat(fd):
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

    def adopted(fd, mode, **kwargs):
        native = os.fdopen(fd, mode, **kwargs)
        state["adoptions"].append((mode, kwargs))
        state["streams"].append(native)

        class Observed:
            def __enter__(self):
                return native.__enter__()

            def __exit__(self, *exc):
                try:
                    return native.__exit__(*exc)
                finally:
                    state["live"].remove(fd)
                    state["stream_closes"] += 1

        return Observed()

    monkeypatch.setattr(module, "os", SimpleNamespace(
        **{**vars(os), "open": opened, "fstat": fstat, "close": close, "fdopen": adopted}))
    try:
        yield state
    finally:
        for stream in state["streams"]:
            stream.close()
        for fd in state["live"]:
            os.close(fd)


def test_metadata_interruption_keeps_identity_before_adoption(reader_io):
    primary = KeyboardInterrupt("after native reader metadata")
    reader_io.update(primary=primary, cleanup=OSError("after native raw close"))
    with pytest.raises(KeyboardInterrupt) as raised:
        reader_io["read"](reader_io["path"])
    assert raised.value is primary
    assert reader_io["closes"] == 1
    assert reader_io["adoptions"] == []
    assert not reader_io["live"]


@pytest.mark.parametrize("primary_type", [RuntimeError, MemoryError, SystemExit, ValueError])
@pytest.mark.parametrize("close_type", [OSError, KeyboardInterrupt])
def test_unexpected_metadata_error_keeps_identity(reader_io, primary_type, close_type):
    primary = primary_type("after native metadata")
    reader_io.update(primary=primary, cleanup=close_type("after native raw close"))
    with pytest.raises(primary_type) as raised:
        reader_io["read"](reader_io["path"])
    assert raised.value is primary
    assert reader_io["closes"] == 1
    assert reader_io["adoptions"] == []
    assert not reader_io["live"]


@pytest.mark.parametrize("close_type", [None, OSError, KeyboardInterrupt, SystemExit])
def test_handled_metadata_io_retains_distinct_raw_close_policy(reader_io, close_type):
    primary = OSError("after native metadata")
    cleanup = close_type("after native raw close") if close_type else None
    reader_io.update(primary=primary, cleanup=cleanup)
    if close_type in (KeyboardInterrupt, SystemExit) or (close_type is OSError and reader_io["kind"] == "resolver"):
        with pytest.raises(close_type) as raised:
            reader_io["read"](reader_io["path"])
        assert raised.value is cleanup
    else:
        assert reader_io["read"](reader_io["path"]) is None
    assert reader_io["closes"] == 1
    assert reader_io["adoptions"] == []
    assert not reader_io["live"]


def test_healthy_native_adoption_keeps_stream_ownership(reader_io):
    assert reader_io["read"](reader_io["path"]) == reader_io["expected"]
    assert reader_io["adoptions"] == [("rb", {"closefd": True})]
    assert reader_io["closes"] == 0
    assert reader_io["stream_closes"] == 1
    assert reader_io["streams"][0].closed
    assert not reader_io["live"]
