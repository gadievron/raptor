"""Adopted plaintext stream cleanup; no native constructor failure claim."""
import os
from types import SimpleNamespace

import pytest

from packages.sca.parsers import _safe_read as prefix
from packages.sca.resolvers import _safe_io as resolver


@pytest.fixture(params=["resolver", "prefix"])
def stream_io(request, tmp_path, monkeypatch):
    path = tmp_path / "plain.txt"
    path.write_bytes(b"plain\n")
    if request.param == "resolver":
        module, reader, expected, extent = resolver, lambda p: resolver.read_regular_bytes(p, max_bytes=8), b"plain\n", 9
    else:
        module, reader, expected, extent = prefix, lambda p: prefix.read_head_bytes(p, max_bytes=4), b"plai", 4
    state = {"path": path, "read": reader, "expected": expected, "extent": extent,
             "live": set(), "primary": None, "cleanup": None, "raw_closes": 0,
             "stream_closes": 0, "adoptions": [], "streams": [], "reads": []}

    def opened(*args, **kwargs):
        fd = os.open(*args, **kwargs)
        state["live"].add(fd)
        return fd

    def close(fd):
        os.close(fd)
        state["live"].remove(fd)
        state["raw_closes"] += 1

    def adopted(fd, mode, **kwargs):
        native = os.fdopen(fd, mode, **kwargs)
        state["adoptions"].append((mode, kwargs))
        state["streams"].append(native)

        class Observed:
            def __enter__(self):
                native.__enter__()
                return self

            def __exit__(self, *exc):
                result = native.__exit__(*exc)
                state["live"].remove(fd)
                state["stream_closes"] += 1
                if state["cleanup"] is not None:
                    raise state["cleanup"]
                return result

            def read(self, size):
                result = native.read(size)
                state["reads"].append(size)
                if state["primary"] is not None:
                    raise state["primary"]
                return result

        return Observed()

    monkeypatch.setattr(module, "os", SimpleNamespace(
        **{**vars(os), "open": opened, "close": close, "fdopen": adopted}))
    try:
        yield state
    finally:
        for stream in state["streams"]:
            stream.close()
        for fd in state["live"]:
            os.close(fd)


def _assert_retired(state):
    assert state["adoptions"] == [("rb", {"closefd": True})]
    assert state["raw_closes"] == 0
    assert state["stream_closes"] == 1
    assert state["streams"][0].closed
    assert state["reads"] == [state["extent"]]
    assert not state["live"]


def test_stream_read_interruption_does_not_become_none(stream_io):
    primary = KeyboardInterrupt("after native buffered read")
    stream_io.update(primary=primary, cleanup=OSError("after native stream close"))
    with pytest.raises(KeyboardInterrupt) as raised:
        stream_io["read"](stream_io["path"])
    assert raised.value is primary
    _assert_retired(stream_io)


@pytest.mark.parametrize("primary_type", [RuntimeError, MemoryError, SystemExit, ValueError])
@pytest.mark.parametrize("close_type", [OSError, KeyboardInterrupt])
def test_active_stream_error_keeps_identity(stream_io, primary_type, close_type):
    primary = primary_type("after native buffered read")
    stream_io.update(primary=primary, cleanup=close_type("after native stream close"))
    with pytest.raises(primary_type) as raised:
        stream_io["read"](stream_io["path"])
    assert raised.value is primary
    _assert_retired(stream_io)


@pytest.mark.parametrize("close_type", [None, OSError, KeyboardInterrupt, SystemExit])
def test_handled_read_io_retains_fresh_close_policy(stream_io, close_type):
    primary = OSError("after native buffered read")
    cleanup = close_type("after native stream close") if close_type else None
    stream_io.update(primary=primary, cleanup=cleanup)
    if close_type in (KeyboardInterrupt, SystemExit):
        with pytest.raises(close_type) as raised:
            stream_io["read"](stream_io["path"])
        assert raised.value is cleanup
    else:
        assert stream_io["read"](stream_io["path"]) is None
    _assert_retired(stream_io)


@pytest.mark.parametrize("close_type", [None, OSError, KeyboardInterrupt, SystemExit])
def test_successful_read_retains_fresh_close_policy(stream_io, close_type):
    cleanup = close_type("after native stream close") if close_type else None
    stream_io["cleanup"] = cleanup
    if close_type in (KeyboardInterrupt, SystemExit):
        with pytest.raises(close_type) as raised:
            stream_io["read"](stream_io["path"])
        assert raised.value is cleanup
    else:
        result = stream_io["read"](stream_io["path"])
        assert result == (None if close_type is OSError else stream_io["expected"])
    _assert_retired(stream_io)


@pytest.mark.parametrize("close_fails", [False, True])
def test_handled_io_logging_retains_cause_after_retirement(stream_io, monkeypatch, close_fails):
    primary = OSError("after native buffered read")
    cleanup = OSError("after native stream close") if close_fails else None
    stream_io.update(primary=primary, cleanup=cleanup)
    records = []

    def observed_log(native_method):
        def record(*args, **kwargs):
            assert stream_io["stream_closes"] == 1
            assert stream_io["streams"][0].closed
            assert not stream_io["live"]
            records.append(args)
            native_method(*args, **kwargs)
        return record

    for module in (resolver, prefix):
        original = module.logger
        monkeypatch.setattr(module, "logger", SimpleNamespace(
            warning=observed_log(original.warning), debug=observed_log(original.debug)))
    assert stream_io["read"](stream_io["path"]) is None
    assert len(records) == 1
    assert records[0][-1] is (cleanup if close_fails else primary)
    _assert_retired(stream_io)
