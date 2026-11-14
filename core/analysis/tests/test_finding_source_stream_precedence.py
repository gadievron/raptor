"""Direct tiny-file reads preserve primary errors over stream cleanup faults."""

import errno
import io
import os

import pytest

from core.analysis import finding_resolver as resolver


@pytest.fixture
def owned_source(tmp_path, monkeypatch):
    source = tmp_path / "owned.txt"
    payload = b"owned marker\n"
    source.write_bytes(payload)
    state = {"primary": None, "cleanup": None, "reads": [], "streams": [],
             "fds": [], "closes": 0}

    class Reader(io.BufferedReader):
        def read(self, size=-1):
            data = super().read(size)
            state["reads"].append((size, data))
            if state["primary"] is not None:
                raise state["primary"]
            return data

        def close(self):
            if self.closed:
                return
            super().close()
            state["closes"] += 1
            if state["cleanup"] is not None:
                raise state["cleanup"]

    class OwnedPath(type(source)):
        def open(self, *args, **kwargs):
            assert self == source and args == ("rb",) and not kwargs
            stream = Reader(source.open("rb"))
            state["streams"].append(stream)
            state["fds"].append(stream.fileno())
            return stream

    def forbidden(*args, **kwargs):
        raise AssertionError("private reader only; parser and resolution are outside this test")

    for name in ("resolve_finding", "_resolve_from_parsed", "_resolve_source",
                 "_detect_language", "build_python_cfg", "build_cpp_intraproc_cfg"):
        monkeypatch.setattr(resolver, name, forbidden)
    monkeypatch.setattr(resolver, "Path", OwnedPath)
    try:
        yield str(source), state
        assert state["reads"] == [(64 * 1024 * 1024 + 1, payload)]
        assert state["closes"] == len(state["streams"]) == 1
        assert all(stream.closed for stream in state["streams"])
        for fd in state["fds"]:
            with pytest.raises(OSError) as caught:
                os.fstat(fd)
            assert caught.value.errno == errno.EBADF
        assert source.read_bytes() == payload
    finally:
        state["cleanup"] = None
        for stream in state["streams"]:
            if not stream.closed:
                stream.close()


def test_reader_preserves_keyboard_interrupt_over_close_oserror(owned_source):
    source, state = owned_source
    primary = state["primary"] = KeyboardInterrupt("owned read cancellation")
    state["cleanup"] = OSError("owned cleanup failure")
    with pytest.raises(KeyboardInterrupt) as caught:
        resolver._read_finding_source(source)
    assert caught.value is primary


@pytest.mark.parametrize("primary_type", [ValueError, SystemExit])
@pytest.mark.parametrize("cleanup_type", [OSError, KeyboardInterrupt])
def test_other_primary_read_errors_keep_identity(owned_source, primary_type, cleanup_type):
    source, state = owned_source
    primary = state["primary"] = primary_type("owned read failure")
    state["cleanup"] = cleanup_type("owned cleanup failure")
    with pytest.raises(primary_type) as caught:
        resolver._read_finding_source(source)
    assert caught.value is primary


@pytest.mark.parametrize("cleanup_type", [OSError, KeyboardInterrupt])
def test_read_oserror_keeps_original_failure_diagnostic(owned_source, cleanup_type):
    source, state = owned_source
    state["primary"] = OSError("owned read refusal")
    state["cleanup"] = cleanup_type("owned cleanup failure")
    result = resolver._read_finding_source(source)
    assert isinstance(result, resolver.ResolutionFailure)
    assert "owned read refusal" in result.reason


def test_fresh_close_oserror_remains_a_failure_result(owned_source):
    source, state = owned_source
    state["cleanup"] = OSError("owned cleanup failure")
    result = resolver._read_finding_source(source)
    assert isinstance(result, resolver.ResolutionFailure)
    assert "owned cleanup failure" in result.reason


@pytest.mark.parametrize("cleanup_type", [KeyboardInterrupt, SystemExit])
def test_fresh_close_cancellation_still_propagates(owned_source, cleanup_type):
    source, state = owned_source
    cleanup = state["cleanup"] = cleanup_type("owned cleanup failure")
    with pytest.raises(cleanup_type) as caught:
        resolver._read_finding_source(source)
    assert caught.value is cleanup


def test_healthy_private_reader_returns_owned_marker(owned_source):
    source, _ = owned_source
    assert resolver._read_finding_source(source) == "owned marker\n"
