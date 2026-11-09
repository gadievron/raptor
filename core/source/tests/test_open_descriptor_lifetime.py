"""Owned-file descriptor retirement during reader setup failures."""

import os

import pytest

from core.source import beneath, contained
from core.source.streams import adopt_fd
from core.testing.module_bindings import patch_module_attribute


@pytest.fixture
def reader(tmp_path, monkeypatch):
    folder = tmp_path / "one" / "two"
    folder.mkdir(parents=True)
    path = folder / "file.txt"
    path.write_bytes(b"owned bytes")
    real_open, real_close = os.open, os.close
    live, streams, opened, closed = {}, [], [], []

    def install(route, *, wrap_error=None, close_error=None, close_index=0):
        owner = contained if route == "direct" else beneath
        monkeypatch.setattr(beneath, "_OPENAT2_ARCH_OK", False)

        def open_file(*args, **kwargs):
            fd = real_open(*args, **kwargs)
            opened.append(fd)
            live[fd] = len(opened) - 1
            return fd

        def close(fd):
            index = live.pop(fd)
            closed.append(index)
            real_close(fd)
            if close_error is not None and index == close_index:
                raise close_error

        def wrap(fd, mode, close_fd=None, **kwargs):
            if wrap_error is not None:
                try:
                    close_fd(fd)
                except BaseException:
                    pass
                raise wrap_error
            stream = adopt_fd(fd, mode, close_fd, **kwargs)
            live.pop(fd)
            streams.append(stream)
            return stream

        patch_module_attribute(monkeypatch, owner, "os", "open", open_file)
        patch_module_attribute(monkeypatch, owner, "os", "close", close)
        monkeypatch.setattr(owner, "adopt_fd", wrap)
        invoke = (lambda: contained.open_regular(path, "rb")) if route == "direct" else (
            lambda: beneath.open_regular_beneath(tmp_path, "one/two/file.txt", "rb")
        )
        return invoke, live, streams, opened, closed

    yield install
    for stream in streams:
        stream.close()
    for fd in live:
        real_close(fd)


@pytest.mark.parametrize("route", ["direct", "beneath"])
@pytest.mark.parametrize("error_type", [OSError, ValueError, RuntimeError, KeyboardInterrupt, SystemExit])
def test_failed_wrapping_releases_raw_descriptors(reader, route, error_type):
    error = error_type("wrapping failed")
    invoke, live, streams, opened, _ = reader(route, wrap_error=error)
    if error_type is OSError:
        assert invoke() is None
    else:
        with pytest.raises(error_type) as caught:
            invoke()
        assert caught.value is error
    assert opened
    assert live == {}
    assert streams == []


@pytest.mark.parametrize("route", ["direct", "beneath"])
def test_wrapping_interruption_survives_failed_raw_close(reader, route):
    error = KeyboardInterrupt("wrapping interrupted")
    invoke, live, _, _, _ = reader(
        route, wrap_error=error, close_error=OSError("close failed"),
    )
    with pytest.raises(KeyboardInterrupt) as caught:
        invoke()
    assert caught.value is error
    assert live == {}


@pytest.mark.parametrize("error_type", [OSError, RuntimeError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("close_index", [1, 2])
def test_walk_retirement_failure_closes_pending_descriptors(reader, error_type, close_index):
    error = error_type("directory retirement failed")
    invoke, live, streams, opened, closed = reader(
        "beneath", close_error=error, close_index=close_index,
    )
    if error_type is OSError:
        assert invoke() is None
    else:
        with pytest.raises(error_type) as caught:
            invoke()
        assert caught.value is error
    assert len(opened) >= 3
    assert live == {}
    assert all(stream.closed for stream in streams)
    assert len(closed) == len(set(closed))  # No retry after an uncertain close.


@pytest.mark.parametrize("error_type", [OSError, KeyboardInterrupt])
def test_root_close_failure_reclaims_unreturned_stream(reader, error_type):
    error = error_type("root retirement failed")
    invoke, live, streams, _, _ = reader("beneath", close_error=error)
    with pytest.raises(error_type) as caught:
        invoke()
    assert caught.value is error
    assert live == {}
    assert streams and all(stream.closed for stream in streams)


@pytest.mark.parametrize("route", ["direct", "beneath"])
def test_success_transfers_only_the_open_stream(reader, route):
    invoke, live, streams, _, _ = reader(route)
    stream = invoke()
    assert stream is not None
    with stream:
        assert stream.read() == b"owned bytes"
        assert not stream.closed
        assert live == {}
    assert streams == [stream] and stream.closed
