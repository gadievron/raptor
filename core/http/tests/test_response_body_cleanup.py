"""Owned file-backed responses preserve body failures during teardown."""
import errno
import io
import os
from types import SimpleNamespace

import pytest
from urllib3.response import HTTPResponse

from core.http import HttpError
from core.http import _body
from core.testing.module_bindings import patch_module_attribute


@pytest.fixture
def body(tmp_path, monkeypatch):
    path = tmp_path / "response.bin"
    payload = b"0123456789abcdef"
    path.write_bytes(payload)
    native = path.open("rb")
    state = SimpleNamespace(primary=None, cleanup=None, reads=[], closes=0,
                            native=native, descriptor=native.fileno())

    class Reader(io.BufferedReader):
        def read(self, size=-1):
            data = super().read(size)
            state.reads.append((size, data))
            return data

        def close(self):
            if self.closed:
                return super().close()
            super().close()
            state.closes += 1
            if state.cleanup is not None:
                raise state.cleanup

    reader = Reader(native)
    response = HTTPResponse(body=reader, preload_content=False)
    state.reader, state.response = reader, response

    def unexpected_timer(*args, **kwargs):
        pytest.fail("file-backed response must not create a socket watchdog")

    patch_module_attribute(monkeypatch, _body, "threading", "Timer", unexpected_timer)

    def run():
        with _body.response_body(response, 10, clock=lambda: 0):
            data = response.read(4)
            assert data == payload[:4]
            if state.primary is not None:
                raise state.primary
            return data

    state.run = run
    try:
        yield state
    finally:
        if not reader.closed:
            io.BufferedReader.close(reader)
        assert path.read_bytes() == payload


def assert_retired(state):
    assert state.reads == [(4, b"0123")]
    assert state.closes == 1 and state.reader.closed and state.native.closed
    assert state.response.closed and state.response.connection is None
    with pytest.raises(OSError) as caught:
        os.fstat(state.descriptor)
    assert caught.value.errno == errno.EBADF


@pytest.mark.parametrize("primary", [HttpError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("cleanup", [OSError, KeyboardInterrupt, SystemExit])
def test_active_error_survives_consumed_response_close(body, primary, cleanup):
    body.primary = primary("after native HTTP response read")
    body.cleanup = cleanup("after native HTTP response file close")
    with pytest.raises(BaseException) as caught:
        body.run()
    assert caught.value is body.primary
    assert_retired(body)


@pytest.mark.parametrize("cleanup", [OSError, KeyboardInterrupt, SystemExit])
def test_fresh_response_close_failure_keeps_existing_policy(body, cleanup):
    body.cleanup = cleanup("fresh native response close failure")
    expected = HttpError if cleanup is OSError else cleanup
    with pytest.raises(expected) as caught:
        body.run()
    if cleanup is OSError:
        assert "cleanup failed" in str(caught.value)
    else:
        assert caught.value is body.cleanup
    assert_retired(body)


def test_healthy_response_keeps_bytes_and_closes_once(body):
    assert body.run() == b"0123"
    assert_retired(body)
