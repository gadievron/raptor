"""Consumed response-close failures must retire their real queue lease."""
import errno
import io
import os
from types import SimpleNamespace

import pytest
from urllib3 import HTTPConnectionPool
from urllib3.connection import HTTPConnection
from urllib3.response import HTTPResponse

from core.http import HttpError
from core.http import _body
from core.testing.module_bindings import patch_module_attribute


@pytest.fixture
def leased(tmp_path, monkeypatch):
    path = tmp_path / "response.bin"
    payload = b"0123456789abcdef"
    path.write_bytes(payload)
    native = path.open("rb")
    state = SimpleNamespace(cleanup=None, closes=0, connection_closes=[],
                            native=native, descriptor=native.fileno())

    class NoNetworkConnection(HTTPConnection):
        def connect(self):
            pytest.fail("queue ownership test must not connect")

        def close(self):
            assert self.sock is None
            state.connection_closes.append(self)
            super().close()

    class Reader(io.BufferedReader):
        def close(self):
            if self.closed:
                return super().close()
            super().close()
            state.closes += 1
            if state.cleanup is not None:
                raise state.cleanup

    pool = HTTPConnectionPool("owned.invalid", maxsize=1, block=True)
    pool.ConnectionCls = NoNetworkConnection
    connection = pool._get_conn(timeout=0)
    assert connection.sock is None and pool.pool.qsize() == 0
    reader = Reader(native)
    response = HTTPResponse(body=reader, preload_content=False, pool=pool, connection=connection)
    state.pool, state.connection, state.reader, state.response = pool, connection, reader, response

    def unexpected_timer(*args, **kwargs):
        pytest.fail("unconnected file-backed response must not start a watchdog")

    patch_module_attribute(monkeypatch, _body, "threading", "Timer", unexpected_timer)

    def run():
        with _body.response_body(response, 10, clock=lambda: 0):
            assert response.read(4) == payload[:4]

    state.run = run
    try:
        yield state
    finally:
        if not reader.closed:
            io.BufferedReader.close(reader)
        pool.close()
        connection.close()
        assert path.read_bytes() == payload


@pytest.mark.parametrize("cleanup", [OSError, KeyboardInterrupt, SystemExit])
def test_interrupted_close_returns_pool_slot(leased, cleanup):
    leased.cleanup = cleanup("after native response file close")
    expected = HttpError if cleanup is OSError else cleanup
    with pytest.raises(expected) as failure:
        leased.run()
    if cleanup is not OSError:
        assert failure.value is leased.cleanup
    assert leased.closes == 1 and leased.reader.closed and leased.native.closed
    with pytest.raises(OSError) as caught:
        os.fstat(leased.descriptor)
    assert caught.value.errno == errno.EBADF
    assert leased.pool.pool.qsize() == 1
    assert leased.response._connection is None
    assert leased.connection.sock is None
    assert leased.connection_closes == [leased.connection]
    assert leased.pool.pool.queue[0] is None
    # A zero-timeout lease succeeds without connecting, rather than leaving
    # the only capacity slot permanently unavailable after the failed close.
    replacement = leased.pool._get_conn(timeout=0)
    try:
        assert replacement is not leased.connection and replacement.sock is None
    finally:
        leased.pool._put_conn(replacement)


def test_healthy_close_keeps_queue_capacity(leased):
    leased.run()
    assert leased.closes == 1 and leased.reader.closed and leased.native.closed
    assert leased.response._connection is None
    assert leased.pool.pool.qsize() == 1
