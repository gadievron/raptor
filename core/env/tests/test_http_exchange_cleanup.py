"""HTTP response lifetime controls with ordinary files, no socket or thread."""
import http.client
import io
import socket
from types import SimpleNamespace

import pytest

from core.env import verify
from core.testing.module_bindings import patch_module_attribute


@pytest.fixture
def exchange(tmp_path, monkeypatch):
    path = tmp_path / 'response.http'
    body = b'0123456789abcdef' * 2
    path.write_bytes(b'HTTP/1.1 200 OK\r\nContent-Length: 32\r\n\r\n' + body)
    state = SimpleNamespace(primary=None, cleanup=None, opened=[], readers=[],
                            responses=[], connections=[], timers=[], sent=[], reads=[],
                            transport_closes=0, native_closes=0, shutdowns=[],
                            fire_watchdog=False, response_error=None)

    class Reader(io.BufferedReader):
        def read1(self, size=-1):
            data = super().read1(size)
            state.reads.append((size, data))
            if state.primary is not None:
                raise state.primary
            return data

        def close(self):
            if self.closed:
                return super().close()
            super().close()
            state.native_closes += 1
            if state.cleanup is not None:
                raise state.cleanup

    class Transport:
        def sendall(self, data):
            state.sent.append(bytes(data))

        def makefile(self, mode):
            assert mode == 'rb'
            native = path.open(mode)
            state.opened.append(native)
            reader = Reader(native)
            state.readers.append(reader)
            return reader

        def shutdown(self, how):
            state.shutdowns.append(how)

        def close(self):
            state.transport_closes += 1

    class Connection(http.client.HTTPConnection):
        def __init__(self, host, port, *, timeout):
            assert (host, port, timeout) == ('owned.invalid', 80, 1.0)
            super().__init__(host, port, timeout=timeout)
            state.connections.append(self)

        def connect(self):
            self.sock = Transport()

        def getresponse(self):
            response = super().getresponse()
            state.responses.append(response)
            if state.fire_watchdog:
                state.timers[0].callback()
            if state.response_error is not None:
                raise state.response_error
            return response

    class Timer:
        def __init__(self, interval, callback):
            self.interval = interval
            self.callback = callback
            self.started = self.cancelled = False
            state.timers.append(self)

        def start(self):
            self.started = True

        def cancel(self):
            self.cancelled = True

    patch_module_attribute(monkeypatch, verify, 'http.client', 'HTTPConnection', Connection)
    patch_module_attribute(monkeypatch, verify, 'threading', 'Timer', Timer)
    state.run = lambda: verify._http_exchange(host_ip='owned.invalid', host_port=80,
        method='GET', path='/', timeout_seconds=1.0, max_response_bytes=4)
    try:
        yield state
    finally:
        for reader in state.readers:
            if not reader.closed:
                io.BufferedReader.close(reader)


def assert_retired(state, *, body_read=True):
    assert state.native_closes == len(state.opened) == len(state.responses) == 1
    assert all(f.closed for f in state.opened + state.readers)
    assert state.responses[0].fp is None
    assert state.connections[0].sock is None
    assert state.connections[0]._HTTPConnection__response is None
    assert state.transport_closes == 1
    assert state.reads == ([(4, b'0123')] if body_read else [])
    assert state.sent and state.sent[0].startswith(b'GET / HTTP/1.1\r\n')
    assert len(state.timers) == 1
    assert state.timers[0].started and state.timers[0].cancelled
    assert state.timers[0].daemon is True and state.timers[0].interval == 2.0


@pytest.mark.parametrize('primary_type', [OSError, ValueError, KeyboardInterrupt, SystemExit, http.client.HTTPException])
@pytest.mark.parametrize('cleanup_type', [OSError, MemoryError])
def test_primary_native_body_read_failure_survives_close(exchange, primary_type, cleanup_type):
    exchange.primary = primary_type('after native HTTP body read')
    exchange.cleanup = cleanup_type('after native response file close')
    with pytest.raises(primary_type) as caught:
        exchange.run()
    assert caught.value is exchange.primary
    assert_retired(exchange)


@pytest.mark.parametrize('cleanup_type', [OSError, KeyboardInterrupt])
def test_fresh_close_error_after_capped_success_remains_visible(exchange, cleanup_type):
    exchange.cleanup = cleanup_type('fresh native response close failure')
    with pytest.raises(cleanup_type) as caught:
        exchange.run()
    assert caught.value is exchange.cleanup
    assert_retired(exchange)


def test_real_http_parser_keeps_capped_success(exchange):
    assert exchange.run() == (200, b'0123')
    assert_retired(exchange)


@pytest.mark.parametrize('cleanup_type', [None, OSError, KeyboardInterrupt])
def test_watchdog_transformed_error_keeps_original_cause(exchange, cleanup_type):
    exchange.fire_watchdog = True
    exchange.response_error = OSError('after native HTTP response begin')
    exchange.cleanup = cleanup_type('after native response close') if cleanup_type else None
    with pytest.raises(TimeoutError, match='watchdog') as caught:
        exchange.run()
    assert caught.value.__cause__ is exchange.response_error
    assert exchange.shutdowns == [socket.SHUT_RDWR]
    assert_retired(exchange, body_read=False)
