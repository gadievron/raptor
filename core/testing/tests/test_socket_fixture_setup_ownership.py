"""Blocked-worker fixtures acquire sockets only after fallible setup."""
import socket
import threading
from types import SimpleNamespace

import pytest

from core.testing.tests import test_socket_worker_cleanup as native


@pytest.mark.parametrize("kind", ["parser", "usage"])
@pytest.mark.parametrize("fail_at", [1, 2])
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_event_refusal_precedes_owned_socket_acquisition(
    kind, fail_at, error, monkeypatch
):
    endpoints, calls = [], []
    failure = error("event construction refused")
    borrowed_socket, borrowed_threading = native.socket, native.threading

    def pair():
        result = socket.socketpair()
        endpoints.extend(result)
        return result

    def event():
        calls.append(True)
        if len(calls) == fail_at:
            raise failure
        return threading.Event()

    try:
        with monkeypatch.context() as scope:
            scope.setattr(native, "socket", SimpleNamespace(
                **(vars(socket) | {"socketpair": pair})
            ))
            scope.setattr(native, "threading", SimpleNamespace(
                **(vars(threading) | {"Event": event})
            ))
            with pytest.raises(error, match="event construction refused") as caught:
                native.test_kill_wakes_blocked_worker_with_peer_open(kind, monkeypatch)
            assert caught.value is failure
        assert len(calls) == fail_at
        assert not endpoints
        assert native.socket is borrowed_socket
        assert native.threading is borrowed_threading
    finally:
        for endpoint in endpoints:
            endpoint.close()
