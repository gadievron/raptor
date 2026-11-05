"""Captive upstream retains socket/thread ownership on lifecycle failures."""

from contextlib import suppress
import socket
import threading
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from core.llm.tests import mock_upstream as module


def _model():
    server = module.MockUpstream.__new__(module.MockUpstream)
    server._stop = threading.Event()
    server._lock = threading.Lock()
    server._listener = Mock()
    server._accept_thread = Mock(ident=1)
    server._accept_thread.is_alive.return_value = False
    clients = [Mock(), Mock()]
    server._clients = set(clients)
    workers = [Mock(ident=2), Mock(ident=3)]
    for worker in workers:
        worker.is_alive.return_value = False
    server._threads = workers
    server.mode = "keepalive"
    server.idle_s = 0.01
    server.response_delay_s = 0
    server._bump = lambda name: None
    return server, clients, workers


@pytest.mark.parametrize(
    "stage",
    [
        "event",
        "listener_shutdown",
        "listener_close",
        "accept_join",
        "client_shutdown",
        "client_close",
        "worker_join",
    ],
)
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_shutdown_failure_attempts_remaining_resources(stage, error):
    server, clients, workers = _model()
    target = {
        "event": server._stop.set,
        "listener_shutdown": server._listener.shutdown,
        "listener_close": server._listener.close,
        "accept_join": server._accept_thread.join,
        "client_shutdown": next(iter(server._clients)).shutdown,
        "client_close": next(iter(server._clients)).close,
        "worker_join": workers[0].join,
    }[stage]
    failure = error("injected upstream retirement failure")
    if stage == "event":
        server._stop.set = Mock(side_effect=failure)
    else:
        target.side_effect = failure
    ignored = error is OSError and stage in (
        "listener_shutdown",
        "listener_close",
        "client_shutdown",
        "client_close",
    )
    if ignored:
        server.shutdown()
    else:
        with pytest.raises(error, match="injected upstream retirement failure"):
            server.shutdown()
    server._listener.close.assert_called_once()
    server._accept_thread.join.assert_called_once()
    for client in clients:
        client.shutdown.assert_called_once()
        client.close.assert_called_once()
    for worker in workers:
        worker.join.assert_called_once()


@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_counter_failure_closes_accepted_socket(error):
    server, _, _ = _model()
    left, right = socket.socketpair()
    server._clients = set()
    server._threads = []
    server._listener = SimpleNamespace(accept=lambda: (left, None))
    server._bump = Mock(side_effect=error("injected counter failure"))
    try:
        with pytest.raises(error, match="injected counter failure"):
            server._accept_loop()
        assert left.fileno() == -1, "counter update abandoned accepted socket"
    finally:
        left.close()
        right.close()


@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_handler_close_failure_still_unregisters_client(error):
    server, _, _ = _model()
    raw, peer = socket.socketpair()

    class Client:
        def settimeout(self, timeout):
            raw.settimeout(timeout)

        def close(self):
            raw.close()
            raise error("injected handler close failure")

    client = Client()
    server._clients = {client}
    server._read_request = lambda conn: None
    try:
        if error is OSError:
            server._handle(client)
        else:
            with pytest.raises(error, match="injected handler close failure"):
                server._handle(client)
        assert client not in server._clients, "closed client remained registered"
        assert raw.fileno() == -1
    finally:
        raw.close()
        peer.close()


@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_constructor_post_start_failure_joins_real_acceptor(error, monkeypatch):
    real_socket, real_thread = socket.socket, threading.Thread
    listeners, workers = [], []
    entered, release = threading.Event(), threading.Event()

    class Listener:
        def __init__(self, *args, **kwargs):
            self.sock = real_socket(*args, **kwargs)
            listeners.append(self.sock)

        def __getattr__(self, name):
            return getattr(self.sock, name)

        def accept(self):
            entered.set()
            release.wait(3)
            return self.sock.accept()

        def shutdown(self, how):
            release.set()
            self.sock.shutdown(how)

    def thread(*args, **kwargs):
        worker = real_thread(*args, **kwargs)
        start = worker.start

        def start_then_raise():
            start()
            assert entered.wait(2)
            raise error("injected upstream post-start failure")

        worker.start = start_then_raise
        workers.append(worker)
        return worker

    sockets = SimpleNamespace(**vars(socket))
    sockets.socket = Listener
    threads = SimpleNamespace(**vars(threading))
    threads.Thread = thread
    try:
        with monkeypatch.context() as patcher:
            patcher.setattr(module, "socket", sockets)
            patcher.setattr(module, "threading", threads)
            with pytest.raises(error, match="injected upstream post-start failure"):
                module.MockUpstream()
        assert workers and not workers[0].is_alive(), "acceptor escaped failed setup"
        assert all(listener.fileno() == -1 for listener in listeners)
    finally:
        release.set()
        for listener in listeners:
            with suppress(OSError):
                listener.shutdown(socket.SHUT_RDWR)
            listener.close()
        for worker in workers:
            worker.join(3)


@pytest.mark.parametrize("direction", ["read", "write"])
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_handler_post_start_failure_joins_real_worker(direction, error, monkeypatch):
    server, _, _ = _model()
    left, right = socket.socketpair()
    entered = threading.Event()
    workers = []
    real_thread = threading.Thread
    server._clients, server._threads = set(), []
    server._listener = SimpleNamespace(accept=lambda: (left, None))

    def read(conn):
        if direction == "write":
            return b"GET / HTTP/1.1\r\n\r\n"
        entered.set()
        return conn.recv(1) or None

    def respond(conn):
        conn.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
        entered.set()
        conn.sendall(b"x" * (8 * 1024 * 1024))

    server._read_request, server._respond = read, respond

    def thread(*args, **kwargs):
        worker = real_thread(*args, **kwargs)
        start, join = worker.start, worker.join
        worker.join_attempted = False

        def start_then_raise():
            start()
            assert entered.wait(2)
            raise error("injected handler post-start failure")

        def joined(*args, **kwargs):
            worker.join_attempted = True
            return join(*args, **kwargs)

        worker.start, worker.join = start_then_raise, joined
        workers.append(worker)
        return worker

    threads = SimpleNamespace(**vars(threading))
    threads.Thread = thread
    try:
        with monkeypatch.context() as patcher:
            patcher.setattr(module, "threading", threads)
            with pytest.raises(error, match="injected handler post-start failure"):
                server._accept_loop()
        assert workers and workers[0].join_attempted, "partial handler was never joined"
        assert not workers[0].is_alive()
        assert left.fileno() == -1
        assert not server._clients
    finally:
        with suppress(OSError):
            right.shutdown(socket.SHUT_RDWR)
        for worker in workers:
            real_thread.join(worker, 3)
        left.close()
        right.close()


def test_normal_shutdown_attempts_all_owned_resources():
    server, clients, workers = _model()
    server.shutdown()
    for client in clients:
        client.close.assert_called_once()
    for worker in workers:
        worker.join.assert_called_once()
