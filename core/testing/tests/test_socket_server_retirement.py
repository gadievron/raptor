"""SocketServer retains ownership through startup and complete retirement."""

from contextlib import suppress
import socket
import threading
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from core.sandbox.tests import socket_server as module


@pytest.mark.parametrize("stage", ["Event", "Lock", "Thread", "settimeout", "start"])
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_constructor_failure_closes_listener(stage, error, monkeypatch):
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    retained = listener
    failure = error("injected constructor failure")
    threads = SimpleNamespace(**vars(threading))
    fake_thread = Mock(ident=None)
    threads.Thread = Mock(return_value=fake_thread)
    if stage in ("Event", "Lock", "Thread"):
        setattr(threads, stage, Mock(side_effect=failure))
    elif stage == "start":
        fake_thread.start.side_effect = failure
    else:
        class Listener:
            def settimeout(self, value):
                raise failure

            def close(self):
                retained.close()

            def shutdown(self, how):
                retained.shutdown(how)
        listener = Listener()
    try:
        with monkeypatch.context() as patcher:
            patcher.setattr(module, "threading", threads)
            with pytest.raises(error, match="injected constructor failure"):
                module.SocketServer(listener, lambda conn: None)
        assert retained.fileno() == -1, "constructor left listener open"
    finally:
        retained.close()


def _model_server():
    server = module.SocketServer.__new__(module.SocketServer)
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
    return server, clients, workers


@pytest.mark.parametrize("stage", ["listener_close", "accept_join", "client_close", "worker_join"])
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_close_failure_still_retires_other_resources(stage, error):
    server, clients, workers = _model_server()
    failing = {
        "listener_close": server._listener.close,
        "accept_join": server._accept_thread.join,
        "client_close": next(iter(server._clients)).close,
        "worker_join": workers[0].join,
    }[stage]
    failure = error("injected retirement failure")
    failing.side_effect = failure
    with pytest.raises(error, match="injected retirement failure"):
        server.close()
    assert server._stop.is_set()
    server._listener.close.assert_called_once()
    server._accept_thread.join.assert_called_once()
    for client in clients:
        client.shutdown.assert_called_once()
        client.close.assert_called_once()
    for worker in workers:
        worker.join.assert_called_once()


@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_serve_close_failure_still_unregisters_client(error):
    server, clients, _ = _model_server()
    client = clients[0]
    client.close.side_effect = error("injected client close failure")
    server._handler = lambda conn: None
    with pytest.raises(error, match="injected client close failure"):
        server._serve(client)
    assert client not in server._clients


@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_constructor_start_then_raise_joins_real_acceptor(error, monkeypatch):
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    entered, release = threading.Event(), threading.Event()
    real_thread = threading.Thread
    started = []

    class Listener:
        def settimeout(self, value):
            listener.settimeout(value)

        def accept(self):
            entered.set()
            release.wait(3)
            return listener.accept()

        def shutdown(self, how):
            release.set()
            listener.shutdown(how)

        def close(self):
            listener.close()

    def thread(*args, **kwargs):
        worker = real_thread(*args, **kwargs)
        start = worker.start

        def start_then_raise():
            start()
            assert entered.wait(2)
            raise error("injected post-start failure")
        worker.start = start_then_raise
        started.append(worker)
        return worker

    try:
        with monkeypatch.context() as patcher:
            patcher.setattr(module, "threading", SimpleNamespace(**(vars(threading) | {"Thread": thread})))
            with pytest.raises(error, match="injected post-start failure"):
                module.SocketServer(Listener(), lambda conn: None)
        assert started and not started[0].is_alive(), "acceptor escaped failed setup"
        assert listener.fileno() == -1
    finally:
        release.set()
        listener.close()
        for worker in started:
            worker.join(3)


@pytest.mark.parametrize("direction", ["read", "write"])
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_handler_start_then_raise_joins_real_worker(direction, error, monkeypatch):
    server, _, _ = _model_server()
    left, right = socket.socketpair()
    entered = threading.Event()
    real_thread = threading.Thread
    started = []
    server._clients = set()
    server._threads = []
    server._listener = SimpleNamespace(accept=lambda: (left, None))

    def handler(conn):
        conn.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
        entered.set()
        if direction == "read":
            conn.recv(1)
        else:
            conn.sendall(b"x" * (8 * 1024 * 1024))

    server._handler = handler

    def thread(*args, **kwargs):
        worker = real_thread(*args, **kwargs)
        start = worker.start

        def start_then_raise():
            start()
            assert entered.wait(2)
            raise error("injected post-start failure")
        worker.start = start_then_raise
        started.append(worker)
        return worker

    try:
        with monkeypatch.context() as patcher:
            patcher.setattr(module, "threading", SimpleNamespace(**(vars(threading) | {"Thread": thread})))
            with pytest.raises(error, match="injected post-start failure"):
                server._accept()
        assert started and not started[0].is_alive(), "handler escaped failed setup"
        assert left.fileno() == -1
        assert not server._clients
    finally:
        with suppress(OSError):
            right.shutdown(socket.SHUT_RDWR)
        for worker in started:
            worker.join(3)
        left.close()
        right.close()


def test_normal_close_retires_every_resource():
    server, clients, workers = _model_server()
    server.close()
    assert server._stop.is_set()
    for client in clients:
        client.close.assert_called_once()
    for worker in workers:
        worker.join.assert_called_once()


@pytest.mark.parametrize("stage", ["listener", "client"])
def test_interrupted_shutdown_still_attempts_remaining_cleanup(stage):
    server, clients, workers = _model_server()
    target = server._listener if stage == "listener" else next(iter(server._clients))
    target.shutdown.side_effect = KeyboardInterrupt("interrupted shutdown")
    with pytest.raises(KeyboardInterrupt, match="interrupted shutdown"):
        server.close()
    server._listener.close.assert_called_once()
    server._accept_thread.join.assert_called_once()
    for client in clients:
        client.close.assert_called_once()
    for worker in workers:
        worker.join.assert_called_once()
