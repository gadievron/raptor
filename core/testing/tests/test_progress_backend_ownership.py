"""Progress and keepalive test backends retain ownership through setup."""

from contextlib import suppress
import socket
import threading
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from core.sandbox.tests import socket_server as support
from core.sandbox.tests import test_proxy_progress_cap as progress
from core.sandbox.tests import test_proxy_tcp_keepalive as keepalive


CALLERS = ["test_tunnel_with_steady_progress_survives_past_old_cap",
           "test_stalled_tunnel_still_dies_at_idle"]


@pytest.mark.parametrize("name", CALLERS)
@pytest.mark.parametrize("stage", ["proxy", "stop", "client", "handshake"])
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_progress_caller_retires_backend_and_client(name, stage, error, monkeypatch):
    listener = Mock()
    owner = Mock()
    owner.close.side_effect = listener.close
    owner.join.side_effect = lambda **kwargs: owner.close()
    proxy = Mock(port=2)
    client = Mock()
    failure = error("injected progress caller failure")
    if stage == "stop":
        proxy.stop.side_effect = failure
    client.settimeout.side_effect = failure
    with monkeypatch.context() as patcher:
        patcher.setattr(progress, "_echo_upstream", lambda: (listener, 1, owner))
        patcher.setattr(progress.proxy_mod, "EgressProxy", Mock(
            side_effect=failure if stage == "proxy" else None, return_value=proxy,
        ))
        patcher.setattr(progress, "_connect_through", Mock(
            side_effect=failure if stage in ("stop", "handshake") else None,
            return_value=client,
        ))
        with pytest.raises(error, match="injected progress caller failure"):
            getattr(progress, name)(patcher)
    assert listener.close.called, "backend listener leaked"
    owner.close.assert_called_once()
    if stage != "proxy":
        proxy.stop.assert_called_once()
    if stage == "client":
        client.close.assert_called_once()


@pytest.mark.parametrize("kind", ["progress", "keepalive"])
@pytest.mark.parametrize("stage", ["bind", "listen", "getsockname", "server"])
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_backend_setup_failure_closes_listener(kind, stage, error, monkeypatch):
    module = progress if kind == "progress" else keepalive
    listener = socket.socket()
    failure = error("injected backend setup failure")
    reached = []

    def fail(*args, **kwargs):
        reached.append(stage)
        raise failure

    class Listener:
        def __getattr__(self, name):
            return fail if name == stage else getattr(listener, name)

        def close(self):
            listener.close()

    def server(*args, **kwargs):
        assert stage == "server", "selected native setup fault was not reached"
        fail()

    sockets = SimpleNamespace(**vars(socket))
    sockets.socket = lambda *a, **kw: Listener()
    try:
        with monkeypatch.context() as patcher:
            patcher.setattr(module, "socket", sockets)
            patcher.setattr(module, "SocketServer", server, raising=False)
            with pytest.raises(error, match="injected backend setup failure"):
                if kind == "progress":
                    progress._echo_upstream()
                else:
                    keepalive.test_established_tunnel_enables_keepalive_on_both_legs(patcher)
        assert reached == [stage], "selected setup fault was not exercised"
        assert listener.fileno() == -1, "backend setup left listener open"
    finally:
        listener.close()


@pytest.mark.parametrize("stage", ["proxy", "stop", "client"])
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_keepalive_caller_releases_listener_and_client(stage, error, monkeypatch):
    listener = socket.socket()
    client = Mock()
    failure = error("injected keepalive caller failure")
    proxy = Mock(port=2)
    if stage == "stop":
        proxy.stop.side_effect = failure
    client.sendall.side_effect = failure
    sockets = SimpleNamespace(**vars(socket))

    class Listener:
        def bind(self, address):
            listener.bind(address)

        def listen(self, backlog):
            listener.listen(backlog)

        def getsockname(self):
            return listener.getsockname()

        def close(self):
            listener.close()

    sockets.socket = lambda *a, **kw: Listener()
    sockets.create_connection = Mock(side_effect=failure if stage == "stop" else None,
                                     return_value=client)
    server = Mock()
    server.close.side_effect = listener.close
    try:
        with monkeypatch.context() as patcher:
            patcher.setattr(keepalive, "socket", sockets)
            patcher.setattr(keepalive, "SocketServer", Mock(return_value=server), raising=False)
            patcher.setattr(threading, "Thread", Mock(return_value=Mock(ident=None)))
            patcher.setattr(progress.proxy_mod, "EgressProxy", Mock(
                side_effect=failure if stage == "proxy" else None, return_value=proxy,
            ))
            with pytest.raises(error, match="injected keepalive caller failure"):
                keepalive.test_established_tunnel_enables_keepalive_on_both_legs(patcher)
        assert listener.fileno() == -1, "keepalive caller leaked listener"
        if stage == "client":
            client.close.assert_called_once()
    finally:
        listener.close()


@pytest.mark.parametrize("stage,error", [
    ("sendall", OSError), ("sendall", KeyboardInterrupt),
    ("recv", OSError), ("recv", KeyboardInterrupt),
    ("eof", AssertionError), ("status", AssertionError), ("none", None),
])
def test_progress_handshake_owns_failed_clients(stage, error, monkeypatch):
    owned = socket.socket()

    class Client:
        def sendall(self, data):
            if stage == "sendall":
                raise error("injected handshake failure")

        def recv(self, size):
            if stage == "recv":
                raise error("injected handshake failure")
            return b"" if stage == "eof" else (
                b"HTTP/1.1 502 Failed\r\n\r\n" if stage == "status"
                else b"HTTP/1.1 200 OK\r\n\r\n"
            )

        def close(self):
            owned.close()

    client = Client()
    sockets = SimpleNamespace(**vars(socket))
    sockets.create_connection = lambda *a, **kw: client
    try:
        with monkeypatch.context() as patcher:
            patcher.setattr(progress, "socket", sockets)
            if error is None:
                assert progress._connect_through(SimpleNamespace(port=1), 2) is client
                assert owned.fileno() != -1
            else:
                with pytest.raises(error):
                    progress._connect_through(SimpleNamespace(port=1), 2)
                assert owned.fileno() == -1, "failed handshake leaked client"
    finally:
        owned.close()


@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_progress_start_then_raise_retires_real_acceptor(error, monkeypatch):
    real_socket, real_thread = socket.socket, threading.Thread
    listeners, workers = [], []
    entered = threading.Event()

    class Listener:
        def __init__(self):
            self.sock = real_socket()
            listeners.append(self.sock)

        def __getattr__(self, name):
            return getattr(self.sock, name)

        def accept(self):
            entered.set()
            return self.sock.accept()

    def thread(*args, **kwargs):
        worker = real_thread(*args, **kwargs)
        start = worker.start

        def start_then_raise():
            start()
            assert entered.wait(2)
            raise error("injected progress post-start failure")
        worker.start = start_then_raise
        workers.append(worker)
        return worker

    sockets = SimpleNamespace(**vars(socket))
    sockets.socket = lambda *a, **kw: Listener()
    threads = SimpleNamespace(**vars(threading))
    threads.Thread = thread
    try:
        with monkeypatch.context() as patcher:
            patcher.setattr(progress, "socket", sockets)
            patcher.setattr(progress, "threading", threads)
            patcher.setattr(support, "threading", threads)
            with pytest.raises(error, match="injected progress post-start failure"):
                progress._echo_upstream()
        assert workers and not workers[0].is_alive(), "acceptor escaped failed setup"
        assert listeners[0].fileno() == -1
    finally:
        for listener in listeners:
            with suppress(OSError):
                listener.shutdown(socket.SHUT_RDWR)
            listener.close()
        for worker in workers:
            worker.join(3)


@pytest.mark.parametrize("connected", [False, True])
def test_real_progress_backend_retires_idle_and_connected_workers(connected):
    listener, port, server = progress._echo_upstream()
    client = None
    try:
        if connected:
            client = socket.create_connection(("127.0.0.1", port), timeout=2)
            client.sendall(b"payload")
            echoed = b""
            while len(echoed) < len(b"payload"):
                chunk = client.recv(7)
                assert chunk
                echoed += chunk
            assert echoed == b"payload"
        server.close()
        assert listener.fileno() == -1
        assert not server._accept_thread.is_alive()
        assert all(not worker.is_alive() for worker in server._threads)
        assert not server._clients
        if connected:
            assert client.recv(1) == b""
    finally:
        if client is not None:
            client.close()
        server.close()


@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_real_keepalive_backend_retires_after_proxy_setup_failure(error, monkeypatch):
    real_server = keepalive.SocketServer
    servers = []

    def server(*args, **kwargs):
        owned = real_server(*args, **kwargs)
        servers.append(owned)
        return owned

    try:
        with monkeypatch.context() as patcher:
            patcher.setattr(keepalive, "SocketServer", server)
            patcher.setattr(progress.proxy_mod, "EgressProxy", Mock(
                side_effect=error("injected proxy construction failure"),
            ))
            with pytest.raises(error, match="injected proxy construction failure"):
                keepalive.test_established_tunnel_enables_keepalive_on_both_legs(patcher)
        assert len(servers) == 1
        assert servers[0]._listener.fileno() == -1
        assert not servers[0]._accept_thread.is_alive()
    finally:
        for owned in servers:
            owned.close()
