"""Captive socket backends release threads even while clients remain open."""

import socket
import threading

import pytest

from core.sandbox.tests.socket_server import SocketServer


@pytest.fixture(params=["tcp", "unix"])
def listener(request, short_sock_dir):
    if request.param == "unix" and not hasattr(socket, "AF_UNIX"):
        pytest.skip("Unix sockets unavailable")
    family = socket.AF_INET if request.param == "tcp" else socket.AF_UNIX
    address = (("127.0.0.1", 0) if request.param == "tcp"
               else str(short_sock_dir / "backend.sock"))
    with socket.socket(family, socket.SOCK_STREAM) as sock:
        sock.bind(address)
        sock.listen(8)
        yield sock


def _connect(listener):
    client = socket.socket(listener.family, socket.SOCK_STREAM)
    try:
        client.settimeout(5)
        client.connect(listener.getsockname())
    except BaseException:
        client.close()
        raise
    return client


def _assert_stopped(server):
    assert not server._accept_thread.is_alive()
    assert all(not t.is_alive() for t in server._threads)
    assert not server._clients


def test_idle_close_is_idempotent(listener):
    with SocketServer(listener, lambda conn: None) as server:
        server.close()
        _assert_stopped(server)
        server.close()
        _assert_stopped(server)


def test_close_wakes_blocked_readers(listener):
    ready = [threading.Event(), threading.Event()]
    accepted = iter(ready)
    lock = threading.Lock()

    def read(conn):
        with lock:
            event = next(accepted)
        event.set()
        conn.recv(1)

    with SocketServer(listener, read) as server:
        with _connect(listener), _connect(listener):
            assert all(event.wait(5) for event in ready), "readers did not start"
            server.close()
            _assert_stopped(server)


def test_close_wakes_blocked_writer(listener):
    ready = threading.Event()

    def write(conn):
        conn.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
        ready.set()
        conn.sendall(b"x" * (8 * 1024 * 1024))

    with SocketServer(listener, write) as server:
        with _connect(listener) as client:
            client.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
            assert ready.wait(5), "writer did not start"
            server.close()
            _assert_stopped(server)


@pytest.mark.parametrize("fault", ["thread-construction", "thread-start"])
def test_failed_startup_closes_listener(listener, monkeypatch, fault):
    from types import SimpleNamespace
    from core.sandbox.tests import socket_server

    class StartFailure(threading.Thread):
        def start(self):
            raise RuntimeError("injected thread-start failure")

    def thread(*args, **kwargs):
        if fault == "thread-construction":
            raise RuntimeError("injected thread-construction failure")
        return StartFailure(*args, **kwargs)

    with monkeypatch.context() as patcher:
        patcher.setattr(socket_server, "threading", SimpleNamespace(
            Event=threading.Event, Lock=threading.Lock, Thread=thread,
        ))
        with pytest.raises(RuntimeError, match="injected .* failure"):
            SocketServer(listener, lambda conn: None)
    assert listener.fileno() == -1, "failed startup left its listener open"


@pytest.mark.parametrize("fault", ["construction", "start"])
def test_failed_handler_start_releases_connection(listener, monkeypatch, fault):
    from types import SimpleNamespace
    from core.sandbox.tests import socket_server

    finished = threading.Event()
    errors = []
    connections = []
    real_thread = threading.Thread

    class StartFailure(real_thread):
        def start(self):
            raise RuntimeError("injected handler start failure")

    def thread(*args, **kwargs):
        if "args" not in kwargs:
            return real_thread(*args, **kwargs)  # The real accept loop.
        connections.append(kwargs["args"][0])
        if fault == "construction":
            raise RuntimeError("injected handler construction failure")
        return StartFailure(*args, **kwargs)

    class ObservedServer(SocketServer):
        def _accept(self):
            try:
                super()._accept()
            except RuntimeError as error:
                errors.append(str(error))
            finally:
                finished.set()

    with monkeypatch.context() as patcher:
        patcher.setattr(socket_server, "threading", SimpleNamespace(
            Event=threading.Event, Lock=threading.Lock, Thread=thread,
        ))
        server = ObservedServer(listener, lambda conn: None)
        try:
            with _connect(listener):
                assert finished.wait(5), "accept loop did not report injected failure"
                assert errors == [f"injected handler {fault} failure"]
                assert len(connections) == 1
                assert connections[0].fileno() == -1, "failed handler left its socket open"
                assert not server._clients
                assert not server._threads, "unstarted handler remained registered"
                server.close()
                _assert_stopped(server)
        finally:
            # Independent cleanup keeps the regression contained on an unfixed tree.
            for conn in connections:
                conn.close()
            listener.close()
            server._accept_thread.join(timeout=5)
