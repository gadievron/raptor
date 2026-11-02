"""Captive socket backends release threads even while clients remain open."""

import socket
import threading

from core.sandbox.tests.socket_server import SocketServer


def _listener():
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(8)
    return listener


def _assert_stopped(server):
    assert not server._accept_thread.is_alive()
    assert all(not t.is_alive() for t in server._threads)
    assert not server._clients


def test_idle_close_is_idempotent():
    with SocketServer(_listener(), lambda conn: None) as server:
        server.close()
        _assert_stopped(server)
        server.close()
        _assert_stopped(server)


def test_close_wakes_blocked_readers():
    ready = [threading.Event(), threading.Event()]
    accepted = iter(ready)
    lock = threading.Lock()

    def read(conn):
        with lock:
            event = next(accepted)
        event.set()
        conn.recv(1)

    listener = _listener()
    with SocketServer(listener, read) as server:
        with socket.create_connection(listener.getsockname(), timeout=5), \
                socket.create_connection(listener.getsockname(), timeout=5):
            assert all(event.wait(5) for event in ready), "readers did not start"
            server.close()
            _assert_stopped(server)


def test_close_wakes_blocked_writer():
    ready = threading.Event()

    def write(conn):
        conn.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
        ready.set()
        conn.sendall(b"x" * (8 * 1024 * 1024))

    listener = _listener()
    with SocketServer(listener, write) as server:
        with socket.create_connection(listener.getsockname(), timeout=5) as client:
            client.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
            assert ready.wait(5), "writer did not start"
            server.close()
            _assert_stopped(server)
