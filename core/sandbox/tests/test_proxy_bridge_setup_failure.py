"""Transient upstream socket setup failures do not stop the bridge."""

import errno
import os
import socket
import threading

import pytest

from core.testing.module_bindings import patch_module_attribute

from core.sandbox import _proxy_bridge as bridge
from core.sandbox.tests.socket_server import SocketServer

@pytest.fixture(autouse=True)
def _owned_backends(monkeypatch):
    import sys
    from core.testing.sockets import isolated_socket_servers

    with isolated_socket_servers(sys.modules[__name__], monkeypatch):
        yield



def test_upstream_socket_exhaustion_allows_later_connection(
    short_sock_dir, monkeypatch,
):
    path = str(short_sock_dir / "upstream.sock")
    real_socket = socket.socket
    upstream = real_socket(socket.AF_UNIX, socket.SOCK_STREAM)
    upstream.bind(path)
    upstream.listen()

    def echo(conn):
        with conn:
            conn.sendall(conn.recv(1024))

    server = SocketServer(upstream, echo)
    ready = threading.Event()
    ports = []
    errors = []
    attempts = []

    def socket_with_one_failure(family=socket.AF_INET, *args, **kwargs):
        if family == socket.AF_UNIX and threading.current_thread() is thread:
            attempts.append(True)
            if len(attempts) == 1:
                raise OSError(errno.EMFILE, "injected descriptor exhaustion")
        return real_socket(family, *args, **kwargs)

    def on_ready(bound):
        ports.append(bound[0][0])
        ready.set()

    death_r, death_w = os.pipe()

    def run():
        try:
            bridge._run_bridges([(0, path)], death_r, ready_cb=on_ready)
        except BaseException as exc:
            errors.append(exc)

    patch_module_attribute(monkeypatch, bridge, 'socket', "socket", socket_with_one_failure)
    thread = None
    try:
        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        assert ready.wait(5), errors
        with socket.create_connection(("127.0.0.1", ports[0]), timeout=5) as first:
            assert first.recv(1) == b""
        assert thread.is_alive(), errors
        with socket.create_connection(("127.0.0.1", ports[0]), timeout=5) as second:
            second.sendall(b"still serving")
            assert second.recv(1024) == b"still serving"
        assert len(attempts) == 2
    finally:
        os.close(death_w)
        if thread is not None and thread.ident is not None:
            thread.join(5)
            assert not thread.is_alive(), "bridge worker survived cleanup"
        os.close(death_r)
        server.close()
    assert not thread.is_alive()
    assert not errors
