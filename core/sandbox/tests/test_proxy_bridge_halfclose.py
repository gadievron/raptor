"""Relay EOF in one direction must leave the reverse direction usable."""

from contextlib import contextmanager
import errno
import os
import socket
import threading

import pytest

from core.testing.module_bindings import patch_module_attribute

from core.sandbox import _proxy_bridge as bridge
from core.sandbox.tests.socket_server import SocketServer


def receive_all(conn):
    data = bytearray()
    while chunk := conn.recv(4096):
        data.extend(chunk)
    return bytes(data)


@contextmanager
def running_bridge(short_sock_dir, handler):
    path = str(short_sock_dir / "upstream.sock")
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(path)
    listener.listen()
    server = SocketServer(listener, handler)
    ready = threading.Event()
    ports, errors = [], []
    death_r, death_w = os.pipe()

    def on_ready(bound):
        ports.append(bound[0][0])
        ready.set()

    def run():
        try:
            bridge._run_bridges([(0, path)], death_r, on_ready)
        except BaseException as exc:
            errors.append(exc)

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    try:
        assert ready.wait(5), errors
        yield ports[0], thread
    finally:
        os.close(death_w)
        thread.join(5)
        os.close(death_r)
        server.close()
    assert not thread.is_alive()
    assert not errors


@pytest.mark.parametrize("force_pending", [None, "request", "reply"])
def test_request_eof_is_delivered_before_reply(short_sock_dir, monkeypatch, force_pending):
    payload = bytes(range(256)) * 128
    received = []

    def reply(conn):
        conn.settimeout(5)
        request = receive_all(conn)
        received.append(request)
        conn.sendall(b"reply:" + request)

    allow_drain = threading.Event()
    partial = []
    real_read, real_write = os.read, os.write

    with running_bridge(short_sock_dir, reply) as (port, relay):
        def read(fd, size):
            data = real_read(fd, size)
            if (threading.current_thread() is relay and not data
                    and (force_pending == "request" or partial)):
                allow_drain.set()
            return data

        def write(fd, data):
            should_queue = force_pending == "request" or partial or bytes(data).startswith(b"reply:")
            if (threading.current_thread() is relay and should_queue
                    and not allow_drain.is_set()):
                if not partial:
                    partial.append(True)
                    return real_write(fd, data[:7])
                raise BlockingIOError(errno.EAGAIN, "forced backpressure")
            return real_write(fd, data)

        if force_pending:
            patch_module_attribute(monkeypatch, bridge, 'os', "read", read)
            patch_module_attribute(monkeypatch, bridge, 'os', "write", write)
        with socket.create_connection(("127.0.0.1", port), timeout=5) as client:
            client.sendall(payload)
            client.shutdown(socket.SHUT_WR)
            assert receive_all(client) == b"reply:" + payload
        assert received == [payload]
        if force_pending:
            assert partial
            assert allow_drain.is_set()


def test_upstream_eof_does_not_prevent_later_client_writes(short_sock_dir):
    finished = threading.Event()
    received = []
    payload = b"request after upstream EOF"

    def upstream(conn):
        conn.settimeout(5)
        conn.sendall(b"ready")
        conn.shutdown(socket.SHUT_WR)
        received.append(receive_all(conn))
        finished.set()

    with running_bridge(short_sock_dir, upstream) as (port, _):
        with socket.create_connection(("127.0.0.1", port), timeout=5) as client:
            assert receive_all(client) == b"ready"
            client.sendall(payload)
            client.shutdown(socket.SHUT_WR)
            assert finished.wait(5)
    assert received == [payload]


def test_half_closed_pair_still_obeys_idle_timeout(short_sock_dir, monkeypatch):
    eof_seen, release = threading.Event(), threading.Event()

    def upstream(conn):
        conn.settimeout(5)
        receive_all(conn)
        eof_seen.set()
        assert release.wait(5)

    monkeypatch.setattr(bridge, "_PAIR_IDLE_TIMEOUT_S", 0.05)
    monkeypatch.setattr(bridge, "_SELECT_TIMEOUT", 0.01)
    try:
        with running_bridge(short_sock_dir, upstream) as (port, _):
            with socket.create_connection(("127.0.0.1", port), timeout=2) as client:
                client.shutdown(socket.SHUT_WR)
                assert eof_seen.wait(2)
                assert client.recv(1) == b""
                release.set()
    finally:
        release.set()
