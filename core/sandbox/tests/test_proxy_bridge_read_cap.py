"""A small relay buffer cap bounds reads without truncating traffic."""

import os
import socket
import threading

from core.sandbox import _proxy_bridge as bridge
from core.sandbox.tests.socket_server import SocketServer


def test_small_buffer_cap_preserves_large_roundtrip(short_sock_dir, monkeypatch):
    path = str(short_sock_dir / "echo.sock")
    upstream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    upstream.bind(path)
    upstream.listen()

    def echo(conn):
        with conn:
            while data := conn.recv(4096):
                conn.sendall(data)

    server = SocketServer(upstream, echo)
    ready = threading.Event()
    ports = []
    errors = []
    read_sizes = []
    real_read = os.read
    cap = 31

    def tracked_read(fd, size):
        if threading.current_thread() is thread:
            read_sizes.append(size)
        return real_read(fd, size)

    def on_ready(bound):
        ports.append(bound[0][0])
        ready.set()

    death_r, death_w = os.pipe()

    def run():
        try:
            bridge._run_bridges([(0, path)], death_r, on_ready)
        except BaseException as exc:
            errors.append(exc)

    monkeypatch.setattr(bridge, "_MAX_PENDING_BYTES", cap)
    monkeypatch.setattr(bridge.os, "read", tracked_read)
    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    try:
        assert ready.wait(5), errors
        payload = bytes(range(256)) * 16
        with socket.create_connection(("127.0.0.1", ports[0]), timeout=5) as client:
            client.sendall(payload)
            received = bytearray()
            while len(received) < len(payload):
                chunk = client.recv(len(payload) - len(received))
                assert chunk, "relay truncated the payload"
                received.extend(chunk)
        assert bytes(received) == payload
        assert read_sizes
        assert max(read_sizes) <= cap
    finally:
        os.close(death_w)
        thread.join(5)
        os.close(death_r)
        server.close()
    assert not thread.is_alive()
    assert not errors
