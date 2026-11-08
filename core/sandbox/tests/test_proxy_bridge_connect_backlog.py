"""A saturated Unix listener must not park the shared bridge loop."""

from contextlib import ExitStack
import os
import socket
import sys
import threading

import pytest

from core.sandbox import _proxy_bridge as bridge
from core.sandbox.tests.socket_server import SocketServer

@pytest.fixture(autouse=True)
def _owned_backends(monkeypatch):
    import sys
    from core.testing.sockets import isolated_socket_servers

    with isolated_socket_servers(sys.modules[__name__], monkeypatch):
        yield



@pytest.mark.skipif(sys.platform != "linux", reason="Linux AF_UNIX backlog semantics")
def test_full_upstream_queue_does_not_block_other_bridge(short_sock_dir):
    with ExitStack() as cleanup:
        stalled_path = str(short_sock_dir / "stalled.sock")
        healthy_path = str(short_sock_dir / "healthy.sock")
        stalled = cleanup.enter_context(socket.socket(socket.AF_UNIX, socket.SOCK_STREAM))
        stalled.bind(stalled_path)
        stalled.listen(0)
        queued = cleanup.enter_context(socket.socket(socket.AF_UNIX, socket.SOCK_STREAM))
        queued.settimeout(2)
        queued.connect(stalled_path)
        healthy = cleanup.enter_context(socket.socket(socket.AF_UNIX, socket.SOCK_STREAM))
        healthy.bind(healthy_path)
        healthy.listen()

        def echo(conn):
            with conn:
                conn.sendall(conn.recv(1024))

        server = SocketServer(healthy, echo)
        cleanup.callback(server.close)
        ready = threading.Event()
        ports = []
        errors = []
        death_r, death_w = os.pipe()
        cleanup.callback(os.close, death_r)
        writer_cleanup = ExitStack()
        writer_cleanup.callback(os.close, death_w)

        thread = None

        def retire_relay():
            if thread is not None and thread.ident is not None:
                thread.join(5)
                assert not thread.is_alive(), "bridge worker survived cleanup"

        cleanup.callback(retire_relay)

        def drain_upstream():
            # Drain the queued connection even on assertion failure so an
            # unfixed, blocking connect can finish and the test can retire it.
            stalled.settimeout(1)
            try:
                conn, _ = stalled.accept()
                conn.close()
            except OSError:
                pass
            queued.close()
            stalled.close()

        cleanup.callback(drain_upstream)
        cleanup.callback(writer_cleanup.close)

        def on_ready(bound):
            ports.extend(port for port, _ in bound)
            ready.set()

        def run():
            try:
                bridge._run_bridges(
                    [(0, stalled_path), (0, healthy_path)], death_r, on_ready,
                )
            except BaseException as exc:
                errors.append(exc)

        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        assert ready.wait(5), errors
        with socket.create_connection(("127.0.0.1", ports[0]), timeout=2) as client:
            assert client.recv(1) == b""
        with socket.create_connection(("127.0.0.1", ports[1]), timeout=2) as client:
            client.sendall(b"healthy")
            assert client.recv(1024) == b"healthy"
        writer_cleanup.close()
        thread.join(2)
        assert not thread.is_alive(), "bridge shutdown blocked behind connect"
        assert not errors
        cleanup.close()
