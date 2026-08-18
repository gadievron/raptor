"""Multi-listener TCP→Unix bridge relay (`_proxy_bridge._run_bridges`)
and the `loopback_unix_bridges` sandbox-policy plumbing.

The relay itself is exercised in-process (thread + death pipe) — no
namespaces needed: the function is transport logic, identical inside
or outside a netns.
"""

from __future__ import annotations

import os
import socket
import threading

import pytest

from core.sandbox._proxy_bridge import _run_bridges, _run_forwarder


def _unix_echo_server(path: str, tag: bytes) -> threading.Thread:
    """Echo server on a unix socket that prefixes replies with *tag*
    so tests can prove WHICH upstream a bridge port maps to."""
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(path)
    srv.listen(4)

    def _serve():
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            with conn:
                data = conn.recv(4096)
                if data:
                    conn.sendall(tag + data)

    t = threading.Thread(target=_serve, daemon=True)
    t.start()
    t._srv = srv  # keep a handle for cleanup
    return t


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_listening(port: int, timeout: float = 5.0) -> None:
    """The relay thread binds asynchronously — poll until it accepts."""
    import time
    deadline = time.monotonic() + timeout
    while True:
        try:
            socket.create_connection(("127.0.0.1", port), timeout=1).close()
            return
        except OSError:
            if time.monotonic() > deadline:
                raise
            time.sleep(0.02)


def _roundtrip(port: int, payload: bytes) -> bytes:
    # No half-close: the relay tears the whole pair down on EOF from
    # either side (correct for its HTTP consumers), so a SHUT_WR here
    # would race the reply. Read until the SERVER closes.
    with socket.create_connection(("127.0.0.1", port), timeout=5) as c:
        c.settimeout(5)
        c.sendall(payload)
        chunks = []
        while True:
            b = c.recv(4096)
            if not b:
                break
            chunks.append(b)
        return b"".join(chunks)


class TestRunBridges:

    def test_two_bridges_relay_to_their_own_upstreams(self,
                                                      short_sock_dir):
        path_a = str(short_sock_dir / "a.sock")
        path_b = str(short_sock_dir / "b.sock")
        srv_a = _unix_echo_server(path_a, b"A:")
        srv_b = _unix_echo_server(path_b, b"B:")
        port_a, port_b = _free_port(), _free_port()
        death_r, death_w = os.pipe()
        t = threading.Thread(
            target=_run_bridges,
            args=(((port_a, path_a), (port_b, path_b)), death_r),
            daemon=True,
        )
        t.start()
        try:
            _wait_listening(port_a)
            _wait_listening(port_b)
            assert _roundtrip(port_a, b"hello") == b"A:hello"
            assert _roundtrip(port_b, b"world") == b"B:world"
            # A second connection on the same bridge still works
            # (the loop keeps accepting).
            assert _roundtrip(port_a, b"again") == b"A:again"
        finally:
            os.close(death_w)
            t.join(timeout=5)
            os.close(death_r)
            srv_a._srv.close()
            srv_b._srv.close()
        assert not t.is_alive()

    def test_single_bridge_wrapper_compatible(self, short_sock_dir):
        path = str(short_sock_dir / "one.sock")
        srv = _unix_echo_server(path, b"X:")
        port = _free_port()
        death_r, death_w = os.pipe()
        t = threading.Thread(
            target=_run_forwarder, args=(port, path, death_r),
            daemon=True,
        )
        t.start()
        try:
            _wait_listening(port)
            assert _roundtrip(port, b"ping") == b"X:ping"
        finally:
            os.close(death_w)
            t.join(timeout=5)
            os.close(death_r)
            srv._srv.close()

    def test_dead_upstream_closes_client_not_relay(self, short_sock_dir):
        """A bridge whose unix upstream is gone must refuse that
        connection (fail fast for the child) while the relay itself
        keeps serving its other bridges."""
        path_dead = str(short_sock_dir / "dead.sock")   # never bound
        path_live = str(short_sock_dir / "live.sock")
        srv = _unix_echo_server(path_live, b"L:")
        port_dead, port_live = _free_port(), _free_port()
        death_r, death_w = os.pipe()
        t = threading.Thread(
            target=_run_bridges,
            args=(((port_dead, path_dead), (port_live, path_live)),
                  death_r),
            daemon=True,
        )
        t.start()
        try:
            _wait_listening(port_live)
            # Dead upstream: connection is accepted then immediately
            # closed — the client reads EOF, no hang.
            with socket.create_connection(
                ("127.0.0.1", port_dead), timeout=5,
            ) as c:
                c.settimeout(5)
                assert c.recv(4096) == b""
            # Live bridge unaffected.
            assert _roundtrip(port_live, b"ok") == b"L:ok"
        finally:
            os.close(death_w)
            t.join(timeout=5)
            os.close(death_r)
            srv._srv.close()


class TestSandboxPolicyPlumbing:

    def test_bridges_require_egress_proxy(self):
        from core.sandbox.context import sandbox
        with pytest.raises(ValueError, match="use_egress_proxy"):
            with sandbox(
                loopback_unix_bridges={61781: "/tmp/x.sock"},
            ):
                pass  # pragma: no cover — must raise on entry

    def test_run_untrusted_networked_accepts_bridge_kwarg(self):
        """Signature-level: the kwarg is policy, not a rejected
        passthrough. (Full behaviour needs a netns host — covered by
        the credential-proxy proof script.)"""
        import inspect

        from core.sandbox.context import run_untrusted_networked
        sig = inspect.signature(run_untrusted_networked)
        assert "loopback_unix_bridges" in sig.parameters
