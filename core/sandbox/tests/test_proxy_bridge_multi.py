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


def _unix_hold_echo_server(path: str) -> threading.Thread:
    """Echo server that HOLDS each connection open (echoes every
    chunk, closes only on client EOF) — for tests that need live
    long-lived pairs."""
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(path)
    srv.listen(16)

    def _serve_conn(conn):
        with conn:
            conn.settimeout(30)
            try:
                while True:
                    data = conn.recv(4096)
                    if not data:
                        return
                    conn.sendall(data)
            except OSError:
                return

    def _serve():
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            threading.Thread(target=_serve_conn, args=(conn,),
                             daemon=True).start()

    t = threading.Thread(target=_serve, daemon=True)
    t.start()
    t._srv = srv
    return t


def _unix_flood_server(path: str, nbytes: int) -> threading.Thread:
    """Server that blasts *nbytes* at every connection as soon as it
    is accepted — for tests that need a peer's write side saturated."""
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(path)
    srv.listen(16)

    def _blast(conn):
        with conn:
            conn.settimeout(30)
            try:
                conn.sendall(b"\x00" * nbytes)
            except OSError:
                return

    def _serve():
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            threading.Thread(target=_blast, args=(conn,),
                             daemon=True).start()

    t = threading.Thread(target=_serve, daemon=True)
    t.start()
    t._srv = srv
    return t


class TestForwarderBounds:
    """Pair cap, idle sweep, and non-blocking writes — the forwarder
    must never let one peer starve or stall the others."""

    def test_pair_cap_refuses_excess_connections(self, short_sock_dir,
                                                 monkeypatch):
        import time as _time
        monkeypatch.setattr(
            "core.sandbox._proxy_bridge._MAX_PAIRS", 2)
        path = str(short_sock_dir / "cap.sock")
        srv = _unix_hold_echo_server(path)
        port = _free_port()
        death_r, death_w = os.pipe()
        t = threading.Thread(
            target=_run_bridges, args=(((port, path),), death_r),
            daemon=True)
        t.start()
        held = []
        try:
            _wait_listening(port)
            for i in range(2):
                c = socket.create_connection(("127.0.0.1", port),
                                             timeout=5)
                c.settimeout(5)
                c.sendall(b"hi%d" % i)
                assert c.recv(4096) == b"hi%d" % i
                held.append(c)
            # Third pair is over the cap: accepted then immediately
            # closed — the client reads EOF, no hang, no relay.
            with socket.create_connection(("127.0.0.1", port),
                                          timeout=5) as c3:
                c3.settimeout(5)
                assert c3.recv(4096) == b""
            # Freeing a slot re-opens admission.
            held.pop().close()
            deadline = _time.monotonic() + 5
            admitted = False
            while _time.monotonic() < deadline and not admitted:
                with socket.create_connection(("127.0.0.1", port),
                                              timeout=5) as c4:
                    c4.settimeout(1)
                    try:
                        c4.sendall(b"again")
                        admitted = (c4.recv(4096) == b"again")
                    except OSError:
                        admitted = False
                if not admitted:
                    _time.sleep(0.1)
            assert admitted, "slot freed by a closed pair never reopened"
        finally:
            for c in held:
                c.close()
            os.close(death_w)
            t.join(timeout=5)
            os.close(death_r)
            srv._srv.close()

    def test_idle_pairs_are_swept(self, short_sock_dir, monkeypatch):
        import time as _time
        monkeypatch.setattr(
            "core.sandbox._proxy_bridge._PAIR_IDLE_TIMEOUT_S", 0.5)
        path = str(short_sock_dir / "idle.sock")
        srv = _unix_hold_echo_server(path)
        port = _free_port()
        death_r, death_w = os.pipe()
        t = threading.Thread(
            target=_run_bridges, args=(((port, path),), death_r),
            daemon=True)
        t.start()
        try:
            _wait_listening(port)
            c = socket.create_connection(("127.0.0.1", port), timeout=5)
            c.settimeout(5)
            c.sendall(b"warm")
            assert c.recv(4096) == b"warm"
            # Go idle past the (shrunk) idle timeout; sweep granularity
            # is one _SELECT_TIMEOUT (1s), so allow a couple of seconds.
            t0 = _time.monotonic()
            got = c.recv(4096)  # blocks until the sweep closes the pair
            assert got == b"", "idle pair not swept (data instead of EOF)"
            assert _time.monotonic() - t0 < 4.0, "idle sweep too late"
            c.close()
        finally:
            os.close(death_w)
            t.join(timeout=5)
            os.close(death_r)
            srv._srv.close()

    def test_stalled_peer_does_not_block_other_pairs(
        self, short_sock_dir, monkeypatch,
    ):
        """One peer that stops reading while its upstream floods must
        neither park the select loop (head-of-line blocking every
        other pair — the old synchronous _write_all did, for up to
        60s) nor hold its pair forever: the stall deadline drops it."""
        import time as _time
        monkeypatch.setattr(
            "core.sandbox._proxy_bridge._WRITE_STALL_TIMEOUT_S", 1.0)
        flood_path = str(short_sock_dir / "flood.sock")
        echo_path = str(short_sock_dir / "echo.sock")
        flood_srv = _unix_flood_server(flood_path, 32 * 1024 * 1024)
        echo_srv = _unix_hold_echo_server(echo_path)
        flood_port, echo_port = _free_port(), _free_port()
        death_r, death_w = os.pipe()
        t = threading.Thread(
            target=_run_bridges,
            args=(((flood_port, flood_path), (echo_port, echo_path)),
                  death_r),
            daemon=True)
        t.start()
        stalled = None
        try:
            _wait_listening(echo_port)
            # The stalling peer: tiny receive buffer, never reads.
            stalled = socket.socket()
            stalled.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
            stalled.connect(("127.0.0.1", flood_port))
            _time.sleep(0.7)  # let the flood saturate every buffer

            # Unrelated pair on the same forwarder must be unaffected.
            with socket.create_connection(("127.0.0.1", echo_port),
                                          timeout=5) as b:
                b.settimeout(4)
                t0 = _time.monotonic()
                b.sendall(b"ping")
                assert b.recv(4096) == b"ping", (
                    "roundtrip failed while a sibling pair was stalled"
                )
                assert _time.monotonic() - t0 < 2.0, (
                    "head-of-line blocking: sibling roundtrip stalled"
                )

            # And the stalled pair itself is dropped at the stall
            # deadline (1s + sweep granularity), not held forever.
            stalled.settimeout(6)
            deadline = _time.monotonic() + 6
            dropped = False
            try:
                while _time.monotonic() < deadline:
                    if not stalled.recv(65536):
                        dropped = True
                        break
            except OSError:
                dropped = True  # reset by the forwarder — also a drop
            assert dropped, "stalled pair was never dropped"
        finally:
            if stalled is not None:
                stalled.close()
            os.close(death_w)
            t.join(timeout=5)
            os.close(death_r)
            flood_srv._srv.close()
            echo_srv._srv.close()

    def test_eof_with_pending_bytes_still_delivers_the_tail(
        self, short_sock_dir,
    ):
        """A source that writes a burst and immediately closes must
        not lose the tail: bytes queued in the pending buffer are
        drained before the pair is torn down."""
        path = str(short_sock_dir / "tail.sock")
        # Burst server: to EVERY connection (including the
        # _wait_listening probe), send 2 MiB then close — the EOF
        # chases the data through the relay.
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.bind(path)
        srv.listen(4)
        payload = os.urandom(2 * 1024 * 1024)

        def _burst(conn):
            with conn:
                conn.settimeout(10)
                try:
                    conn.sendall(payload)
                except OSError:
                    pass

        def _serve():
            while True:
                try:
                    conn, _ = srv.accept()
                except OSError:
                    return
                threading.Thread(target=_burst, args=(conn,),
                                 daemon=True).start()

        st = threading.Thread(target=_serve, daemon=True)
        st.start()
        port = _free_port()
        death_r, death_w = os.pipe()
        t = threading.Thread(
            target=_run_bridges, args=(((port, path),), death_r),
            daemon=True)
        t.start()
        try:
            _wait_listening(port)
            with socket.create_connection(("127.0.0.1", port),
                                          timeout=5) as c:
                c.settimeout(10)
                got = bytearray()
                while True:
                    chunk = c.recv(65536)
                    if not chunk:
                        break
                    got += chunk
                assert bytes(got) == payload, (
                    f"tail lost: received {len(got)} of "
                    f"{len(payload)} bytes"
                )
        finally:
            os.close(death_w)
            t.join(timeout=5)
            os.close(death_r)
            srv.close()  # daemon accept-thread exits with the process


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
