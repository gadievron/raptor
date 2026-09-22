"""Captive keep-alive upstream with configurable teardown behaviour.

Test support for the LLM transport's connection-reuse failure modes.
The stdlib ``http.server`` doubles used elsewhere in these tests
cannot express the behaviours that matter here — server-initiated
idle close, half-open sockets, RST — so this is a raw-socket
HTTP/1.1 server whose per-connection lifecycle is the test subject.

Teardown modes (``mode=``):

``keepalive``
    Serve every request on a persistent connection, never close.
``idle-close-fin``
    Clean FIN after ``idle_s`` of inactivity on a kept-alive
    connection. Models an upstream (or a proxy that propagates the
    upstream's close) timing out an idle connection. A FIN that has
    ARRIVED before the client reuses the connection is detectable
    client-side (the socket polls readable); one that lands mid-reuse
    is the classic stale-connection race.
``idle-close-rst``
    Same trigger, but the close carries RST (``SO_LINGER`` zero).
``half-open``
    After ``idle_s`` of inactivity the connection stops being served
    but NO close is sent — the client-side socket stays open and
    unreadable, exactly like a proxied CONNECT tunnel whose upstream
    side died while the proxy holds the client side. When the client
    eventually writes a request into it, the connection is closed
    (FIN) without any response bytes.
``half-open-rst``
    Same, but the eventual teardown is an RST.
``rst-mid-response``
    Serve headers plus a partial body, then RST. Models an upstream
    (or tunnel) dying mid-response — the shape where the request WAS
    processed upstream before the transport error.
``close-after-response``
    Serve one response (no ``Connection: close`` header), then FIN
    immediately. The client pools a connection that is already dead.
``no-response-close``
    Read every request in full, then FIN without any response bytes —
    fresh connections included. Models an upstream that persistently
    dies pre-response; the shape a bounded transparent retry must NOT
    chase indefinitely.

Counters distinguish "the upstream did the work" from "the wire
failed": ``requests_processed`` increments only when a full request
was parsed and handling began — the double-send evidence a retry
audit needs. ``stale_hits`` counts request bytes that arrived on a
connection already condemned by its teardown mode (never processed).
"""

from __future__ import annotations

import contextlib
import json
import socket
import struct
import threading
import time

_MODES = frozenset({
    "keepalive",
    "idle-close-fin",
    "idle-close-rst",
    "half-open",
    "half-open-rst",
    "rst-mid-response",
    "close-after-response",
    "no-response-close",
})


def _rst_close(conn: socket.socket) -> None:
    """Close ``conn`` with an RST instead of an orderly FIN."""
    with contextlib.suppress(OSError):
        conn.setsockopt(
            socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0),
        )
    with contextlib.suppress(OSError):
        conn.close()


class MockUpstream:
    """Threaded captive upstream; see module docstring for modes."""

    def __init__(
        self,
        mode: str = "keepalive",
        *,
        idle_s: float = 0.5,
        response_delay_s: float = 0.0,
        body_bytes: int = 512,
    ) -> None:
        if mode not in _MODES:
            raise ValueError(f"unknown mode: {mode!r}")
        self.mode = mode
        self.idle_s = idle_s
        self.response_delay_s = response_delay_s
        self.body_bytes = body_bytes

        self._lock = threading.Lock()
        self.connections = 0
        self.requests_processed = 0
        self.responses_completed = 0
        self.stale_hits = 0

        self._stop = threading.Event()
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(64)
        self.port = self._listener.getsockname()[1]
        self.base_url = f"http://127.0.0.1:{self.port}"
        self._threads: list[threading.Thread] = []
        self._accept_thread = threading.Thread(
            target=self._accept_loop, daemon=True,
        )
        self._accept_thread.start()

    # ---- lifecycle ----

    def shutdown(self) -> None:
        self._stop.set()
        with contextlib.suppress(OSError):
            self._listener.close()
        # Handler threads are daemons blocked on client sockets at
        # most; give them a beat to notice the stop flag.
        for t in self._threads:
            t.join(timeout=1.0)

    def __enter__(self) -> MockUpstream:
        return self

    def __exit__(self, *exc: object) -> None:
        self.shutdown()

    def counters(self) -> dict[str, int]:
        with self._lock:
            return {
                "connections": self.connections,
                "requests_processed": self.requests_processed,
                "responses_completed": self.responses_completed,
                "stale_hits": self.stale_hits,
            }

    def _bump(self, name: str) -> None:
        with self._lock:
            setattr(self, name, getattr(self, name) + 1)

    # ---- accept / handle ----

    def _accept_loop(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _addr = self._listener.accept()
            except OSError:
                return
            self._bump("connections")
            t = threading.Thread(
                target=self._handle, args=(conn,), daemon=True,
            )
            self._threads.append(t)
            t.start()

    def _read_request(self, conn: socket.socket) -> bytes | None:
        """Read one full HTTP/1.1 request (headers + Content-Length
        body). Returns None on orderly client close before any bytes.
        Raises ``socket.timeout`` if the connection idles past the
        configured timeout mid-wait (only armed by idle modes)."""
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = conn.recv(65536)
            if not chunk:
                if buf:
                    raise ConnectionError("client closed mid-request")
                return None
            buf += chunk
        head, _, rest = buf.partition(b"\r\n\r\n")
        length = 0
        for line in head.split(b"\r\n")[1:]:
            name, _, value = line.partition(b":")
            if name.strip().lower() == b"content-length":
                length = int(value.strip())
        while len(rest) < length:
            chunk = conn.recv(65536)
            if not chunk:
                raise ConnectionError("client closed mid-body")
            rest += chunk
        return head + b"\r\n\r\n" + rest

    def _respond(self, conn: socket.socket) -> None:
        body = json.dumps({
            "ok": True, "pad": "x" * max(0, self.body_bytes - 32),
        }).encode()
        head = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: application/json\r\n"
            b"Content-Length: " + str(len(body)).encode() + b"\r\n"
            b"\r\n"
        )
        if self.mode == "rst-mid-response":
            # Half the body, then RST: the request WAS processed —
            # the wire failure happens after the work (and any cost)
            # already landed upstream.
            conn.sendall(head + body[: len(body) // 2])
            time.sleep(0.05)  # let the partial bytes reach the client
            _rst_close(conn)
            return
        conn.sendall(head + body)
        self._bump("responses_completed")

    def _handle(self, conn: socket.socket) -> None:
        idle_modes = (
            "idle-close-fin", "idle-close-rst", "half-open", "half-open-rst",
        )
        try:
            while not self._stop.is_set():
                conn.settimeout(
                    self.idle_s if self.mode in idle_modes else None,
                )
                try:
                    request = self._read_request(conn)
                except TimeoutError:
                    self._on_idle_timeout(conn)
                    return
                except ConnectionError:
                    return
                if request is None:
                    return  # orderly client close between requests
                self._bump("requests_processed")
                if self.response_delay_s:
                    time.sleep(self.response_delay_s)
                if self.mode == "no-response-close":
                    conn.close()
                    return
                self._respond(conn)
                if self.mode == "rst-mid-response":
                    return
                if self.mode == "close-after-response":
                    # FIN right after the response, WITHOUT having
                    # advertised ``Connection: close`` — the client
                    # pools a connection that is already dead.
                    conn.close()
                    return
        except OSError:
            pass
        finally:
            with contextlib.suppress(OSError):
                conn.close()

    def _on_idle_timeout(self, conn: socket.socket) -> None:
        if self.mode == "idle-close-fin":
            conn.close()
            return
        if self.mode == "idle-close-rst":
            _rst_close(conn)
            return
        # half-open variants: stay silent until the client writes,
        # then tear down without a response. The client-side socket
        # polls unreadable throughout the silent phase, so pool
        # checkout guards cannot see the condemnation.
        conn.settimeout(None)
        try:
            data = conn.recv(65536)
        except OSError:
            return
        if data:
            self._bump("stale_hits")
        if self.mode == "half-open-rst":
            _rst_close(conn)
        else:
            conn.close()


__all__ = ["MockUpstream"]
