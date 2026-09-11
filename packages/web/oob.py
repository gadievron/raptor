"""Run-scoped out-of-band callback listener (blind SSRF detection).

Third-party OAST services are rejected by design: they route canary
metadata through someone else's infrastructure and need egress the
pinned proxy forbids. This listener instead runs INSIDE the scanner
process — trusted code, never sandboxed. The sandbox question does not
arise: ffuf and nuclei are the untrusted children; the listener is
part of the scan, and what it receives are inbound HTTP connections
FROM the target when an injected canary URL gets fetched server-side.
Binding a listen port is fine (and deliberately unrestricted by the
sandbox policy) — it is connecting out that is policed.

Evidence discipline: one recorded callback proves nothing by itself —
a crawler, a link-preview bot, or a security appliance may fetch any
URL it sees. The detection funnel is mint → inject → callback →
REPLAY: re-inject with a FRESH token, and only a new callback on that
fresh token verifies the finding. Correlation is exact-token, so two
concurrent scans (or two parameters in one scan) can never claim each
other's callbacks.
"""

from __future__ import annotations

import re
import secrets
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from core.logging import get_logger

logger = get_logger()

_TOKEN_RE = re.compile(r"^/([0-9a-f]{16})(?:[/?].*)?$")

# Tokens are minted per injection point; a scan should never need more.
_MAX_TOKENS = 4096
# Recorded hits are bounded so a hostile target cannot balloon memory
# by hammering the listener.
_MAX_HITS_PER_TOKEN = 20
# Scoped expectations (see OobListener.expect): far fewer than tokens —
# one per bare-host injection point.
_MAX_EXPECTATIONS = 256
_MAX_HITS_PER_EXPECTATION = 10
# Idle-connection reap + live-connection cap: the listener faces the
# hostile network by design, and every held-open connection pins a
# handler thread — without these, a slowloris peer kills the scan.
_CONNECTION_TIMEOUT_S = 10
_MAX_LIVE_CONNECTIONS = 64


def _strip_ctl(value: str, limit: int) -> str:
    """Header/path values recorded off the wire feed finding evidence
    and reports — control characters (obs-fold smuggles raw CRLF
    through Python's header parser) become spaces."""
    return re.sub(r"[\x00-\x1f\x7f]", " ", value)[:limit]


class _BoundedThreadingHTTPServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._conn_slots = threading.BoundedSemaphore(_MAX_LIVE_CONNECTIONS)

    def process_request(self, request: Any, client_address: Any) -> None:
        if not self._conn_slots.acquire(blocking=False):
            # Over the cap: drop immediately rather than queue a thread.
            self.shutdown_request(request)
            return
        super().process_request(request, client_address)

    def process_request_thread(self, request: Any, client_address: Any) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._conn_slots.release()


@dataclass
class OobHit:
    """One inbound callback, bounded fields only."""

    token: str
    path: str
    method: str
    source_ip: str
    user_agent: str
    received_at: float


@dataclass
class OobContext:
    """What was injected where — the correlation record for a token."""

    url: str
    param: str
    method: str = "GET"
    kind: str = "ssrf"
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class OobExpectation:
    """A WINDOWED, path-scoped callback expectation — the lower
    correlation tier for injection points that can only carry a bare
    host (X-Forwarded-Host, Host), where no token can ride: the
    application builds the path itself (a reset link, a cache-key
    URL), so hits are matched by path marker + time window instead of
    an exact token. This tier NEVER confirms anything by itself —
    consumers must keep such findings at needs_review with the
    callback attached as corroboration, because a window-plus-path
    match is exactly the ambiguity the exact-token replay exists to
    kill."""

    context: OobContext
    path_marker: str          # substring the hit's path must carry; "" = any
    expires_at: float
    hits: list[OobHit] = field(default_factory=list)


class OobListener:
    """HTTP callback listener with token mint/correlate/replay support.

    DNS callbacks are out of scope for a run-scoped listener: they need
    a delegated public zone and a privileged port 53 bind, neither of
    which a per-run scanner can assume. HTTP covers the common blind
    SSRF shape; targets that can only speak DNS outward need
    operator-provided infrastructure.
    """

    def __init__(
        self,
        bind_host: str = "0.0.0.0",
        port: int = 0,
        callback_host: str | None = None,
    ) -> None:
        self._bind_host = bind_host
        self._requested_port = port
        # The address the TARGET must reach may differ from the bind
        # address (NAT, container, port-forward) — the operator asserts
        # it; we only default to the bind interface.
        self._callback_host = callback_host
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()
        self._contexts: dict[str, OobContext] = {}
        self._hits: dict[str, list[OobHit]] = {}
        self._expectations: list[OobExpectation] = []
        self._unknown_token_requests = 0

    # -- lifecycle ---------------------------------------------------------

    def start(self) -> None:
        if self._server is not None:
            return
        listener = self

        class _Handler(BaseHTTPRequestHandler):
            # Reap idle connections: BaseHTTPRequestHandler treats a
            # socket timeout as end-of-conversation.
            timeout = _CONNECTION_TIMEOUT_S

            def _serve(self) -> None:
                listener._record(self)
                body = b"ok"
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            do_GET = _serve  # noqa: N815 - BaseHTTPRequestHandler API
            do_POST = _serve  # noqa: N815
            do_HEAD = _serve  # noqa: N815

            def log_message(self, *_args: object) -> None:
                pass

        self._server = _BoundedThreadingHTTPServer(
            (self._bind_host, self._requested_port), _Handler,
        )
        self._thread = threading.Thread(
            target=self._server.serve_forever, daemon=True,
        )
        self._thread.start()
        logger.info(
            "OOB listener started on %s:%d (callback base %s)",
            self._bind_host, self.port, self.callback_base,
        )

    def stop(self) -> None:
        if self._server is None:
            return
        self._server.shutdown()
        self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)
        self._server = None
        self._thread = None

    @property
    def port(self) -> int:
        if self._server is None:
            return self._requested_port
        return self._server.server_port

    @property
    def callback_base(self) -> str:
        host = self._callback_host or self._bind_host
        if host in ("0.0.0.0", "::") and self._callback_host is None:  # noqa: S104
            # Wildcard bind with no operator-asserted callback host:
            # minted canaries would tell the target to fetch from ITS
            # OWN loopback/interface, so the listener could never see a
            # genuine callback. Mint them anyway (local targets still
            # work) but say so loudly.
            logger.warning(
                "OOB callback host defaults to the bind interface %s — "
                "remote targets cannot reach it; pass an externally "
                "reachable callback host",
                host,
            )
        return f"http://{self._format_host_port(host, self.port)}"

    @staticmethod
    def _format_host_port(host: str, port: int) -> str:
        """HOST[:PORT] with correct IPv6 bracketing.

        A bare ':' test misreads every IPv6 literal as host:port and
        emits an unparseable URL ('http://::1') as the canary base.
        """
        if host.startswith("["):
            # Already bracketed; append the port unless one is present.
            return host if host.rsplit("]", 1)[-1].startswith(":") else f"{host}:{port}"
        if ":" in host:
            head, _, tail = host.rpartition(":")
            if head and tail.isdigit() and ":" not in head:
                return host  # plain host:port
            return f"[{host}]:{port}"  # unbracketed IPv6 literal
        return f"{host}:{port}"

    # -- mint / record / correlate -----------------------------------------

    def mint(self, context: OobContext) -> str:
        """A fresh canary URL registered to *context*."""
        with self._lock:
            if len(self._contexts) >= _MAX_TOKENS:
                msg = "OOB token budget exhausted"
                raise RuntimeError(msg)
            token = secrets.token_hex(8)
            self._contexts[token] = context
        return f"{self.callback_base}/{token}"

    def expect(
        self,
        context: OobContext,
        *,
        path_marker: str = "",
        window_s: float = 300.0,
    ) -> OobExpectation:
        """Register a windowed, path-scoped expectation (see
        OobExpectation). Returns the registration for later
        inspection."""
        with self._lock:
            if len(self._expectations) >= _MAX_EXPECTATIONS:
                msg = "OOB expectation budget exhausted"
                raise RuntimeError(msg)
            expectation = OobExpectation(
                context=context,
                path_marker=path_marker,
                expires_at=time.time() + window_s,
            )
            self._expectations.append(expectation)
            return expectation

    def correlated_expectations(self) -> list[OobExpectation]:
        """Expectations that received at least one in-window hit."""
        with self._lock:
            return [e for e in self._expectations if e.hits]

    def _record(self, handler: BaseHTTPRequestHandler) -> None:
        match = _TOKEN_RE.match(handler.path or "")
        token = match.group(1) if match else None
        with self._lock:
            if token is None or token not in self._contexts:
                self._record_expectation_hit(handler)
                self._unknown_token_requests += 1
                return
            hits = self._hits.setdefault(token, [])
            if len(hits) >= _MAX_HITS_PER_TOKEN:
                return
            hits.append(OobHit(
                token=token,
                path=_strip_ctl(str(handler.path), 256),
                method=_strip_ctl(str(handler.command), 16),
                source_ip=str(handler.client_address[0]),
                user_agent=_strip_ctl(
                    str(handler.headers.get("User-Agent", "")), 256,
                ),
                received_at=time.time(),
            ))

    def _record_expectation_hit(
        self, handler: BaseHTTPRequestHandler,
    ) -> None:
        """Lock held by caller. Non-token requests match open
        expectations by path marker within their window."""
        now = time.time()
        path = _strip_ctl(str(handler.path or ""), 256)
        for expectation in self._expectations:
            if now > expectation.expires_at:
                continue
            if expectation.path_marker and (
                expectation.path_marker not in path
            ):
                continue
            if len(expectation.hits) >= _MAX_HITS_PER_EXPECTATION:
                continue
            expectation.hits.append(OobHit(
                token="",
                path=path,
                method=_strip_ctl(str(handler.command), 16),
                source_ip=str(handler.client_address[0]),
                user_agent=_strip_ctl(
                    str(handler.headers.get("User-Agent", "")), 256,
                ),
                received_at=now,
            ))

    def hits_for(self, token: str) -> list[OobHit]:
        with self._lock:
            return list(self._hits.get(token, ()))

    def wait_for(self, token: str, timeout: float) -> OobHit | None:
        """Poll for the first hit on *token*, bounded by *timeout*."""
        deadline = time.monotonic() + timeout
        while True:
            hits = self.hits_for(token)
            if hits:
                return hits[0]
            if time.monotonic() >= deadline:
                return None
            time.sleep(0.2)

    def correlated(self) -> list[tuple[OobContext, OobHit]]:
        """(context, first hit) for every token that called back."""
        with self._lock:
            return [
                (self._contexts[token], hits[0])
                for token, hits in self._hits.items()
                if hits and token in self._contexts
            ]

    @property
    def stats(self) -> dict[str, int]:
        with self._lock:
            return {
                "tokens_minted": len(self._contexts),
                "tokens_hit": sum(1 for h in self._hits.values() if h),
                "expectations": len(self._expectations),
                "expectations_hit": sum(
                    1 for e in self._expectations if e.hits
                ),
                "unknown_token_requests": self._unknown_token_requests,
            }


def token_of(canary_url: str) -> str:
    """The token component of a minted canary URL."""
    return canary_url.rsplit("/", 1)[-1]
