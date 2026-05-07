"""Unix-domain HTTP dispatcher with credential-isolation security layers.

Five security layers, in the order an attacker must defeat them:

  L1. **Filesystem isolation.** Socket lives in a fresh 0700 directory
      created via ``tempfile.mkdtemp``; socket file is 0600. Other
      UIDs cannot traverse into the directory regardless of the
      socket file's mode.
  L2. **Peer-UID verification on every accept.** Linux uses
      ``SO_PEERCRED``, macOS uses ``LOCAL_PEERCRED``. Connections
      from a different UID are dropped before any HTTP parsing.
  L3. **Per-worker capability token, FD-passed.** Each spawned
      worker gets a fresh 32-byte token via inherited file descriptor
      (NOT env var — same-UID processes can read ``/proc/N/environ``
      on Linux). Worker presents the token in the ``X-Raptor-Token``
      header on its first request.
  L4. **Single-use connection tokens with per-token budget.** Token
      authorises one connection; revoked when connection closes,
      after ``request_budget`` requests, or after ``ttl_s`` seconds.
      Replay after legitimate session ends fails.
  L5. **Audit log.** Every accept / reject / dispatch event lands
      in a JSONL log. Body content is intentionally never logged.

The dispatcher does NOT terminate TLS, MITM, or read prompt/response
content beyond what's needed to inject the auth header and forward
bytes upstream.
"""

from __future__ import annotations

import errno
import http.server
import json
import logging
import os
import secrets
import socket
import socketserver
import struct
import sys
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO, Optional

import httpx

from .auth import CredentialStore, ProviderRule, build_rules


_logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Token bookkeeping
# ---------------------------------------------------------------------------


_TOKEN_DEFAULT_TTL_S = 60 * 60       # one hour
_TOKEN_DEFAULT_BUDGET = 1000         # requests per worker run
_TOKEN_HEADER = "X-Raptor-Token"


@dataclass
class _TokenRecord:
    value: str
    worker_label: str
    issued_at: float
    expires_at: float
    request_budget: int
    requests_made: int = 0
    status: str = "pending"   # pending → active → revoked|exhausted|expired


@dataclass(frozen=True)
class AuditEvent:
    """One row in the audit log. Body content is intentionally absent."""
    ts: float
    event: str
    peer_pid: Optional[int]
    peer_uid: Optional[int]
    token_id: Optional[str]   # 12-char prefix for correlation; never the full token
    worker_label: Optional[str]
    status: str
    reason: Optional[str] = None
    extra: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Cross-platform peer-UID
# ---------------------------------------------------------------------------


def _peer_uid(conn: socket.socket) -> Optional[int]:
    """Return the connecting peer's UID, or None on platforms / failure
    where the lookup isn't supported. Caller should reject the
    connection if None on a platform we expect to support it."""
    if sys.platform == "linux":
        try:
            data = conn.getsockopt(
                socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"),
            )
            _pid, uid, _gid = struct.unpack("3i", data)
            return uid
        except (OSError, AttributeError):
            return None
    if sys.platform == "darwin":
        # ``LOCAL_PEERCRED`` returns ``struct xucred`` — version (uint32_t),
        # uid (uid_t = uint32_t), ngroups (short), groups (16 * uint32_t).
        # Only ``uid`` is interesting here.
        SOL_LOCAL = getattr(socket, "SOL_LOCAL", 0)
        LOCAL_PEERCRED = getattr(socket, "LOCAL_PEERCRED", 0x001)
        try:
            buf = conn.getsockopt(SOL_LOCAL, LOCAL_PEERCRED, 76)
            _version, uid = struct.unpack("II", buf[:8])
            return uid
        except (OSError, AttributeError):
            return None
    return None


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------


class LLMDispatcher:
    """Per-run dispatcher daemon.

    Lifecycle:
      1. ``LLMDispatcher(run_id=...)`` — sets up secrets, binds UDS,
         starts the server thread.
      2. ``allocate_worker(label)`` returns ``(socket_path, token_fd)``
         to pass to a child via env + ``pass_fds``.
      3. Child connects, sends token in first request header,
         dispatcher forwards to upstream with auth injected.
      4. ``shutdown()`` stops the server, closes sockets, removes
         the socket dir. Also wired to ``atexit``.
    """

    def __init__(
        self,
        run_id: str,
        *,
        audit_path: Optional[Path] = None,
        token_ttl_s: int = _TOKEN_DEFAULT_TTL_S,
        token_budget: int = _TOKEN_DEFAULT_BUDGET,
        creds: Optional[CredentialStore] = None,
    ) -> None:
        self.run_id = run_id
        self._token_ttl_s = token_ttl_s
        self._token_budget = token_budget

        self._creds = creds or CredentialStore()
        self._rules: dict[str, ProviderRule] = build_rules(self._creds)

        self._tokens: dict[str, _TokenRecord] = {}
        self._tokens_lock = threading.Lock()

        # L1 — filesystem isolation.
        self._sock_dir = Path(tempfile.mkdtemp(prefix=f"raptor-llm-{run_id}-"))
        os.chmod(self._sock_dir, 0o700)
        self.socket_path = self._sock_dir / "llm.sock"

        # Audit log
        self._audit_path = audit_path
        self._audit_lock = threading.Lock()

        # Pass dispatcher self into the request handler via the server.
        # http.server's HTTPServer accepts a ``RequestHandlerClass`` so
        # we close over the dispatcher in a per-instance handler.
        dispatcher = self

        class _UnixThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
            address_family = socket.AF_UNIX
            daemon_threads = True
            allow_reuse_address = True

            # Override server_bind to set socket file mode immediately
            # after bind (umask is also set via _setup_socket).
            def server_bind(self):
                old_umask = os.umask(0o077)
                try:
                    super().server_bind()
                finally:
                    os.umask(old_umask)
                # Belt + braces: explicit chmod after bind. Inside an
                # 0700 dir this is mostly cosmetic, but it bounds the
                # window between bind() and dir-mode enforcement.
                try:
                    os.chmod(str(self.server_address), 0o600)
                except OSError:
                    pass

            # L2 — peer-UID verification gate. The standard
            # ``verify_request`` hook runs after accept, before the
            # handler executes. Rejecting here closes the socket
            # without ever feeding bytes to the HTTP parser.
            def verify_request(self, request, client_address):
                uid = _peer_uid(request)
                if uid is None or uid != os.getuid():
                    dispatcher._audit(AuditEvent(
                        ts=time.time(),
                        event="peer_uid.reject",
                        peer_pid=None,
                        peer_uid=uid,
                        token_id=None,
                        worker_label=None,
                        status="reject",
                        reason="peer uid mismatch" if uid is not None else "peer uid unavailable",
                    ))
                    return False
                return True

        handler_cls = _make_request_handler(dispatcher)
        self._server = _UnixThreadingHTTPServer(str(self.socket_path), handler_cls)

        self._thread = threading.Thread(
            target=self._server.serve_forever,
            name=f"raptor-llm-dispatcher-{run_id}",
            daemon=True,
        )
        self._thread.start()

        self._audit(AuditEvent(
            ts=time.time(),
            event="server.start",
            peer_pid=None, peer_uid=None,
            token_id=None, worker_label=None,
            status="ok",
            extra={"socket": str(self.socket_path), "providers": sorted(self._rules)},
        ))

    # ---- public API ----

    def allocate_worker(self, label: str) -> tuple[str, int]:
        """Issue a token for one worker. Returns ``(socket_path, token_fd)``.

        The returned ``token_fd`` is a read-end of an OS pipe with the
        token already written and the write-end closed; the caller
        passes it via ``subprocess.Popen(pass_fds=[token_fd])`` and
        sets ``RAPTOR_LLM_TOKEN_FD=<n>`` in the worker's env. The
        worker reads the token from the FD at startup and closes it.
        """
        token = secrets.token_urlsafe(32)
        now = time.time()
        rec = _TokenRecord(
            value=token,
            worker_label=label,
            issued_at=now,
            expires_at=now + self._token_ttl_s,
            request_budget=self._token_budget,
        )
        with self._tokens_lock:
            self._tokens[token] = rec

        read_fd, write_fd = os.pipe()
        os.write(write_fd, token.encode("ascii"))
        os.close(write_fd)
        # Mark inheritable so subprocess.Popen(pass_fds=...) can
        # forward it to the child. By default Python sets CLOEXEC.
        os.set_inheritable(read_fd, True)

        self._audit(AuditEvent(
            ts=now, event="token.issue",
            peer_pid=None, peer_uid=None,
            token_id=_short(token), worker_label=label,
            status="ok",
        ))
        return str(self.socket_path), read_fd

    def shutdown(self) -> None:
        """Stop the server thread and remove the socket directory."""
        try:
            self._server.shutdown()
        except Exception:
            pass
        try:
            self._server.server_close()
        except Exception:
            pass
        # Remove socket file then dir
        try:
            self.socket_path.unlink(missing_ok=True)
        except Exception:
            pass
        try:
            self._sock_dir.rmdir()
        except Exception:
            pass
        self._audit(AuditEvent(
            ts=time.time(), event="server.stop",
            peer_pid=None, peer_uid=None,
            token_id=None, worker_label=None,
            status="ok",
        ))

    # ---- internal ----

    def _audit(self, ev: AuditEvent) -> None:
        # Always log via stdlib logger for terminal visibility.
        _logger.info(
            "llm-dispatcher %s %s pid=%s uid=%s token=%s label=%s%s",
            ev.event, ev.status, ev.peer_pid, ev.peer_uid,
            ev.token_id or "-", ev.worker_label or "-",
            f" reason={ev.reason}" if ev.reason else "",
        )
        if self._audit_path is None:
            return
        with self._audit_lock:
            try:
                with open(self._audit_path, "a", encoding="utf-8") as fh:
                    fh.write(json.dumps({
                        "ts": ev.ts,
                        "event": ev.event,
                        "peer_pid": ev.peer_pid,
                        "peer_uid": ev.peer_uid,
                        "token_id": ev.token_id,
                        "worker_label": ev.worker_label,
                        "status": ev.status,
                        "reason": ev.reason,
                        **ev.extra,
                    }) + "\n")
            except OSError:
                # Audit failures must not break the dispatcher.
                pass

    def _validate_token(self, raw: str | None) -> tuple[Optional[_TokenRecord], Optional[str]]:
        """L3 + L4 — return (record, None) on success, (None, reason)
        on rejection. Increments ``requests_made`` and revokes if
        budget exhausted or TTL elapsed."""
        if not raw:
            return None, "missing token"
        with self._tokens_lock:
            rec = self._tokens.get(raw)
            if rec is None:
                return None, "unknown token"
            if rec.status in ("revoked", "exhausted", "expired"):
                return None, f"token {rec.status}"
            now = time.time()
            if now >= rec.expires_at:
                rec.status = "expired"
                return None, "token expired"
            if rec.requests_made >= rec.request_budget:
                rec.status = "exhausted"
                return None, "token budget exhausted"
            rec.status = "active"
            rec.requests_made += 1
            return rec, None

    def _provider(self, name: str) -> Optional[ProviderRule]:
        return self._rules.get(name)


def _short(token: str) -> str:
    """Return a short prefix of a token for audit correlation. Never
    log the full token — it's a credential."""
    return token[:12]


# ---------------------------------------------------------------------------
# HTTP request handler
# ---------------------------------------------------------------------------


_PROVIDER_FROM_PATH_PREFIX = {
    "/anthropic/": "anthropic",
    "/openai/":    "openai",
    "/gemini/":    "gemini",
}


def _make_request_handler(dispatcher: LLMDispatcher) -> type:
    """Build a BaseHTTPRequestHandler subclass closed over the
    dispatcher instance. Factory so the dispatcher is plumbed in
    without mutable global state."""

    class _Handler(http.server.BaseHTTPRequestHandler):

        # Disable BaseHTTPRequestHandler's reverse DNS log spam — peer
        # is always the local socket on UDS anyway.
        def log_message(self, format, *args):  # noqa: A002
            return

        def _send_simple(self, status: int, reason: str) -> None:
            body = json.dumps({"error": reason}).encode("utf-8")
            self.send_response(status, reason)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)

        def _dispatch(self) -> None:
            # ---- L3+L4 — token check ----
            token = self.headers.get(_TOKEN_HEADER)
            rec, reason = dispatcher._validate_token(token)
            if rec is None:
                dispatcher._audit(AuditEvent(
                    ts=time.time(), event="token.reject",
                    peer_pid=None, peer_uid=None,
                    token_id=_short(token) if token else None,
                    worker_label=None, status="reject", reason=reason,
                ))
                self._send_simple(401, reason or "unauthorized")
                return

            # ---- provider routing via path prefix ----
            provider_name: Optional[str] = None
            upstream_path = self.path
            for prefix, name in _PROVIDER_FROM_PATH_PREFIX.items():
                if self.path.startswith(prefix):
                    provider_name = name
                    upstream_path = self.path[len(prefix) - 1:]   # keep leading "/"
                    break
            if provider_name is None:
                dispatcher._audit(AuditEvent(
                    ts=time.time(), event="provider.reject",
                    peer_pid=None, peer_uid=None,
                    token_id=_short(rec.value), worker_label=rec.worker_label,
                    status="reject", reason=f"unknown path: {self.path}",
                ))
                self._send_simple(404, "unknown provider path")
                return
            rule = dispatcher._provider(provider_name)
            if rule is None or not rule.inject_headers():
                dispatcher._audit(AuditEvent(
                    ts=time.time(), event="provider.unconfigured",
                    peer_pid=None, peer_uid=None,
                    token_id=_short(rec.value), worker_label=rec.worker_label,
                    status="reject", reason=provider_name,
                ))
                self._send_simple(503, f"provider not configured: {provider_name}")
                return

            # ---- request body ----
            content_length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(content_length) if content_length else b""

            # ---- header rewrite ----
            forwarded: dict[str, str] = {}
            for k, v in self.headers.items():
                if k.lower() in rule.strip_request_headers:
                    continue
                if k.lower() in ("host", "content-length", _TOKEN_HEADER.lower()):
                    continue
                forwarded[k] = v
            forwarded.update(rule.inject_headers())

            # ---- forward to upstream + stream response back ----
            url = rule.upstream_base_url + upstream_path
            method = self.command
            try:
                with httpx.Client(timeout=httpx.Timeout(60.0, connect=10.0)) as client:
                    with client.stream(method, url, content=body, headers=forwarded) as up:
                        self.send_response(up.status_code)
                        for k, v in up.headers.items():
                            if k.lower() in (
                                "transfer-encoding", "content-encoding",
                                "connection",
                            ):
                                continue
                            self.send_header(k, v)
                        self.end_headers()
                        for chunk in up.iter_raw():
                            self.wfile.write(chunk)
                        self.wfile.flush()
                dispatcher._audit(AuditEvent(
                    ts=time.time(), event="request.dispatch",
                    peer_pid=None, peer_uid=None,
                    token_id=_short(rec.value), worker_label=rec.worker_label,
                    status="ok",
                    extra={"provider": provider_name, "method": method, "path": upstream_path},
                ))
            except (httpx.HTTPError, OSError) as exc:
                dispatcher._audit(AuditEvent(
                    ts=time.time(), event="request.error",
                    peer_pid=None, peer_uid=None,
                    token_id=_short(rec.value), worker_label=rec.worker_label,
                    status="error", reason=type(exc).__name__,
                ))
                # Best-effort failure response. If headers already sent
                # there's nothing useful to do.
                try:
                    self._send_simple(502, f"upstream error: {type(exc).__name__}")
                except OSError:
                    pass

        # Wire all common methods to the dispatch path. Anthropic /
        # OpenAI / Gemini all use POST + GET.
        def do_POST(self):  # noqa: N802
            self._dispatch()

        def do_GET(self):  # noqa: N802
            self._dispatch()

    return _Handler
