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
  L4. **Token bounded by request budget + TTL + explicit revocation.**
      Token can establish multiple connections within its budget +
      TTL — required so a worker process that spawns its own
      grandchildren (relayed via :func:`relay_for_grandchild`) can
      share the session without round-tripping the dispatcher for a
      fresh token. Connections after ``request_budget`` requests or
      ``ttl_s`` seconds are rejected; an explicit ``revoke`` flips
      the record to terminal state.
  L5. **Audit log.** Every accept / reject / dispatch event lands
      in a JSONL log. Body content is intentionally never logged.

The dispatcher does NOT terminate TLS, MITM, or read prompt/response
content beyond what's needed to inject the auth header and forward
bytes upstream.
"""

from __future__ import annotations

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

import httpx

from core.security.log_sanitisation import escape_nonprintable

from .auth import (
    BedrockTransformError,
    CredentialStore,
    ProviderRule,
    build_rules,
)

_logger = logging.getLogger(__name__)


# Audit event types whose terminal-visible log is duplicated by a
# higher-level layer's own visibility — demote to DEBUG so operator
# output isn't flooded. Consumed by ``_audit``; events not in this
# set stay at INFO. Audit log on disk records every event at full
# fidelity regardless.
#
# * ``request.dispatch`` (status="ok"): one per successful LLM call;
#   ~100+ per /agentic run. No operator action on success.
# * ``request.error`` (status="error"): one per upstream API
#   failure. The LLMClient retry loop catches the underlying
#   exception and emits its own WARNING ("Attempt N/M failed
#   for <provider>/<model>: <reason>") at the operator-relevant
#   abstraction layer. The dispatcher's INFO-level audit was a
#   third copy of the same fact, alongside the provider's own
#   error log — see the retry-dedupe commit for the full cluster.
_DEMOTED_AUDIT_EVENTS = frozenset({"request.dispatch"})


def _scrub(value: str | None) -> str | None:
    """Defang nonprintable + ANSI escapes in operator-visible
    fields (``worker_label``, ``reason``) before they hit the
    audit log or stdlib logger. Pre-fix a malicious model name
    or framework-supplied label could embed control sequences
    that corrupted terminal output / log-tail viewers — same
    threat model as ``core/security/prompt_output_sanitise``."""
    if value is None:
        return None
    return escape_nonprintable(value)


# ---------------------------------------------------------------------------
# Token bookkeeping
# ---------------------------------------------------------------------------


_TOKEN_DEFAULT_TTL_S = 8 * 60 * 60   # 8 hours — long-running /agentic
                                     # and /validate runs on large
                                     # codebases comfortably exceed
                                     # the original 1-hour cap.
_TOKEN_DEFAULT_BUDGET = 10_000       # requests per worker run — agentic
                                     # workflows over many findings can
                                     # easily clear 1k LLM calls.
_TOKEN_HEADER = "X-Raptor-Token"

# Scoped child tokens (CC CLI children) — defaults. TTL is short by
# design: the minting callsite passes its own run-length-derived TTL,
# and this floor only covers callers that don't.
_CHILD_DEFAULT_TTL_S = 30 * 60
_CHILD_DEFAULT_REQUEST_BUDGET = 1_000
# Providers a scoped child token may address. CC children speak the
# Anthropic Messages shape; the dispatcher fronts either the first-
# party API or Bedrock Mantle. Everything else is parent/worker-only.
_CHILD_ALLOWED_PROVIDERS = frozenset({"anthropic", "bedrock"})
# Child-token management endpoints — the parent/worker plane. Served
# on the UDS ONLY (peer-UID-verified, worker-token-gated); the TCP
# plane refuses them wholesale so a child holding only its scoped
# bearer token can never mint, revoke, or read other tokens.
_CHILD_ADMIN_PREFIX = "/_child/"

_UPSTREAM_DEFAULT_TIMEOUT_S = 600    # read/write/pool timeout on the
                                     # dispatcher→provider leg. Must be
                                     # at least the largest worker-side
                                     # timeout (claudecode/audit models
                                     # configure up to 600s): a
                                     # non-streaming call sends no bytes
                                     # until generation completes, so a
                                     # smaller value here kills long
                                     # generations with ReadTimeout →
                                     # 502 regardless of what the worker
                                     # configured on its own leg.
_UPSTREAM_CONNECT_TIMEOUT_S = 10.0


def _env_int(name: str, default: int, *, minimum: int = 1) -> int:
    """Read an int from the environment with a default + floor.

    Used to let an operator override the dispatcher TTL/budget
    without code edits. Out-of-range or non-numeric values fall
    back to ``default`` silently (with a debug-level log) so a
    typo doesn't break dispatcher startup.
    """
    raw = os.environ.get(name)
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        _logger.debug("llm-dispatcher: ignoring non-int %s=%r", name, raw)
        return default
    if value < minimum:
        _logger.debug(
            "llm-dispatcher: ignoring %s=%d below minimum %d",
            name, value, minimum,
        )
        return default
    return value


# The conventional proxy-route family (same set core.llm.egress
# snapshots as _PROXY_VAR_NAMES) — the forwarding-leg client is keyed
# on these because httpx resolves proxy mounts at client construction.
_PROXY_ENV_VARS = (
    "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "ALL_PROXY",
    "http_proxy", "https_proxy", "no_proxy", "all_proxy",
)


def _upstream_timeout() -> httpx.Timeout:
    """Timeout for the dispatcher→provider forwarding leg.

    Read from ``RAPTOR_LLM_DISPATCHER_UPSTREAM_TIMEOUT_S`` per request
    (cheap — one env lookup) so operators can tune it without code
    edits, same pattern as the token TTL/budget knobs. The connect
    timeout stays fixed and short: a provider that can't complete the
    TCP/TLS handshake in 10s is down, and a long connect timeout only
    delays the worker's failover.
    """
    read_s = _env_int(
        "RAPTOR_LLM_DISPATCHER_UPSTREAM_TIMEOUT_S",
        _UPSTREAM_DEFAULT_TIMEOUT_S,
    )
    return httpx.Timeout(float(read_s), connect=_UPSTREAM_CONNECT_TIMEOUT_S)


@dataclass
class _TokenRecord:
    value: str
    worker_label: str
    issued_at: float
    expires_at: float
    request_budget: int
    requests_made: int = 0
    status: str = "pending"   # pending → active → revoked|exhausted|expired
    # ---- scoping extension (kind="child") ----
    # One token concept, two transports: workers get the FD-passed
    # token and full provider access; CC CLI children get a SCOPED
    # token over HTTP bearer auth — spend-capped, model-allowlisted,
    # short-TTL. Scoping fields are inert for kind="worker".
    kind: str = "worker"                   # "worker" | "child"
    token_id: str = ""                     # public correlation id (child)
    budget_usd: float | None = None        # spend cap; None = uncapped
    spent_usd: float = 0.0                 # booked from upstream usage
    model_allowlist: frozenset | None = None   # normalized ids; None = any
    unpriced_requests: int = 0             # usage seen but model unpriced
    last_model: str | None = None


@dataclass(frozen=True)
class AuditEvent:
    """One row in the audit log. Body content is intentionally absent."""
    ts: float
    event: str
    peer_pid: int | None
    peer_uid: int | None
    token_id: str | None   # 12-char prefix for correlation; never the full token
    worker_label: str | None
    status: str
    reason: str | None = None
    extra: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Cross-platform peer-UID
# ---------------------------------------------------------------------------


def _peer_uid(conn: socket.socket) -> int | None:
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
# Child-token usage accounting
# ---------------------------------------------------------------------------


def _model_id_forms(model: str) -> frozenset:
    """All normalized spellings of *model* for allowlist comparison.

    A Bedrock install may pin ``us.anthropic.claude-x`` while the child
    requests the bare or Mantle form (or vice versa) — allowlist checks
    compare the union of forms on both sides so the operator's pin
    matches whatever spelling actually rides the request body.
    """
    forms = {model}
    try:
        from core.security.llm_family import bare_model_id
        forms.add(bare_model_id(model))
    except Exception:  # noqa: BLE001 — normalization is best-effort
        pass
    try:
        from core.llm.bedrock_prefixes import mantle_model_id
        forms.add(mantle_model_id(model))
    except Exception:  # noqa: BLE001
        pass
    return frozenset(f for f in forms if f)


class _UsageScanner:
    """Extract (model, token usage) from a forwarded response body.

    Fed the exact bytes relayed to the child (``Accept-Encoding:
    identity`` is forced on child-token requests so they are
    uncompressed). Keeps bounded head/tail windows — SSE streams put
    ``message_start`` (model + input/cache tokens) up front and the
    final ``message_delta`` usage frame at the end; JSON bodies carry
    ``model`` early and ``usage`` last. Never throws from ``feed``.
    """

    _HEAD_CAP = 256 * 1024
    _TAIL_CAP = 256 * 1024

    def __init__(self) -> None:
        self._head = bytearray()
        self._tail = bytearray()
        self.truncated = False

    def feed(self, chunk: bytes) -> None:
        if not chunk:
            return
        room = self._HEAD_CAP - len(self._head)
        if room > 0:
            self._head.extend(chunk[:room])
            chunk = chunk[room:]
        if chunk:
            self._tail.extend(chunk)
            if len(self._tail) > self._TAIL_CAP:
                del self._tail[:len(self._tail) - self._TAIL_CAP]
                self.truncated = True

    def extract(self) -> dict:
        """Return ``{model, input_tokens, output_tokens,
        cache_read_tokens, cache_creation_tokens}`` (zeros / None when
        the body carried no usage)."""
        out = {
            "model": None,
            "input_tokens": 0,
            "output_tokens": 0,
            "cache_read_tokens": 0,
            "cache_creation_tokens": 0,
        }
        head = self._head.decode("utf-8", "replace")
        tail = self._tail.decode("utf-8", "replace")
        if "data:" in head or "data:" in tail:
            for text in (head, tail):
                for line in text.splitlines():
                    line = line.strip()
                    if not line.startswith("data:"):
                        continue
                    try:
                        obj = json.loads(line[len("data:"):].strip())
                    except (json.JSONDecodeError, ValueError):
                        continue
                    if not isinstance(obj, dict):
                        continue
                    self._merge_event(obj, out)
            return out
        # Non-streamed JSON body.
        try:
            obj = json.loads(head + tail) if not self.truncated else None
        except (json.JSONDecodeError, ValueError):
            obj = None
        if isinstance(obj, dict):
            if isinstance(obj.get("model"), str):
                out["model"] = obj["model"]
            self._merge_usage(obj.get("usage"), out)
        return out

    @staticmethod
    def _merge_event(obj: dict, out: dict) -> None:
        etype = obj.get("type")
        if etype == "message_start":
            message = obj.get("message")
            if isinstance(message, dict):
                if isinstance(message.get("model"), str):
                    out["model"] = message["model"]
                _UsageScanner._merge_usage(message.get("usage"), out)
        elif etype == "message_delta":
            _UsageScanner._merge_usage(obj.get("usage"), out)

    @staticmethod
    def _merge_usage(usage, out: dict) -> None:
        if not isinstance(usage, dict):
            return
        for src, dst in (
            ("input_tokens", "input_tokens"),
            ("output_tokens", "output_tokens"),
            ("cache_read_input_tokens", "cache_read_tokens"),
            ("cache_creation_input_tokens", "cache_creation_tokens"),
        ):
            v = usage.get(src)
            if isinstance(v, int) and not isinstance(v, bool) and v >= 0:
                # Later frames report cumulative totals — take the max
                # so a final message_delta overrides, while partial
                # streams (abort) keep whatever the upstream reported.
                out[dst] = max(out[dst], v)


def _usage_cost_usd(usage: dict) -> tuple[float, bool]:
    """Price a scanned usage record. Returns ``(cost_usd, priced)``.

    ``priced`` is False when the model is unknown to the pricing table
    — the cost is then 0 and the caller records the gap loudly (an
    unpriced model silently disables the USD budget for its calls).
    """
    model = usage.get("model") or ""
    from core.llm.model_data import (
        ANTHROPIC_CACHE_READ_MULTIPLIER,
        ANTHROPIC_CACHE_WRITE_MULTIPLIER,
        price_for,
    )
    in_rate, out_rate = price_for(model)
    if (in_rate, out_rate) == (0.0, 0.0):
        return 0.0, False
    cost = (
        usage["input_tokens"] * in_rate
        + usage["output_tokens"] * out_rate
        + usage["cache_read_tokens"] * in_rate
        * ANTHROPIC_CACHE_READ_MULTIPLIER
        + usage["cache_creation_tokens"] * in_rate
        * ANTHROPIC_CACHE_WRITE_MULTIPLIER
    ) / 1_000_000.0
    return cost, True


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
        audit_path: Path | None = None,
        token_ttl_s: int | None = None,
        token_budget: int | None = None,
        creds: CredentialStore | None = None,
    ) -> None:
        self.run_id = run_id
        # TTL/budget resolution order: explicit caller arg →
        # ``RAPTOR_LLM_DISPATCHER_TOKEN_TTL_S`` / ``..._BUDGET`` env →
        # module default. Operators on long kernel-scale runs can
        # bump TTL without code edits; tests can pass a tiny value
        # via the call site.
        self._token_ttl_s = (
            token_ttl_s
            if token_ttl_s is not None
            else _env_int(
                "RAPTOR_LLM_DISPATCHER_TOKEN_TTL_S",
                _TOKEN_DEFAULT_TTL_S,
            )
        )
        self._token_budget = (
            token_budget
            if token_budget is not None
            else _env_int(
                "RAPTOR_LLM_DISPATCHER_TOKEN_BUDGET",
                _TOKEN_DEFAULT_BUDGET,
            )
        )

        self._creds = creds or CredentialStore()
        self._rules: dict[str, ProviderRule] = build_rules(self._creds)

        # One pooled client for the forwarding leg, shared by every
        # request (httpx.Client is thread-safe). Building a client
        # per request forced a fresh TCP + TLS handshake — and,
        # behind chained proxies, CONNECT negotiation per hop — on
        # every forwarded LLM call. Built lazily and keyed on the
        # proxy env (see _upstream_client): httpx snapshots proxy
        # routes at client construction, and the egress chokepoint
        # mutates HTTPS_PROXY in-process after the dispatcher may
        # already exist — a construction-time client would bypass it.
        self._upstream_http: httpx.Client | None = None
        self._upstream_http_env: tuple | None = None
        self._upstream_http_lock = threading.Lock()

        self._tokens: dict[str, _TokenRecord] = {}
        self._tokens_lock = threading.Lock()

        # Optional loopback TCP plane for CLI children (see
        # enable_loopback_listener). Not started unless a caller asks.
        self._tcp_server = None
        self._tcp_port = 0
        self._tcp_thread = None
        self._loopback_lock = threading.Lock()

        # L1 — filesystem isolation.
        self._sock_dir = Path(tempfile.mkdtemp(prefix=f"raptor-llm-{run_id}-"))
        # 0o700 = owner-only — the socket lives here and must not be
        # group/other-readable on a multi-user host.
        os.chmod(self._sock_dir, 0o700)  # nosemgrep: python.lang.security.audit.insecure-file-permissions
        self.socket_path = self._sock_dir / "llm.sock"

        # Audit log
        self._audit_path = audit_path
        self._audit_lock = threading.Lock()

        # Shutdown is wired to BOTH the context-manager exit / explicit
        # ``shutdown()`` call AND an ``atexit`` hook (see lifecycle.py).
        # The atexit hook fires at interpreter teardown — under pytest,
        # after the capture streams are already closed — so a second
        # ``shutdown()`` that did real work (rmdir on the already-removed
        # dir, plus an audit log line) raised FileNotFoundError and then
        # cascaded into "I/O operation on closed file" logging errors.
        # Guard makes shutdown idempotent: the second call is a no-op.
        self._shutdown_lock = threading.Lock()
        self._shutdown_done = False

        # Init may fail past this point (bind error, thread start
        # failure). On failure the tempdir would otherwise leak.
        try:
            self._init_server(run_id)
        except Exception:
            # Best-effort cleanup so /tmp/raptor-llm-* doesn't
            # accumulate after init failures.
            try:
                self.socket_path.unlink(missing_ok=True)
            except OSError:
                pass
            try:
                self._sock_dir.rmdir()
            except OSError:
                pass
            raise

    def _init_server(self, run_id: str) -> None:
        # The body below was inlined in __init__ pre-cleanup-fix; lifted
        # here so the try/except wrapper can clean up the tempdir on
        # any partial-init failure.

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

        # Quiet third-party loggers (httpx HTTP-request lines,
        # google.genai AFC banner, etc.) so operator output during
        # /agentic / /understand / /validate isn't drowned in
        # transport-layer chatter. WARNING and above still
        # surface so real failures aren't hidden.
        from core.llm.log_quiet import quiet_noisy_loggers
        quiet_noisy_loggers()

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
        try:
            os.write(write_fd, token.encode("ascii"))
        except OSError:
            # OS-level write failure (BrokenPipeError, ENOSPC,
            # EBADF after a fork-race). Close BOTH FDs to avoid
            # leaking the pipe — pre-fix only the success path
            # closed write_fd and the read_fd was returned to the
            # caller, so a failed write leaked both ends.
            try:
                os.close(write_fd)
            except OSError:
                pass
            try:
                os.close(read_fd)
            except OSError:
                pass
            raise
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

    def allocate_child(
        self,
        label: str,
        *,
        budget_usd: float,
        models: list | tuple | None = None,
        ttl_s: int | None = None,
        request_budget: int | None = None,
    ) -> tuple[str, dict]:
        """Issue a SCOPED token for one CC CLI child.

        Same store and issuance plumbing as :meth:`allocate_worker`,
        with the scoping extension: a USD spend cap (booked from the
        upstream-reported usage of every forwarded call), an optional
        model allowlist (normalized — bare / Mantle / prefixed
        spellings all match), and a short TTL sized by the caller to
        its run length. The token value is returned to the CALLER
        (parent / worker process) which passes it to the child as its
        HTTP bearer credential; unlike worker tokens there is no FD
        hop — the child is a foreign CLI, not RAPTOR code.

        Returns ``(token, info)`` where ``info`` carries ``token_id``
        (public correlation id, safe to log), ``expires_at`` and the
        effective limits.
        """
        if not isinstance(budget_usd, (int, float)) or budget_usd <= 0:
            raise ValueError(f"budget_usd must be > 0, got {budget_usd!r}")
        ttl = int(ttl_s) if ttl_s else _CHILD_DEFAULT_TTL_S
        if ttl <= 0:
            raise ValueError(f"ttl_s must be > 0, got {ttl_s!r}")
        allowlist: frozenset | None = None
        if models:
            forms: set = set()
            for m in models:
                if isinstance(m, str) and m:
                    forms |= _model_id_forms(m)
            allowlist = frozenset(forms) or None
        token = secrets.token_urlsafe(32)
        token_id = secrets.token_hex(8)
        now = time.time()
        rec = _TokenRecord(
            value=token,
            worker_label=label,
            issued_at=now,
            expires_at=now + ttl,
            request_budget=(
                int(request_budget) if request_budget
                else _CHILD_DEFAULT_REQUEST_BUDGET
            ),
            kind="child",
            token_id=token_id,
            budget_usd=float(budget_usd),
            model_allowlist=allowlist,
        )
        with self._tokens_lock:
            self._tokens[token] = rec
        self._audit(AuditEvent(
            ts=now, event="child_token.issue",
            peer_pid=None, peer_uid=None,
            token_id=token_id, worker_label=label,
            status="ok",
            extra={
                "budget_usd": float(budget_usd),
                "ttl_s": ttl,
                "models": sorted(allowlist) if allowlist else None,
            },
        ))
        return token, {
            "token_id": token_id,
            "expires_at": rec.expires_at,
            "budget_usd": rec.budget_usd,
            "request_budget": rec.request_budget,
        }

    def revoke_child(self, token_id: str) -> bool:
        """Flip a child token to terminal ``revoked`` state.

        Keyed by the public ``token_id`` so callers never need to
        retain (or log) the secret. The record is RETAINED so its
        spend stays readable post-run; validation rejects it. Returns
        False when no child token matches.
        """
        with self._tokens_lock:
            rec = self._child_by_id_locked(token_id)
            if rec is None:
                return False
            rec.status = "revoked"
        self._audit(AuditEvent(
            ts=time.time(), event="child_token.revoke",
            peer_pid=None, peer_uid=None,
            token_id=token_id, worker_label=rec.worker_label,
            status="ok",
        ))
        return True

    def child_spend(self, token_id: str) -> dict | None:
        """Spend/limits snapshot for one child token (by public id)."""
        with self._tokens_lock:
            rec = self._child_by_id_locked(token_id)
            if rec is None:
                return None
            return {
                "token_id": rec.token_id,
                "label": rec.worker_label,
                "status": rec.status,
                "spent_usd": rec.spent_usd,
                "budget_usd": rec.budget_usd,
                "requests_made": rec.requests_made,
                "unpriced_requests": rec.unpriced_requests,
                "last_model": rec.last_model,
                "expires_at": rec.expires_at,
            }

    def _child_by_id_locked(self, token_id: str) -> _TokenRecord | None:
        """Find a child record by public id. Caller holds _tokens_lock."""
        if not token_id:
            return None
        for rec in self._tokens.values():
            if rec.kind == "child" and rec.token_id == token_id:
                return rec
        return None

    def _authorize_child_request(
        self, rec: _TokenRecord, provider_name: str, method: str,
        body: bytes,
    ) -> tuple[int, str] | None:
        """Scoped-token enforcement before the forward leg.

        Returns ``(http_status, reason)`` to reject, or None to allow.
        Order: provider scope → method shape → model allowlist →
        budget. The budget check runs BEFORE the forward so an
        exhausted token never reaches the provider.
        """
        if provider_name not in _CHILD_ALLOWED_PROVIDERS:
            return 403, (
                f"scoped token: provider '{provider_name}' not permitted"
            )
        if method != "POST":
            return 405, "scoped token: only POST requests are permitted"
        model = ""
        try:
            payload = json.loads(body) if body else {}
            if isinstance(payload, dict):
                model = str(payload.get("model") or "")
        except (json.JSONDecodeError, UnicodeDecodeError):
            model = ""
        if not model:
            return 400, "scoped token: request body carries no model"
        if rec.model_allowlist is not None and not (
            _model_id_forms(model) & rec.model_allowlist
        ):
            return 403, (
                f"scoped token: model '{model}' not in allowlist"
            )
        with self._tokens_lock:
            rec.last_model = model
            if rec.budget_usd is not None and rec.spent_usd >= rec.budget_usd:
                rec.status = "exhausted"
                return 402, (
                    f"scoped token budget exhausted: spent "
                    f"${rec.spent_usd:.4f} of ${rec.budget_usd:.4f}"
                )
        return None

    def _book_child_usage(
        self, rec: _TokenRecord, scanner: "_UsageScanner",
        *, aborted: bool,
    ) -> None:
        """Book upstream-reported usage onto the token's spend ledger.

        Runs on success AND on abort — a partially-streamed response
        already cost real money; the ``message_start`` frame's input
        tokens are the floor of what the upstream reported. Nothing
        vanishes: the parent-side reconciliation reads this ledger as
        the failed-attempt floor (max-of-ledgers, matching the
        provider-ledger contract for failed CC calls).
        """
        usage = scanner.extract()
        cost, priced = _usage_cost_usd(usage)
        saw_usage = any(
            usage[k] for k in (
                "input_tokens", "output_tokens",
                "cache_read_tokens", "cache_creation_tokens",
            )
        )
        with self._tokens_lock:
            if cost:
                rec.spent_usd += cost
            if saw_usage and not priced:
                rec.unpriced_requests += 1
            if usage.get("model"):
                rec.last_model = usage["model"]
        if saw_usage and not priced:
            _logger.warning(
                "llm-dispatcher: model %r absent from the pricing table "
                "— scoped-token spend for this call booked as $0 (USD "
                "budget not enforced for it)", usage.get("model"),
            )
        self._audit(AuditEvent(
            ts=time.time(), event="child_token.spend",
            peer_pid=None, peer_uid=None,
            token_id=rec.token_id, worker_label=rec.worker_label,
            status="ok" if not aborted else "aborted",
            extra={
                "cost_usd": cost,
                "spent_usd": rec.spent_usd,
                "model": usage.get("model"),
                "input_tokens": usage["input_tokens"],
                "output_tokens": usage["output_tokens"],
                "priced": priced,
            },
        ))

    def enable_loopback_listener(self) -> int:
        """Start (idempotently) the loopback TCP plane and return its port.

        The TCP plane exists for CLI children that cannot speak
        HTTP-over-UDS (``claude`` reads ``ANTHROPIC_BASE_URL`` — an
        http URL). It serves the SAME handler and token store with a
        reduced surface: only scoped child tokens authenticate
        (worker tokens are refused — the full-power capability never
        rides the plane that lacks peer-UID verification), and the
        ``/_child/*`` management endpoints are refused wholesale.
        Bound to 127.0.0.1 with an ephemeral port; non-loopback peers
        are dropped pre-parse.
        """
        with self._loopback_lock:
            if self._tcp_server is not None:
                return self._tcp_port
            dispatcher = self

            class _LoopbackHTTPServer(
                socketserver.ThreadingMixIn, http.server.HTTPServer,
            ):
                daemon_threads = True
                allow_reuse_address = True

                def verify_request(self, request, client_address):
                    # Loopback-only peers. The bind address already
                    # guarantees this; the check defends against a
                    # surprising rebind and mirrors the UDS peer gate.
                    if client_address[0] != "127.0.0.1":
                        dispatcher._audit(AuditEvent(
                            ts=time.time(), event="peer.reject",
                            peer_pid=None, peer_uid=None,
                            token_id=None, worker_label=None,
                            status="reject",
                            reason=f"non-loopback peer {client_address[0]}",
                        ))
                        return False
                    return True

            handler_cls = _make_request_handler(dispatcher, plane="tcp")
            self._tcp_server = _LoopbackHTTPServer(
                ("127.0.0.1", 0), handler_cls,
            )
            self._tcp_port = self._tcp_server.server_address[1]
            self._tcp_thread = threading.Thread(
                target=self._tcp_server.serve_forever,
                name=f"raptor-llm-dispatcher-tcp-{self.run_id}",
                daemon=True,
            )
            self._tcp_thread.start()
            self._audit(AuditEvent(
                ts=time.time(), event="server.loopback_start",
                peer_pid=None, peer_uid=None,
                token_id=None, worker_label=None,
                status="ok", extra={"port": self._tcp_port},
            ))
            return self._tcp_port

    def _upstream_client(self) -> httpx.Client:
        """The pooled forwarding-leg client, rebuilt on proxy-env change.

        httpx resolves proxy routes when the client is CONSTRUCTED,
        not per request. The egress chokepoint
        (``core.llm.egress.enable_llm_egress``) points HTTPS_PROXY at
        the in-process proxy after startup, so the client is keyed on
        a snapshot of the proxy env: same env → full connection
        reuse; env changed → rebuild once and reuse from there. Env
        changes happen at startup, before workers dispatch — closing
        the superseded client here cannot race an in-flight stream in
        any real sequence, and a hypothetical racer surfaces as a
        502 the worker SDK already retries.
        """
        env = tuple(os.environ.get(v) for v in _PROXY_ENV_VARS)
        with self._upstream_http_lock:
            if self._upstream_http is None or self._upstream_http_env != env:
                from core.llm.http_pool import (
                    http2_enabled,
                    pool_limits,
                    response_event_hooks,
                )
                old = self._upstream_http
                self._upstream_http = httpx.Client(
                    timeout=_upstream_timeout(), limits=pool_limits(),
                    http2=http2_enabled(),
                    event_hooks=response_event_hooks(),
                )
                self._upstream_http_env = env
                if old is not None:
                    try:
                        old.close()
                    except Exception:
                        _logger.debug(
                            "llm-dispatcher: superseded upstream client "
                            "close failed", exc_info=True,
                        )
            return self._upstream_http

    def shutdown(self) -> None:
        """Stop the server thread and remove the socket directory.

        Pre-fix every step silently swallowed any exception and the
        audit event was emitted as ``status="ok"`` regardless. A
        deadlocked-but-throwing ``server.shutdown()`` or an
        ``unlink``/``rmdir`` blocked by a still-bound socket left the
        dispatcher reporting clean stop while a tempdir leaked + the
        process may have kept accepting on a half-shut server.
        Each step's failure now logs at WARNING with the traceback,
        and the audit event records ``status="partial"`` with a
        reason summary when anything went wrong.

        Idempotent: a second call (e.g. the ``atexit`` hook firing after
        an explicit ``shutdown()`` / context-manager exit already ran) is
        a no-op. This avoids a spurious ``FileNotFoundError`` on the
        already-removed socket dir and the closed-stream logging cascade
        it triggers during interpreter teardown.
        """
        with self._shutdown_lock:
            if self._shutdown_done:
                return
            self._shutdown_done = True
        errors: list[str] = []
        if self._tcp_server is not None:
            try:
                self._tcp_server.shutdown()
                self._tcp_server.server_close()
            except Exception:
                _logger.warning(
                    "llm-dispatcher: loopback listener shutdown failed",
                    exc_info=True,
                )
                errors.append("loopback_shutdown")
        try:
            self._server.shutdown()
        except Exception:
            _logger.warning(
                "llm-dispatcher: server.shutdown() failed", exc_info=True,
            )
            errors.append("shutdown")
        try:
            self._server.server_close()
        except Exception:
            _logger.warning(
                "llm-dispatcher: server.server_close() failed", exc_info=True,
            )
            errors.append("server_close")
        try:
            if self._upstream_http is not None:
                self._upstream_http.close()
        except Exception:
            _logger.warning(
                "llm-dispatcher: upstream client close failed", exc_info=True,
            )
            errors.append("upstream_http_close")
        # Remove socket file then dir
        try:
            self.socket_path.unlink(missing_ok=True)
        except Exception:
            _logger.warning(
                "llm-dispatcher: socket unlink failed for %s",
                self.socket_path, exc_info=True,
            )
            errors.append("socket_unlink")
        try:
            self._sock_dir.rmdir()
        except FileNotFoundError:
            # Dir already gone — that IS the goal state, not a leak.
            # (e.g. a prior shutdown removed it, or the tmp area was
            # cleaned out from under us.) No warning, no error record.
            pass
        except Exception:
            _logger.warning(
                "llm-dispatcher: sock_dir rmdir failed for %s "
                "(leak — operator may need to clean manually)",
                self._sock_dir, exc_info=True,
            )
            errors.append("sock_dir_rmdir")
        self._audit(AuditEvent(
            ts=time.time(), event="server.stop",
            peer_pid=None, peer_uid=None,
            token_id=None, worker_label=None,
            status="ok" if not errors else "partial",
            reason=",".join(errors) if errors else None,
        ))

    # ---- internal ----

    def _audit(self, ev: AuditEvent) -> None:
        # Defang nonprintable / ANSI escapes on operator-visible
        # fields. ``token_id`` is already a hex prefix (12 chars)
        # so it doesn't need scrubbing, and ``event`` / ``status``
        # are internally produced strings.
        safe_worker = _scrub(ev.worker_label)
        safe_reason = _scrub(ev.reason)
        # Log level chosen by event type:
        # * Events in ``_DEMOTED_AUDIT_EVENTS`` → DEBUG. These are
        #   duplicated by a higher-level layer's own operator-
        #   visible logging (LLMClient retry loop) or fire on
        #   every LLM call without operator action (request.dispatch
        #   ok). See the constant's docstring for per-event
        #   rationale.
        # * Server lifecycle, token issuance, any unknown event
        #   type → INFO. Low-frequency, operator-actionable, or
        #   both.
        # Audit log on disk continues to record EVERY event at
        # full fidelity — this only affects the stdlib logger
        # that terminal output uses.
        if ev.event in _DEMOTED_AUDIT_EVENTS:
            level = logging.DEBUG
        else:
            level = logging.INFO
        # Always log via stdlib logger for terminal visibility.
        # ``ev.token_id`` is a 12-character correlation prefix (see
        # ``AuditEvent.token_id`` docstring) — explicitly NOT the
        # full token. Operator visibility for the auth flow needs
        # SOME identifier; the prefix gives correlation without
        # disclosure.
        # nosemgrep: python.lang.security.audit.logging.logger-credential-leak.python-logger-credential-disclosure
        parts = [f"llm-dispatcher {ev.event} {ev.status}"]
        if ev.peer_pid is not None:
            parts.append(f"pid={ev.peer_pid}")
        if ev.peer_uid is not None:
            parts.append(f"uid={ev.peer_uid}")
        if ev.token_id:
            parts.append(f"token={ev.token_id}")
        if safe_worker:
            parts.append(f"label={safe_worker}")
        if safe_reason:
            parts.append(f"reason={safe_reason}")
        try:
            _logger.log(level, " ".join(parts))
        except OSError:
            pass
        if self._audit_path is None:
            return
        with self._audit_lock:
            try:
                # Open with mode 0o600 — audit log records worker labels,
                # peer UIDs/PIDs, token-id prefixes, and request paths.
                # The socket dir is already 0o700 / sockets 0o600; this
                # closes the symmetric gap.
                fd = os.open(
                    self._audit_path,
                    os.O_WRONLY | os.O_APPEND | os.O_CREAT,
                    0o600,
                )
                with os.fdopen(fd, "a", encoding="utf-8") as fh:
                    fh.write(json.dumps({
                        "ts": ev.ts,
                        "event": ev.event,
                        "peer_pid": ev.peer_pid,
                        "peer_uid": ev.peer_uid,
                        "token_id": ev.token_id,
                        "worker_label": safe_worker,
                        "status": ev.status,
                        "reason": safe_reason,
                        **ev.extra,
                    }) + "\n")
            except OSError as e:
                # Audit failures must NEVER break the dispatcher (an
                # out-of-disk shouldn't crash an in-flight LLM
                # session). But silent swallow hid an entire
                # production incident: the audit log path was
                # unwritable for the whole run, every event was
                # dropped, and the operator only found out when
                # /project status reported empty audit metrics.
                # Surface ONCE via stdlib logger at WARNING — the
                # ``_audit_warned`` flag stops the per-event flood.
                if not getattr(self, "_audit_warned", False):
                    _logger.warning(
                        "llm-dispatcher: audit log write failed for %s "
                        "(further failures will be silent): %s",
                        self._audit_path, e,
                    )
                    self._audit_warned = True

    def _validate_token(self, raw: str | None) -> tuple[_TokenRecord | None, str | None]:
        """L3 + L4 — return (record, None) on success, (None, reason)
        on rejection. Increments ``requests_made`` and revokes if
        budget exhausted or TTL elapsed."""
        if not raw:
            return None, "missing token"
        with self._tokens_lock:
            rec = self._tokens.get(raw)
            if rec is None:
                return None, "unknown token"
            # Terminal-state handling: worker records are EVICTED to
            # prevent unbounded growth; child records are RETAINED so
            # their spend ledger stays readable post-run (the parent
            # reconciles token spend after the child exits, which may
            # be after expiry/revocation). The dispatcher is per-run
            # and child counts are small, so retention is bounded.
            evict = rec.kind != "child"
            if rec.status in ("revoked", "exhausted", "expired"):
                if evict:
                    self._tokens.pop(raw, None)
                return None, f"token {rec.status}"
            now = time.time()
            if now >= rec.expires_at:
                rec.status = "expired"
                if evict:
                    self._tokens.pop(raw, None)
                # Token age distinguishes "worker outlived its TTL"
                # from a clock/config anomaly without cross-referencing
                # the token.issue event.
                return None, (
                    f"token expired (age {now - rec.issued_at:.1f}s, "
                    f"ttl {int(rec.expires_at - rec.issued_at)}s)"
                )
            if rec.requests_made >= rec.request_budget:
                rec.status = "exhausted"
                if evict:
                    self._tokens.pop(raw, None)
                return None, "token budget exhausted"
            rec.status = "active"
            rec.requests_made += 1
            return rec, None

    def _provider(self, name: str) -> ProviderRule | None:
        return self._rules.get(name)


def _short(token: str) -> str:
    """Return a short prefix of a token for audit correlation. Never
    log the full token — it's a credential."""
    return token[:12]


# ---------------------------------------------------------------------------
# HTTP request handler
# ---------------------------------------------------------------------------


_PROVIDER_FROM_PATH_PREFIX = {
    "/anthropic/":    "anthropic",
    "/openai/":       "openai",
    "/gemini/":       "gemini",
    # OpenAI-compatible aggregators + ecosystem providers added in
    # Phase C-β. Each routes by the same prefix shape; the rule's
    # ``upstream_base_url`` decides where the request actually goes.
    "/mistral/":      "mistral",
    "/groq/":         "groq",
    "/together/":     "together",
    "/openrouter/":   "openrouter",
    "/orcarouter/":   "orcarouter",
    "/fireworks/":    "fireworks",
    "/deepinfra/":    "deepinfra",
    "/perplexity/":   "perplexity",
    "/cohere/":       "cohere",
    "/replicate/":    "replicate",
    "/azure_openai/": "azure_openai",
    # AWS Bedrock — routed by prefix like the others, but the rule
    # carries a ``prepare_request`` hook that rewrites + SigV4-signs the
    # request rather than injecting a static header.
    "/bedrock/":      "bedrock",
}


def _make_request_handler(
    dispatcher: LLMDispatcher, plane: str = "uds",
) -> type:
    """Build a BaseHTTPRequestHandler subclass closed over the
    dispatcher instance. Factory so the dispatcher is plumbed in
    without mutable global state.

    ``plane`` selects the transport surface: ``"uds"`` (the peer-UID-
    verified Unix socket — workers, and the parent/worker child-token
    management endpoints) or ``"tcp"`` (the loopback listener for CLI
    children — scoped child tokens only, management refused).
    """

    class _Handler(http.server.BaseHTTPRequestHandler):

        # Disable BaseHTTPRequestHandler's reverse DNS log spam — peer
        # is always the local socket on UDS anyway.
        def log_message(self, format, *args):
            return

        def _send_simple(self, status: int, reason: str) -> None:
            body = json.dumps({"error": reason}).encode("utf-8")
            self.send_response(status, reason)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)

        def _send_json(self, status: int, payload: dict) -> None:
            body = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)

        def _presented_token(self) -> str | None:
            """The credential the peer presented, wherever it rides.

            Workers use the ``X-Raptor-Token`` header; CC CLI children
            authenticate with ``ANTHROPIC_AUTH_TOKEN``, which the CLI
            sends as ``Authorization: Bearer <token>`` (and the
            Anthropic SDK may echo as ``x-api-key``). One token
            concept — the store decides what the value is scoped to.
            """
            token = self.headers.get(_TOKEN_HEADER)
            if token:
                return token
            auth = self.headers.get("Authorization") or ""
            if auth.startswith("Bearer "):
                return auth[len("Bearer "):].strip() or None
            return self.headers.get("x-api-key") or None

        def _dispatch(self) -> None:
            # ---- L3+L4 — token check (pre-body: nothing is read
            # from the wire beyond headers until the token clears) ----
            token = self._presented_token()
            rec, reason = dispatcher._validate_token(token)
            if rec is not None and plane == "tcp" and rec.kind != "child":
                # Full-power worker tokens never authenticate on the
                # plane without peer-UID verification.
                rec, reason = None, "worker tokens are not accepted here"
            if rec is None:
                dispatcher._audit(AuditEvent(
                    ts=time.time(), event="token.reject",
                    peer_pid=None, peer_uid=None,
                    token_id=_short(token) if token else None,
                    worker_label=None, status="reject", reason=reason,
                ))
                self._send_simple(401, reason or "unauthorized")
                return

            # ---- child-token management plane (/_child/*) ----
            if self.path.startswith(_CHILD_ADMIN_PREFIX):
                if plane != "uds" or rec.kind != "worker":
                    # Scoped child tokens can never mint, revoke, or
                    # read other tokens — and the endpoints do not
                    # exist at all off the peer-UID-verified socket.
                    dispatcher._audit(AuditEvent(
                        ts=time.time(), event="child_admin.reject",
                        peer_pid=None, peer_uid=None,
                        token_id=(rec.token_id or _short(rec.value)),
                        worker_label=rec.worker_label,
                        status="reject",
                        reason=f"plane={plane} kind={rec.kind}",
                    ))
                    self._send_simple(
                        403,
                        "child-token management requires a worker token "
                        "on the dispatcher socket",
                    )
                    return
                self._child_admin(rec)
                return

            # ---- provider routing via path prefix ----
            provider_name: str | None = None
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
            # Scoped-child control-plane shim: Claude Code's Bedrock
            # client probes ``GET <bedrock-base>/inference-profiles``
            # (cross-region profile discovery) before its first model
            # call. A credential-proxy child has no business reading
            # the real AWS control plane — answer the probe with an
            # empty listing so the CLI proceeds on its configured
            # model, without granting any AWS reach.
            if (
                rec.kind == "child"
                and provider_name == "bedrock"
                and self.command == "GET"
                and upstream_path.partition("?")[0].rstrip("/")
                    .endswith("/inference-profiles")
            ):
                dispatcher._audit(AuditEvent(
                    ts=time.time(), event="child_token.control_plane",
                    peer_pid=None, peer_uid=None,
                    token_id=rec.token_id,
                    worker_label=rec.worker_label,
                    status="ok", reason="inference-profiles (canned)",
                ))
                self._send_json(200, {"inferenceProfileSummaries": []})
                return

            rule = dispatcher._provider(provider_name)
            # "Configured?" defaults to "has an injectable header", but a
            # rule may override it (Bedrock needs botocore + AWS creds +
            # region, not a single header).
            configured = (
                rule is not None
                and (
                    rule.is_configured() if rule.is_configured is not None
                    else bool(rule.inject_headers())
                )
            )
            if not configured:
                dispatcher._audit(AuditEvent(
                    ts=time.time(), event="provider.unconfigured",
                    peer_pid=None, peer_uid=None,
                    token_id=_short(rec.value), worker_label=rec.worker_label,
                    status="reject", reason=provider_name,
                ))
                self._send_simple(503, f"provider not configured: {provider_name}")
                return

            # ---- request body ----
            try:
                content_length = int(self.headers.get("Content-Length", "0"))
            except (ValueError, TypeError):
                self._send_simple(400, "invalid Content-Length")
                return
            body = self.rfile.read(content_length) if content_length else b""

            method = self.command

            # ---- scoped-token enforcement (kind="child") ----
            if rec.kind == "child":
                deny = dispatcher._authorize_child_request(
                    rec, provider_name, method, body,
                )
                if deny is not None:
                    status, why = deny
                    dispatcher._audit(AuditEvent(
                        ts=time.time(), event="child_token.reject",
                        peer_pid=None, peer_uid=None,
                        token_id=rec.token_id,
                        worker_label=rec.worker_label,
                        status="reject", reason=why,
                        extra={"http_status": status},
                    ))
                    self._send_simple(status, why)
                    return

            if rule.prepare_request is not None:
                # Provider with a non-static auth scheme (Bedrock SigV4):
                # the rule rewrites + signs the request and we forward
                # exactly what it returns. No further header rewriting —
                # any edit would invalidate the signature.
                try:
                    prepared = rule.prepare_request(
                        method, upstream_path, self.headers, body,
                    )
                except BedrockTransformError as exc:
                    dispatcher._audit(AuditEvent(
                        ts=time.time(), event="provider.transform_reject",
                        peer_pid=None, peer_uid=None,
                        token_id=_short(rec.value), worker_label=rec.worker_label,
                        status="reject", reason=f"{provider_name}: {exc.message}",
                    ))
                    self._send_simple(exc.status, exc.message)
                    return
                except Exception as exc:  # noqa: BLE001
                    # Any OTHER exception from request preparation is an
                    # upstream-signing failure we can't turn into a request —
                    # most importantly a botocore credential refresh
                    # (SSO/IMDS token expiry mid-run) raising inside
                    # SigV4Auth.add_auth. Without this catch the exception
                    # escapes the handler thread: the worker sees a dropped
                    # connection with no HTTP status and no audit row. Map it
                    # to a 502 + audit so the failure is visible and the
                    # worker SDK surfaces a clean error. Log only the
                    # exception TYPE (botocore messages can embed request
                    # context) — never its rendered message.
                    dispatcher._audit(AuditEvent(
                        ts=time.time(), event="provider.transform_error",
                        peer_pid=None, peer_uid=None,
                        token_id=_short(rec.value), worker_label=rec.worker_label,
                        status="error", reason=f"{provider_name}: {type(exc).__name__}",
                    ))
                    self._send_simple(502, f"request signing failed: {type(exc).__name__}")
                    return
                method = prepared.method
                url = prepared.url
                body = prepared.body
                forwarded = dict(prepared.headers)
            else:
                # ---- header rewrite (static strip + inject) ----
                forwarded = {}
                for k, v in self.headers.items():
                    if k.lower() in rule.strip_request_headers:
                        continue
                    if k.lower() in ("host", "content-length", _TOKEN_HEADER.lower()):
                        continue
                    forwarded[k] = v
                forwarded.update(rule.inject_headers())
                url = rule.upstream_base_url + upstream_path

            # Scoped tokens are spend-capped from the upstream-reported
            # usage, which the dispatcher reads from the bytes it
            # relays — force identity encoding so the response is
            # parseable in flight (Anthropic gzips by default). Safe
            # for the SigV4 path: the header is added AFTER signing and
            # unsigned headers don't participate in verification.
            scanner: _UsageScanner | None = None
            if rec.kind == "child":
                scanner = _UsageScanner()
                forwarded["Accept-Encoding"] = "identity"

            # ---- forward to upstream + stream response back ----
            _up_http_version = None
            try:
                with dispatcher._upstream_client().stream(
                    method, url, content=body, headers=forwarded,
                    timeout=_upstream_timeout(),
                ) as up:
                    try:
                        from core.llm.http_pool import (
                            _normalize_http_version,
                        )

                        _up_http_version = _normalize_http_version(
                            up.http_version,
                        )
                    except Exception:
                        _up_http_version = None
                    self.send_response(up.status_code)
                    for k, v in up.headers.items():
                        # Strip hop-by-hop headers only. ``content-
                        # encoding`` is response-scoped and MUST be
                        # preserved: ``iter_raw()`` below forwards
                        # the upstream's still-compressed bytes (it
                        # does not auto-decompress), so the worker
                        # needs the header to know to decompress.
                        # Stripping it ships gzipped bytes labelled
                        # as plain JSON — Anthropic always gzips,
                        # so worker SDK calls choke on the bytes.
                        if k.lower() in (
                            "transfer-encoding",
                            "connection",
                        ):
                            continue
                        self.send_header(k, v)
                    self.end_headers()
                    for chunk in up.iter_raw():
                        if scanner is not None:
                            scanner.feed(chunk)
                        self.wfile.write(chunk)
                    self.wfile.flush()
                if scanner is not None:
                    dispatcher._book_child_usage(
                        rec, scanner, aborted=False,
                    )
                dispatcher._audit(AuditEvent(
                    ts=time.time(), event="request.dispatch",
                    peer_pid=None, peer_uid=None,
                    token_id=_short(rec.value), worker_label=rec.worker_label,
                    status="ok",
                    extra={
                        "provider": provider_name, "method": method,
                        "path": upstream_path,
                        # Negotiated protocol on the upstream leg
                        # (h1/h2) — makes HTTP/2 service provable
                        # from the dispatch audit trail.
                        "http_version": _up_http_version,
                    },
                ))
            except (httpx.HTTPError, OSError) as exc:
                if scanner is not None:
                    # Aborted mid-stream — book what the upstream
                    # already reported (message_start input tokens at
                    # minimum). A failed call still spent real money;
                    # nothing vanishes from the token's ledger.
                    dispatcher._book_child_usage(
                        rec, scanner, aborted=True,
                    )
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

        def _child_admin(self, rec: _TokenRecord) -> None:
            """Handle /_child/{mint,revoke,spend} for a validated
            WORKER token on the UDS plane (gated by the caller)."""
            op = self.path[len(_CHILD_ADMIN_PREFIX):].split("?", 1)[0]
            payload: dict = {}
            try:
                content_length = int(
                    self.headers.get("Content-Length", "0"),
                )
            except (ValueError, TypeError):
                self._send_simple(400, "invalid Content-Length")
                return
            if content_length:
                raw = self.rfile.read(content_length)
                try:
                    parsed = json.loads(raw)
                except (json.JSONDecodeError, UnicodeDecodeError):
                    self._send_simple(400, "body is not valid JSON")
                    return
                if not isinstance(parsed, dict):
                    self._send_simple(400, "body must be a JSON object")
                    return
                payload = parsed
            if op == "mint":
                budget = payload.get("budget_usd")
                models = payload.get("models")
                if models is not None and not isinstance(models, list):
                    self._send_simple(400, "models must be a list or null")
                    return
                try:
                    token, info = dispatcher.allocate_child(
                        str(payload.get("label") or rec.worker_label
                            or "cc-child"),
                        budget_usd=(
                            float(budget)
                            if isinstance(budget, (int, float))
                            and not isinstance(budget, bool) else 0.0
                        ),
                        models=models,
                        ttl_s=(
                            int(payload["ttl_s"])
                            if isinstance(payload.get("ttl_s"), (int, float))
                            else None
                        ),
                        request_budget=(
                            int(payload["request_budget"])
                            if isinstance(
                                payload.get("request_budget"), (int, float),
                            )
                            else None
                        ),
                    )
                except (ValueError, TypeError) as exc:
                    self._send_simple(400, f"mint rejected: {exc}")
                    return
                self._send_json(200, {"token": token, **info})
                return
            if op == "revoke":
                token_id = str(payload.get("token_id") or "")
                if not dispatcher.revoke_child(token_id):
                    self._send_simple(404, "unknown token_id")
                    return
                self._send_json(200, {"revoked": True, "token_id": token_id})
                return
            if op == "spend":
                token_id = str(payload.get("token_id") or "")
                if not token_id and "?" in self.path:
                    from urllib.parse import parse_qs, urlsplit
                    qs = parse_qs(urlsplit(self.path).query)
                    token_id = (qs.get("token_id") or [""])[0]
                snapshot = dispatcher.child_spend(token_id)
                if snapshot is None:
                    self._send_simple(404, "unknown token_id")
                    return
                self._send_json(200, snapshot)
                return
            self._send_simple(404, f"unknown child-admin op: {op!r}")

        # Wire all common methods to the dispatch path. Anthropic /
        # OpenAI / Gemini all use POST + GET.
        def do_POST(self):
            self._dispatch()

        def do_GET(self):
            self._dispatch()

    return _Handler
