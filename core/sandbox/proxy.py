"""Local HTTPS egress proxy for sandboxed subprocesses.

Closes two gaps in the `allowed_tcp_ports=[443]` posture that `cc_dispatch`
and similar Claude-sub-agent callers had to rely on:

1. UDP exfil: Landlock's network rule is TCP-CONNECT only, so a
   compromised sub-agent could previously exfiltrate via DNS/UDP. When
   this proxy is used, callers enable the seccomp UDP block (see
   seccomp.py) — the child has no direct network at all, and every
   outbound connection has to land on the proxy's TCP port, which
   enforces a hostname allowlist.
2. Port-only allowlist: Landlock's TCP allowlist is `(port)` not
   `(host, port)`. A sub-agent with `allowed_tcp_ports=[443]` could
   reach any server on :443, including localhost services (e.g., a
   dev-mode internal HTTPS app). With this proxy, only the proxy's
   ephemeral loopback port is reachable; the proxy validates the
   destination hostname and refuses anything outside the allowlist.

Architecture:
- In-process: runs on a daemon thread inside RAPTOR's Python process.
  No subprocess, no IPC, no lifecycle hooks. Daemon thread terminates
  automatically on interpreter exit; `atexit` handler closes sockets
  as defense-in-depth.
- asyncio event loop in the daemon thread handles many concurrent
  tunnels without thread-per-connection. RAPTOR's main code stays
  fully synchronous — callers just see `get_proxy().port` as an int.
- HTTP CONNECT method only. Proxy tunnels raw TLS bytes between child
  and backend; it does NOT terminate TLS (no MITM, no cert forging).
- Hostname allowlist is UNION across all callers: if cc_dispatch asks
  for {api.anthropic.com} and a later caller asks for {ghcr.io}, both
  hosts are allowed globally. Trust model: RAPTOR's own code is the
  only thing that registers hosts, and all sandboxed children are
  equally untrusted. Per-caller allowlists would require mapping each
  TCP connection back to its originating caller, which isn't worth
  the complexity given the threat model.

Safety hooks baked in:
- Bind: 127.0.0.1 only, NEVER 0.0.0.0. Checked at socket setup.
- Ephemeral port: assigned by the kernel (bind port 0). No collision
  with whatever else is on the box, no well-known port to probe.
- Host validation: resolve the CONNECT target once per tunnel, reject
  if the resolved IP is loopback, private (RFC 1918), link-local, or
  multicast. Stops a compromised child from using the proxy to reach
  internal services on the host's LAN.
- DNS pinning: one resolve per tunnel, then connect to that exact IP.
  No mid-tunnel re-resolution — removes the DNS-rebinding window.
- Idle timeout: 300s. Total tunnel duration cap: 3600s. Either bound
  limits how long one compromised child can hold resources open.
- Concurrent tunnels: capped at 64 (configurable). Hard limit on
  resource consumption by a runaway child.
- Buffer size: 64 KiB per direction. Bounds memory per tunnel.
- Audit log: every CONNECT logs {host, port, result, bytes}, INFO level.
- No Proxy-Authorization: localhost-only bind + same-UID trust model.

HTTP CONNECT protocol (RFC 7231 §4.3.6):
    CONNECT host:port HTTP/1.1\r\n
    Host: host:port\r\n
    (optional headers)\r\n
    \r\n

Response:
    HTTP/1.1 200 Connection established\r\n\r\n
    (then raw bytes in both directions)

Error responses:
    400 Bad Request       — malformed CONNECT line
    403 Forbidden         — host not in allowlist OR resolved to blocked IP
    502 Bad Gateway       — backend refused / unreachable
    504 Gateway Timeout   — backend didn't respond within timeout
"""

import asyncio
import atexit
import ipaddress
import logging
import socket
import threading
import time
from typing import Iterable, List, Optional, Set

logger = logging.getLogger(__name__)

# Connection bounds — per-tunnel and aggregate. Tunable via EgressProxy
# constructor kwargs but the defaults are deliberately conservative.
_DEFAULT_IDLE_TIMEOUT = 300.0        # seconds of silence before forced close
_DEFAULT_TOTAL_TIMEOUT = 3600.0      # absolute cap on a single tunnel
_DEFAULT_MAX_TUNNELS = 64            # concurrent CONNECT tunnels
_DEFAULT_BUFFER_SIZE = 64 * 1024     # relay buffer per direction

# Canonical filename for the per-run proxy events JSONL. Written by
# context.py (post-sandbox flush of unregister_sandbox events). Defined
# here so consumers of the proxy module reference one source-of-truth
# rather than the literal string.
PROXY_EVENTS_FILENAME = "proxy-events.jsonl"

# Canonical set of values the `result` field of a proxy event may take.
# Test consumers (test_proxy_audit, test_e2e_sandbox) filter events by
# this string — silent drift between proxy emits and consumer
# expectations would cause filtered-by-result test queries to return
# nothing. Pinned by structural test (test_audit_filter.py) that scans
# proxy.py for `result="..."` literals and asserts membership in this
# set.
_PROXY_EVENT_RESULTS = frozenset({
    # Connection succeeded (with or without bytes flowed yet)
    "allowed",
    # Gate 1 (hostname allowlist) deny — enforce mode
    "denied_host",
    # Gate 1 audit-mode would-deny (allow + log)
    "would_deny_host",
    # Gate 2 (resolved IP block / DNS-rebinding defense) deny —
    # always enforcing, never audit-allowed. There is NO
    # `would_deny_resolved_ip` event; in audit mode gate 2 still
    # emits `denied_resolved_ip` AND additionally writes a
    # supplementary record to summary via record_denial.
    "denied_resolved_ip",
    # DNS resolution failed (NXDOMAIN, timeout)
    "dns_failed",
    # Upstream (or backend) refused / unreachable
    "upstream_failed",
    # Total tunnel duration cap exceeded mid-relay
    "timed_out",
    # Malformed CONNECT line / bad headers
    "bad_request",
    # Unhandled exception in tunnel handler
    "handler_error",
})

# Thread-safe singleton. `get_proxy()` is the sole entry point.
_lock = threading.Lock()
_instance: Optional["EgressProxy"] = None


def _record_proxy_denial(host: str, port: int, resolved_ip: Optional[str],
                         would_deny: str) -> None:
    """Route a proxy-side audit-mode denial into the per-run sandbox
    summary via core.sandbox.summary.record_denial.

    Called for two cases in audit mode:
    - gate 1 (host not in allowlist) audit-fall-through: the CONNECT
      succeeds and the child sees nothing, so the proxy has to emit
      the record itself or it never lands in the summary.
    - gate 2 (resolved IP blocked) deny: gate 2 stays enforcing in
      audit mode because it's the proxy's DNS-rebinding/DNS-poisoning
      defense, but we ALSO call this so the attack signal lands in
      sandbox-summary.json (not only in proxy-events.jsonl).

    cmd_display uses the CONNECT description (always accurate) rather
    than the originating sandbox's caller_label. The proxy is process-
    wide and serves all registered sandboxes; there's no source-port→
    sandbox mapping at this layer, so any caller-label attribution
    would be a heuristic. Operators wanting attribution can cross-
    reference proxy-events.jsonl which has the matching event with the
    same host/port at the same timestamp.

    Lazy import: keeps core.sandbox.summary out of proxy module load,
    matching the lazy import already used in core/run/metadata.py.

    Performance note: record_denial does sync open/write/close on the
    asyncio event-loop thread. Each record is ~300 bytes and the
    MAX_DENIALS_PER_RUN cap (10000) bounds worst-case I/O volume —
    fine for normal disks. If audit-mode CONNECTs ever stall under
    slow-fs / adversarial-fs conditions, wrap with asyncio.to_thread.
    """
    try:
        from core.sandbox.summary import record_denial
        # ASCII separator rather than Unicode arrow — record_denial
        # writes the JSONL with ensure_ascii=True, so a "→" becomes the
        # escape sequence "→" on disk and operators reading
        # sandbox-summary.json see noise instead of the separator.
        cmd = (f"<egress-proxy CONNECT {host}:{port}>" if resolved_ip is None
               else f"<egress-proxy CONNECT {host}:{port} -> {resolved_ip}>")
        details = {"host": host, "port": port,
                   "would_deny": would_deny, "audit": True}
        if resolved_ip is not None:
            details["resolved_ip"] = resolved_ip
        record_denial(cmd, 0, "network", **details)
    except Exception:  # noqa: BLE001 — best-effort; never fail a CONNECT
        # Deliberate scope: Exception, not BaseException. SystemExit and
        # KeyboardInterrupt SHOULD propagate so the process can exit.
        # record_denial is documented to never raise either of those —
        # if a future change makes it raise SystemExit, the gate-2 deny
        # path's `await self._write_error(...)` would be skipped because
        # the exception escapes this helper. Don't introduce that path.
        logger.debug("_record_proxy_denial: record_denial failed",
                     exc_info=True)


def _ip_is_blocked(ip_str: str) -> bool:
    """Reject any address that isn't routable on the public Internet.

    Prevents a compromised child from using the proxy to pivot into
    internal services on the host's LAN or the host's own loopback
    interface (where a dev-mode HTTPS service might be exposed), or
    into cloud metadata endpoints (169.254.169.254).

    Implementation: `ipaddress.IPvXAddress.is_global == False` covers
    the full "not for public routing" set in one attribute — loopback,
    private (RFC 1918), carrier-grade NAT (100.64.0.0/10), link-local,
    multicast, reserved / future-use (240.0.0.0/4, 2002::/16 6to4,
    TEST-NET-*/documentation ranges), unspecified, and IPv4-mapped
    IPv6 forms of all of the above. An earlier OR-chain missed
    CGNAT 100.64/10, which is_private doesn't flag.
    """
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return True  # unparseable → reject, fail-closed
    return not ip.is_global


def _parse_proxy_url(url: Optional[str]) -> Optional[tuple]:
    """Parse a proxy URL like `http://corp-proxy:3128` into (host, port).

    Returns None if url is None/empty. Raises ValueError for malformed
    URLs so startup fails fast rather than silently skipping upstream
    tunnelling (which would be a data-exfil footgun in a corporate
    network where DIRECT egress is blocked but a bypass via the
    our-proxy-direct path would route around the corp proxy).
    """
    if not url:
        return None
    from urllib.parse import urlparse
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(
            f"egress proxy: unsupported upstream scheme in {url!r} — "
            f"only http:// and https:// are honoured"
        )
    if not parsed.hostname:
        raise ValueError(f"egress proxy: no host in upstream URL {url!r}")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    # Userinfo (auth) not supported yet — most corporate proxies that
    # require auth use Kerberos/SPNEGO or NTLM which need more than an
    # env-var password anyway. If this becomes a real need, add a
    # Proxy-Authorization header here.
    if parsed.username or parsed.password:
        raise ValueError(
            "egress proxy: auth in upstream URL not supported; "
            "configure proxy-side auth or file a feature request"
        )
    return (parsed.hostname, port)


def _parse_no_proxy(value: Optional[str]) -> list:
    """Parse NO_PROXY (comma-separated host patterns).

    Each entry is a host suffix: `internal.corp` matches
    `foo.internal.corp` and `internal.corp` exactly but not `nope.com`.
    A leading dot is tolerated (`.internal.corp`). `*` is treated as
    "bypass all" — equivalent to no upstream. Empty string = no
    exclusions (route everything through upstream).
    """
    if not value:
        return []
    patterns = []
    for raw in value.split(","):
        p = raw.strip().lower().lstrip(".")
        if p:
            patterns.append(p)
    return patterns


def _host_in_no_proxy(host: str, patterns: list) -> bool:
    """Check if a host matches any NO_PROXY pattern (suffix match)."""
    h = host.lower()
    for p in patterns:
        if p == "*":
            return True
        if h == p or h.endswith("." + p):
            return True
    return False


class EgressProxy:
    """HTTPS CONNECT proxy with hostname allowlist.

    Not typically constructed directly — use module-level get_proxy().
    """

    def __init__(self, allowed_hosts: Iterable[str],
                 idle_timeout: float = _DEFAULT_IDLE_TIMEOUT,
                 total_timeout: float = _DEFAULT_TOTAL_TIMEOUT,
                 max_tunnels: int = _DEFAULT_MAX_TUNNELS,
                 buffer_size: int = _DEFAULT_BUFFER_SIZE,
                 upstream_proxy: Optional[str] = None,
                 no_proxy: Optional[str] = None,
                 audit_log_only: bool = False):
        self._hosts_lock = threading.Lock()
        self._allowed_hosts: Set[str] = {h.lower() for h in allowed_hosts}
        # When True, gate 1 (hostname allowlist) emits a `would_deny_host`
        # event AND a record_denial entry, then falls through to the
        # connect path — operator workflows that hit gate 1 keep working
        # but the policy violation is logged. Gate 2 (resolved-IP block)
        # is the proxy's DNS-rebinding/DNS-poisoning defense and stays
        # ENFORCING regardless: it has no legitimate-workflow false
        # positives (an allowlisted hostname resolving to a private/
        # loopback IP is purely an attack signal). In audit mode gate 2
        # additionally records the deny into the summary.
        #
        # Operator-facing wiring: context.py engages this via
        # acquire_audit_log_only() / release_audit_log_only() when an
        # audit-mode sandbox enters/exits. The constructor kwarg here
        # remains for direct test construction. Tests of the toggle
        # itself MUST use the acquire/release API to exercise the ref-
        # counting; concurrent mixed-profile sandbox correctness depends
        # on it.
        self._audit_log_only = audit_log_only
        # Ref-count for concurrent acquire/release. Each audit-mode
        # sandbox via use_egress_proxy=True acquires on entry, releases
        # on exit. Gate 1 is in audit-log mode iff count > 0. Without
        # this, mixed-profile concurrent sandboxes would race —
        # specifically, a non-audit sandbox could see its CONNECTs
        # silently downgraded to allow-and-log (security weakening)
        # because a sibling audit sandbox flipped the singleton's flag.
        self._audit_lock = threading.Lock()
        self._audit_count = 1 if audit_log_only else 0
        self._idle_timeout = idle_timeout
        self._total_timeout = total_timeout
        self._max_tunnels = max_tunnels
        self._buffer_size = buffer_size
        self._active_tunnels = 0
        self._active_lock = threading.Lock()
        # Upstream proxy support — for corporate environments where the
        # user's HTTPS_PROXY env var points at an outbound HTTP proxy
        # that must be traversed to reach any external host. Parsed URL
        # stored as (host, port) tuple; None = direct connect. The
        # upstream host is trusted to resolve to any IP (private
        # corporate addresses are expected), unlike target hostnames.
        self._upstream: Optional[tuple] = _parse_proxy_url(upstream_proxy)
        # NO_PROXY honoured when an upstream is configured: any host
        # matching a pattern bypasses the upstream and connects directly
        # (so internal services like git-server.corp remain reachable).
        self._no_proxy_patterns: list = _parse_no_proxy(no_proxy)
        # Event ring buffer for observability. Each entry is a dict:
        #   {"t": monotonic_seconds, "host": str, "port": int,
        #    "result": one of _PROXY_EVENT_RESULTS (see module-level
        #              constant — pinned by structural test so any
        #              new result string fires the test until added),
        #    "reason": str|None, "resolved_ip": str|None,
        #    "bytes_c2u": int, "bytes_u2c": int, "duration": float}
        # `t` uses time.monotonic() for monotonicity across clock jumps.
        #
        # Per-sandbox buffers. Each active sandbox() context registers
        # via register_sandbox(), receives a token, and on exit reads
        # back its accumulated event list via unregister_sandbox(). The
        # proxy fans every recorded event into every registered buffer.
        # Per-sandbox buffers (rather than one shared ring) eliminate
        # the flood-masks-attack evasion of the old time-windowed deque
        # design: a child making 10 000 CONNECTs to allow-listed hosts
        # can no longer push an earlier denied CONNECT out of a shared
        # 1024-entry deque before the sandbox ends and flushes to file.
        # Each sandbox's buffer grows independently. Memory cost is
        # ~300 bytes per event per active sandbox.
        self._sandbox_buffers: dict = {}
        self._sandbox_labels: dict = {}
        self._next_token = 0
        self._buffer_lock = threading.Lock()

        # Synchronise startup: the thread runs the asyncio loop and signals
        # `_ready` once the server is bound and port is known. The calling
        # thread blocks on _ready before returning from __init__, so
        # callers see a fully-ready proxy or an exception.
        self._ready = threading.Event()
        self._start_error: Optional[BaseException] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._server: Optional[asyncio.AbstractServer] = None
        self.port: int = 0

        self._thread = threading.Thread(
            target=self._run_loop,
            name="raptor-egress-proxy",
            daemon=True,
        )
        self._thread.start()
        self._ready.wait()
        if self._start_error is not None:
            raise RuntimeError(
                f"egress proxy failed to start: {self._start_error}"
            ) from self._start_error

    # ----- public API -----

    def add_hosts(self, hosts: Iterable[str]) -> None:
        """Extend the allowlist. Idempotent. Thread-safe."""
        with self._hosts_lock:
            self._allowed_hosts.update(h.lower() for h in hosts)

    def acquire_audit_log_only(self) -> None:
        """Increment the audit-mode reference count and ensure
        audit-log mode is engaged on the hostname gate.

        Ref-counted to prevent concurrent mixed-profile sandboxes
        from racing on the singleton: when an audit-mode sandbox
        enters via use_egress_proxy=True, it acquires; on exit it
        releases. The gate is in audit-log mode iff at least one
        audit-mode sandbox is active. A concurrent NON-audit sandbox
        does NOT release the count (it never acquired in the first
        place), so its CONNECTs stay properly enforced.

        Without ref-counting, a non-ref-counted setter on the
        singleton (the design that pre-dated this acquire/release
        API) would have allowed a sibling non-audit sandbox to
        unset audit mode while an audit-mode peer was still active
        — weakening the gate's enforcement under concurrent
        mixed-profile usage. And vice-versa: an audit-mode set
        would have allowed a non-audit peer's CONNECTs to non-
        allowlisted hosts to slip through.

        Gate 2 (resolved-IP block) is unaffected — it's the proxy's
        DNS-rebinding defense and stays enforcing in every mode.
        """
        with self._audit_lock:
            self._audit_count += 1
            self._audit_log_only = (self._audit_count > 0)
            # Log the first acquisition (security-property change
            # visibility — matches the disable_from_cli WARNING style).
            if self._audit_count == 1:
                logger.warning(
                    "egress proxy: hostname gate switched to "
                    "AUDIT-LOG mode (CONNECT to non-allowlisted "
                    "hosts will be ALLOWED and logged, not denied). "
                    "Engaged by `--audit` flag."
                )

    def release_audit_log_only(self) -> None:
        """Decrement the audit-mode reference count. When it reaches
        zero, the hostname gate returns to enforcing mode.

        Idempotent at zero — extra release()s are silently clamped
        (defensive: an exception path that runs cleanup twice
        shouldn't push the count negative). Logs the transition only
        when count was actually decremented from 1 to 0; idempotent
        zero-releases don't log so an over-eager cleanup path doesn't
        spam the operator with misleading "returned to enforcing"
        messages when nothing actually changed.
        """
        with self._audit_lock:
            transitioned_to_zero = False
            if self._audit_count > 0:
                self._audit_count -= 1
                transitioned_to_zero = (self._audit_count == 0)
            self._audit_log_only = (self._audit_count > 0)
            if transitioned_to_zero:
                logger.info(
                    "egress proxy: hostname gate returned to "
                    "ENFORCING mode (no audit-mode sandbox active)"
                )

    def is_host_allowed(self, host: str) -> bool:
        """Check if a host is in the allowlist (case-insensitive)."""
        with self._hosts_lock:
            return host.lower() in self._allowed_hosts

    def register_sandbox(self, caller_label: Optional[str] = None) -> int:
        """Register an active sandbox and receive a token.

        While registered, every tunnel event the proxy records is
        fanned into this sandbox's private event list. `caller_label`
        (if provided) is stamped onto each event as `event["caller"]`
        so post-mortem filtering can separate, e.g., claude-sub-agent
        traffic from codeql-pack-download even when they share the
        proxy singleton.

        Must be paired with `unregister_sandbox(token)` — typically via
        try/finally around the sandboxed subprocess invocation. The
        token is opaque; callers must not inspect it.
        """
        with self._buffer_lock:
            self._next_token += 1
            token = self._next_token
            self._sandbox_buffers[token] = []
            self._sandbox_labels[token] = caller_label
            return token

    def unregister_sandbox(self, token: int) -> List[dict]:
        """Stop forwarding events to this sandbox and return its buffer.

        The returned list is a fresh copy of each event with the
        caller_label stamped onto it (if set at registration). Copying
        happens HERE rather than at record-time because some event
        fields (bytes_c2u, bytes_u2c, duration) are mutated in place
        after the tunnel CONNECT is first recorded — keeping a
        reference in the buffer and copying at unregister means the
        caller sees the final stats, not the at-open snapshot. The
        returned dicts are caller-owned; further mutation by the proxy
        (another tunnel under a different sandbox) is invisible.

        Idempotent on an unknown token — returns [] so callers in
        finally blocks can always call this without a try/except.
        """
        with self._buffer_lock:
            events = self._sandbox_buffers.pop(token, [])
            label = self._sandbox_labels.pop(token, None)
        # Copy + stamp outside the lock — `events` is no longer in
        # `_sandbox_buffers` so _record won't touch it. Still, other
        # tunnel handlers may be mutating the underlying dict
        # references via `event.update(...)` — we copy defensively.
        if label is not None:
            return [{**e, "caller": label} for e in events]
        return [dict(e) for e in events]

    def _record(self, event: dict) -> None:
        """Fan a tunnel event into every registered sandbox's buffer.

        Each buffer holds a REFERENCE to the same event dict, NOT a
        copy. That's deliberate: the tunnel handler records at CONNECT
        open (so short tunnels completing around subprocess-end still
        appear) and then updates bytes_c2u / bytes_u2c / duration in
        place when the tunnel closes. A record-time copy would freeze
        the event with bytes==0 / duration==initial. Copying is
        deferred to `unregister_sandbox` where we can do it once per
        caller with the caller_label stamp.

        No-op when no sandbox is registered (rare — means the proxy is
        processing a CONNECT that happened outside any register /
        unregister window, e.g. during proxy shutdown).
        """
        with self._buffer_lock:
            for buf in self._sandbox_buffers.values():
                buf.append(event)

    def stop(self) -> None:
        """Close the server and stop the event loop. Safe to call twice."""
        if self._loop is None:
            return
        try:
            self._loop.call_soon_threadsafe(self._loop.stop)
        except RuntimeError:
            pass  # loop already stopped

    def is_alive(self) -> bool:
        """True if the proxy's event-loop thread is still running.

        `get_proxy()` checks this on re-entry — if the singleton exists
        but its thread died (e.g. asyncio.start_server raised post-init,
        or an unhandled exception escaped), we tear down the zombie
        instance so the next call can create a fresh one instead of
        handing back a broken proxy that silently fails every
        connection.
        """
        return self._thread is not None and self._thread.is_alive()

    # ----- thread entry -----

    def _run_loop(self) -> None:
        try:
            self._loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self._loop)
            self._server = self._loop.run_until_complete(
                asyncio.start_server(
                    self._handle_client,
                    host="127.0.0.1",     # loopback ONLY
                    port=0,               # ephemeral
                    reuse_address=False,
                )
            )
            sock = self._server.sockets[0]
            bound_host, bound_port = sock.getsockname()[:2]
            # Defence against a misconfigured interpreter or OS that
            # somehow bound to a non-loopback address.
            if bound_host != "127.0.0.1":
                self._server.close()
                raise RuntimeError(
                    f"proxy bound to non-loopback {bound_host!r} — refusing to serve"
                )
            self.port = bound_port
            logger.info(
                f"egress proxy listening on 127.0.0.1:{self.port} "
                f"(allowlist: {sorted(self._allowed_hosts)})"
            )
            self._ready.set()
            self._loop.run_forever()
        except BaseException as e:
            self._start_error = e
            self._ready.set()
            return
        finally:
            if self._server is not None:
                self._server.close()
                try:
                    self._loop.run_until_complete(self._server.wait_closed())
                except Exception:
                    pass
            self._loop.close()

    # ----- async CONNECT handler -----

    async def _handle_client(self, reader: asyncio.StreamReader,
                             writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername") or ("?", 0)
        client_ip = peer[0] if peer else "?"

        # Additional belt-and-braces: reject any inbound connection that
        # isn't from loopback (shouldn't happen — we bind to 127.0.0.1 —
        # but if it did, bail).
        if client_ip not in ("127.0.0.1", "::1"):
            logger.warning(f"egress proxy: rejecting non-loopback peer {client_ip}")
            writer.close()
            return

        # Aggregate tunnel cap. Enforced best-effort — a race between
        # check and increment can let 65+ through momentarily, but the
        # bound holds to ~max.
        #
        # Must NOT `await` while holding a threading.Lock — the lock is
        # sync, so a second _handle_client task hitting `with
        # self._active_lock:` on the same event-loop thread would call
        # lock.acquire() which blocks the ENTIRE event loop (not just
        # the task). The first task's in-flight `writer.drain()` then
        # never fires — deadlock. Decide the verdict under the lock,
        # then drop it before issuing the rejection.
        full = False
        with self._active_lock:
            if self._active_tunnels >= self._max_tunnels:
                full = True
            else:
                self._active_tunnels += 1
        if full:
            logger.warning(
                f"egress proxy: max tunnels ({self._max_tunnels}) reached — "
                f"refusing new connection"
            )
            try:
                await self._write_error(writer, 429, "Too Many Tunnels")
            finally:
                # The reject path used to `return` before the try/finally
                # below the cap-counter, so the writer was never closed
                # on rejection — every 429 leaked the inbound socket.
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass
            return

        try:
            await self._serve_tunnel(reader, writer)
        except asyncio.CancelledError:
            # Event-loop shutdown or tunnel-guard timeout — propagate.
            raise
        except Exception as exc:
            # Any uncaught exception inside a tunnel handler must NOT
            # kill the event loop. Log with exception info and move on;
            # the rest of the proxy (other tunnels, singleton lifetime)
            # stays up. Record the incident as a proxy event with
            # result="handler_error" so post-mortem log review sees it.
            logger.exception(
                "egress proxy: unhandled exception in tunnel handler — "
                "connection aborted, proxy stays up"
            )
            self._record({
                "t": time.monotonic(),
                "host": None, "port": None,
                "result": "handler_error",
                "reason": f"{exc.__class__.__name__}: {exc}",
                "resolved_ip": None,
                "bytes_c2u": 0, "bytes_u2c": 0, "duration": 0.0,
            })
        finally:
            with self._active_lock:
                self._active_tunnels -= 1
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def _serve_tunnel(self, reader: asyncio.StreamReader,
                            writer: asyncio.StreamWriter) -> None:
        t_start = time.monotonic()
        event = {
            "t": t_start, "host": None, "port": None,
            "result": None, "reason": None, "resolved_ip": None,
            "bytes_c2u": 0, "bytes_u2c": 0, "duration": 0.0,
        }

        # Read CONNECT line + headers. Enforce small header budget to
        # prevent memory-exhaustion by a client that streams headers.
        request_line = await _read_line(reader, max_len=4096)
        if request_line is None:
            event.update(result="bad_request", reason="empty/overlong CONNECT line",
                         duration=time.monotonic() - t_start)
            self._record(event)
            await self._write_error(writer, 400, "Bad Request")
            return

        parts = request_line.split()
        if len(parts) != 3 or parts[0] != "CONNECT" or not parts[2].startswith("HTTP/"):
            event.update(result="bad_request", reason=f"malformed: {request_line[:80]!r}",
                         duration=time.monotonic() - t_start)
            self._record(event)
            await self._write_error(writer, 400, "Bad Request")
            return

        target = parts[1]
        # Reject non-printable characters in the CONNECT target. A
        # sandboxed client that includes ESC (0x1b) / CR / NUL / C1
        # controls / Unicode line separators in the host field would
        # otherwise have those bytes echoed verbatim into the proxy's
        # log output — terminal escape injection (change colours, set
        # window title, overwrite prior lines to spoof "all clear"
        # entries). JSON logging (proxy-events.jsonl) is safe because
        # json.dumps escapes control chars, but the logger.warning/info
        # calls below interpolate the host into human-readable messages
        # that may reach a live terminal. See
        # core.security.log_sanitisation.has_nonprintable.
        from core.security.log_sanitisation import has_nonprintable
        if has_nonprintable(target):
            event.update(result="bad_request",
                         reason="non-printable characters in CONNECT target",
                         duration=time.monotonic() - t_start)
            self._record(event)
            await self._write_error(writer, 400, "Bad Request")
            return
        if ":" not in target:
            event.update(result="bad_request", reason="no port in target",
                         duration=time.monotonic() - t_start)
            self._record(event)
            await self._write_error(writer, 400, "Bad Request")
            return
        host, _, port_str = target.rpartition(":")
        # Strip IPv6 brackets if present: [::1]:443.
        # `str.strip("[]")` strips ANY leading/trailing `[` or `]`
        # regardless of pairing, so `]example.com[` would also collapse
        # to `example.com` — which doesn't match the IPv6-bracket
        # intent. Only strip when both bookends are present together.
        if host.startswith("[") and host.endswith("]"):
            host = host[1:-1]
        try:
            port = int(port_str)
        except ValueError:
            event.update(host=host, result="bad_request", reason="non-numeric port",
                         duration=time.monotonic() - t_start)
            self._record(event)
            await self._write_error(writer, 400, "Bad Request")
            return
        if not (0 < port < 65536):
            event.update(host=host, port=port, result="bad_request",
                         reason="port out of range",
                         duration=time.monotonic() - t_start)
            self._record(event)
            await self._write_error(writer, 400, "Bad Request")
            return
        event["host"] = host
        event["port"] = port

        # Drain remaining headers (we don't use them, but we must read
        # past them to honour the protocol).
        while True:
            hdr = await _read_line(reader, max_len=4096)
            if hdr is None or hdr == "":
                break

        # Policy gate 1: hostname allowlist.
        if not self.is_host_allowed(host):
            # Snapshot the audit-log flag under the audit lock at the
            # decision point. The flag is mutated by acquire/release
            # ref-counting from other threads; an unlocked read here
            # (CPython-atomic for bools, but no happens-before edge
            # against the increment in acquire_audit_log_only) could
            # in principle read a stale True after a concurrent
            # release dropped the count to zero. The snapshot pattern
            # makes the race window explicit and the outcome
            # consistent with the count value at the snapshot moment.
            with self._audit_lock:
                _audit_now = self._audit_log_only
            if _audit_now:
                # Audit mode: record the would-deny but proceed with the
                # CONNECT. Use a distinct event result so consumers can
                # tell audit-would-deny apart from real-deny in the same
                # proxy-events.jsonl. The audit event captures intent;
                # the later "allowed" event captures the actual outcome
                # (so a single CONNECT in audit mode produces TWO event
                # records — one would-deny, one allowed).
                logger.warning(
                    f"egress proxy: AUDIT would-deny {host}:{port} — "
                    f"not in allowlist (audit mode: allowing)"
                )
                audit_event = {**event, "result": "would_deny_host",
                               "reason": "host not in allowlist (audit mode)",
                               "duration": time.monotonic() - t_start}
                self._record(audit_event)
                _record_proxy_denial(host, port, None,
                                     "host_not_in_allowlist")
                # Fall through to the connect path.
            else:
                logger.warning(
                    f"egress proxy: DENY {host}:{port} — not in allowlist"
                )
                event.update(result="denied_host", reason="host not in allowlist",
                             duration=time.monotonic() - t_start)
                self._record(event)
                await self._write_error(writer, 403, "Forbidden")
                return

        # Decide path: direct or via upstream proxy.
        use_upstream = (self._upstream is not None
                        and not _host_in_no_proxy(host, self._no_proxy_patterns))

        if use_upstream:
            # Tunnel through the user's upstream HTTPS_PROXY. The upstream
            # handles DNS of the target host; we just CONNECT to the
            # upstream's (host, port) directly. Upstream IP is trusted
            # — corporate proxies legitimately live on private IPs.
            up_host, up_port = self._upstream
            event["resolved_ip"] = f"{up_host}:{up_port} (upstream)"
            try:
                up_reader, up_writer = await asyncio.wait_for(
                    asyncio.open_connection(host=up_host, port=up_port),
                    timeout=10.0,
                )
            except (OSError, asyncio.TimeoutError) as e:
                logger.warning(
                    f"egress proxy: upstream proxy unreachable "
                    f"{up_host}:{up_port}: {e}"
                )
                event.update(result="upstream_failed",
                             reason=f"upstream proxy connect: {e.__class__.__name__}: {e}",
                             duration=time.monotonic() - t_start)
                self._record(event)
                await self._write_error(writer, 502, "Bad Gateway")
                return

            # Negotiate CONNECT with the upstream. Upstream responds with
            # HTTP/1.1 200 Connection established on success, or 4xx/5xx
            # with a reason we surface back to the child.
            req = (f"CONNECT {host}:{port} HTTP/1.1\r\n"
                   f"Host: {host}:{port}\r\n\r\n").encode("latin-1")
            up_writer.write(req)
            try:
                await asyncio.wait_for(up_writer.drain(), timeout=10.0)
                resp_line = await asyncio.wait_for(
                    up_reader.readuntil(b"\r\n"), timeout=10.0,
                )
            except (asyncio.TimeoutError, asyncio.IncompleteReadError,
                    ConnectionError) as e:
                logger.warning(f"egress proxy: upstream CONNECT failed: {e}")
                up_writer.close()
                event.update(result="upstream_failed",
                             reason=f"upstream CONNECT handshake: {e.__class__.__name__}",
                             duration=time.monotonic() - t_start)
                self._record(event)
                await self._write_error(writer, 502, "Bad Gateway")
                return

            # Parse "HTTP/1.1 200 ..."
            resp_str = resp_line.decode("latin-1", errors="replace").rstrip()
            status_parts = resp_str.split(None, 2)
            if len(status_parts) < 2 or status_parts[1] != "200":
                logger.warning(
                    f"egress proxy: upstream rejected CONNECT {host}:{port} "
                    f"— {resp_str!r}"
                )
                up_writer.close()
                event.update(result="upstream_failed",
                             reason=f"upstream returned: {resp_str!r}",
                             duration=time.monotonic() - t_start)
                self._record(event)
                await self._write_error(writer, 502, "Bad Gateway")
                return

            # Drain remaining upstream headers up to blank line.
            while True:
                try:
                    hdr = await asyncio.wait_for(
                        up_reader.readuntil(b"\r\n"), timeout=5.0,
                    )
                except (asyncio.TimeoutError, asyncio.IncompleteReadError):
                    break
                if hdr == b"\r\n":
                    break
        else:
            # Direct path — resolve target, reject private/loopback IPs,
            # open connection to resolved address.
            try:
                addrinfo = await asyncio.wait_for(
                    self._loop.getaddrinfo(host, port, type=socket.SOCK_STREAM),
                    timeout=10.0,
                )
            except asyncio.TimeoutError:
                logger.warning(f"egress proxy: DNS timeout for {host}:{port}")
                event.update(result="dns_failed", reason="DNS timeout",
                             duration=time.monotonic() - t_start)
                self._record(event)
                await self._write_error(writer, 504, "Gateway Timeout")
                return
            except socket.gaierror as e:
                logger.warning(f"egress proxy: DNS failure for {host}:{port}: {e}")
                event.update(result="dns_failed", reason=f"DNS: {e}",
                             duration=time.monotonic() - t_start)
                self._record(event)
                await self._write_error(writer, 502, "Bad Gateway")
                return

            if not addrinfo:
                event.update(result="dns_failed", reason="no addresses returned",
                             duration=time.monotonic() - t_start)
                self._record(event)
                await self._write_error(writer, 502, "Bad Gateway")
                return

            # Policy gate 2: reject resolved IPs that point to loopback /
            # private / link-local. Stops a (hypothetical future) allowlisted
            # hostname whose DNS now points to 127.x.
            family, socktype, proto, _, sockaddr = addrinfo[0]
            resolved_ip = sockaddr[0]
            event["resolved_ip"] = resolved_ip
            if _ip_is_blocked(resolved_ip):
                # Gate 2 is the proxy's DNS-rebinding / IP-poisoning
                # defense — always on whenever the proxy is in the loop,
                # regardless of audit_log_only. Resolving an allowlisted
                # hostname to a private/loopback/metadata IP has no
                # legitimate workflow rationale; only DNS attacks land
                # here. Blocking is unconditional.
                #
                # In audit mode we ALSO route the deny into the per-run
                # summary via record_denial — operators reading
                # sandbox-summary.json see the attack signal there, not
                # only in proxy-events.jsonl. (Under full enforcement
                # the child sees a 502 and observe.py picks it up via
                # stderr pattern-matching; under audit the child also
                # sees the deny but we surface it directly because the
                # audit promise is "every policy/safety event lands in
                # the summary".)
                logger.warning(
                    f"egress proxy: DENY {host}:{port} — resolved to blocked "
                    f"IP {resolved_ip}"
                )
                event.update(result="denied_resolved_ip",
                             reason=f"resolved to blocked range: {resolved_ip}",
                             duration=time.monotonic() - t_start)
                self._record(event)
                # Snapshot under the audit lock — same reasoning as
                # gate 1 above: ref-counted mutations from other
                # threads need a happens-before edge to make the
                # snapshot consistent with the count.
                with self._audit_lock:
                    _audit_now = self._audit_log_only
                if _audit_now:
                    _record_proxy_denial(host, port, resolved_ip,
                                         "resolved_ip_blocked")
                await self._write_error(writer, 403, "Forbidden")
                return

            try:
                up_reader, up_writer = await asyncio.wait_for(
                    asyncio.open_connection(host=resolved_ip, port=port,
                                            family=family),
                    timeout=10.0,
                )
            except (OSError, asyncio.TimeoutError) as e:
                logger.warning(
                    f"egress proxy: upstream connect failed {host}:{port} "
                    f"({resolved_ip}): {e}"
                )
                event.update(result="upstream_failed",
                             reason=f"{e.__class__.__name__}: {e}",
                             duration=time.monotonic() - t_start)
                self._record(event)
                await self._write_error(writer, 502, "Bad Gateway")
                return

        # Acknowledge tunnel established, then relay bytes both ways.
        writer.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
        await writer.drain()
        # Pull resolved_ip from the event dict — the direct path sets it
        # as a local variable, but the upstream-proxy branch only populates
        # event["resolved_ip"]. Referencing a bare `resolved_ip` here would
        # NameError on every upstream-proxy CONNECT, crashing the tunnel
        # handler mid-request. Read through the event dict so both paths
        # produce a valid log line.
        logger.info(
            f"egress proxy: OPEN {host}:{port} -> "
            f"{event.get('resolved_ip', '?')}"
        )

        # Record the event NOW (not at close) so short tunnels that
        # complete right around when the caller's subprocess.run returns
        # still show up in events_since(). The event dict is mutable and
        # shared with the ring buffer — we update bytes_c2u/bytes_u2c/
        # duration in place when the tunnel closes.
        event.update(result="allowed", reason=None)
        self._record(event)

        total = {"c2u": 0, "u2c": 0}  # byte counters
        result = "allowed"
        reason: Optional[str] = None
        # `asyncio.wait_for` is the correct primitive for "cap this block
        # at N seconds": it raises `asyncio.TimeoutError` when the deadline
        # fires AND cancels the inner coroutine cleanly. The previous
        # `_TunnelGuard(loop.call_later(t, task.cancel))` design raised
        # `asyncio.CancelledError` on timeout, not TimeoutError — so the
        # explicit `except asyncio.TimeoutError` branch below never fired,
        # and on Python 3.11+ the CancelledError (a BaseException) escaped
        # `except Exception` entirely, leaving the timeout completely
        # unaccounted for in the proxy event ring buffer.
        try:
            await asyncio.wait_for(
                asyncio.gather(
                    self._relay(reader, up_writer, "c2u", total),
                    self._relay(up_reader, writer, "u2c", total),
                ),
                timeout=self._total_timeout,
            )
        except asyncio.TimeoutError:
            result = "timed_out"
            reason = f"exceeded total_timeout={self._total_timeout}s"
            logger.warning(
                f"egress proxy: TIMEOUT {host}:{port} "
                f"(c2u={total['c2u']} u2c={total['u2c']})"
            )
        except Exception as e:
            reason = f"relay ended: {e.__class__.__name__}"
            logger.debug(
                f"egress proxy: relay ended {host}:{port}: {e.__class__.__name__}"
            )
        finally:
            try:
                up_writer.close()
                await up_writer.wait_closed()
            except Exception:
                pass
            # Update the already-recorded event with final byte counts
            # and outcome. Ring buffer holds a reference; consumers who
            # called events_since() between establishment and close will
            # see the in-progress state (result="allowed", bytes=0) and
            # those calling after close see the final state.
            event.update(result=result, reason=reason,
                         bytes_c2u=total["c2u"], bytes_u2c=total["u2c"],
                         duration=time.monotonic() - t_start)
            logger.info(
                f"egress proxy: CLOSE {host}:{port} "
                f"(c2u={total['c2u']} u2c={total['u2c']})"
            )

    async def _relay(self, src: asyncio.StreamReader,
                     dst: asyncio.StreamWriter,
                     counter_key: str, counters: dict) -> None:
        while True:
            try:
                chunk = await asyncio.wait_for(
                    src.read(self._buffer_size),
                    timeout=self._idle_timeout,
                )
            except asyncio.TimeoutError:
                # Idle → let the other direction notice and close.
                return
            if not chunk:
                return
            counters[counter_key] += len(chunk)
            dst.write(chunk)
            try:
                await dst.drain()
            except (ConnectionResetError, BrokenPipeError):
                return

    async def _write_error(self, writer: asyncio.StreamWriter,
                           code: int, reason: str) -> None:
        body = f"HTTP/1.1 {code} {reason}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        try:
            writer.write(body.encode("ascii"))
            await writer.drain()
        except Exception:
            pass


async def _read_line(reader: asyncio.StreamReader, max_len: int) -> Optional[str]:
    """Read one CRLF-terminated line, max_len bytes. None on error/EOF."""
    try:
        data = await asyncio.wait_for(reader.readuntil(b"\r\n"), timeout=30.0)
    except (asyncio.IncompleteReadError, asyncio.LimitOverrunError,
            asyncio.TimeoutError):
        return None
    if len(data) > max_len:
        return None
    return data[:-2].decode("latin-1")  # latin-1 never fails on bytes


# ----- module-level singleton API -----

def get_proxy(allowed_hosts: Iterable[str]) -> EgressProxy:
    """Return the process-wide proxy singleton, creating it on first call.

    Additional calls mutate the allowlist in place (UNION semantics) and
    return the same instance. Thread-safe.

    Upstream proxy autodetect: reads HTTPS_PROXY / https_proxy and
    NO_PROXY / no_proxy from the parent process env at FIRST-CALL time.
    If set, the singleton tunnels through that upstream for every
    outbound connection (except hosts matching NO_PROXY, which connect
    directly). This lets RAPTOR work inside corporate networks where
    direct egress is blocked but an outbound HTTPS proxy is mandatory.
    The upstream and no_proxy are captured once — subsequent env
    mutation doesn't reconfigure the running proxy.
    """
    global _instance
    with _lock:
        # Dead-thread detection: if a previous get_proxy() created the
        # singleton but its event-loop thread has since died (uncaught
        # exception that bypassed our handler guards, asyncio internals
        # crashing, thread killed externally), tear it down so the next
        # call creates a fresh instance. Without this, callers silently
        # get a zombie proxy that accepts connections but never relays.
        if _instance is not None and not _instance.is_alive():
            logger.error(
                "egress proxy: singleton thread has died — "
                "discarding stale instance and creating a fresh one"
            )
            try:
                _instance.stop()
            except Exception:
                pass
            _instance = None

        if _instance is None:
            import os as _os
            upstream = (_os.environ.get("HTTPS_PROXY")
                        or _os.environ.get("https_proxy"))
            no_proxy = (_os.environ.get("NO_PROXY")
                        or _os.environ.get("no_proxy"))
            _instance = EgressProxy(allowed_hosts,
                                    upstream_proxy=upstream,
                                    no_proxy=no_proxy)
            atexit.register(_instance.stop)
            if upstream:
                logger.info(
                    f"egress proxy: tunnelling via upstream {upstream} "
                    f"(no_proxy={no_proxy or 'none'})"
                )
        else:
            _instance.add_hosts(allowed_hosts)
        return _instance


def is_proxy_started() -> bool:
    """True if the singleton has been created. Used by tests."""
    with _lock:
        return _instance is not None


def _reset_for_tests() -> None:
    """Tear down the singleton. Test-only."""
    global _instance
    with _lock:
        if _instance is not None:
            _instance.stop()
            _instance = None
