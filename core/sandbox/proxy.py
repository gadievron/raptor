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
  internal services on the host's LAN. Applies on BOTH connect paths:
  the direct path vets the addresses we dial; the upstream-proxy path
  vets a literal-IP target outright and pre-vets hostname targets with
  a local resolve before forwarding the CONNECT (residual: the
  upstream proxy resolves independently, so a resolver that answers
  differently for the upstream can still steer the tunnel — see
  _vet_upstream_target).
- DNS pinning: one resolve per tunnel, then connect to that exact IP.
  No mid-tunnel re-resolution — removes the DNS-rebinding window.
- Idle timeout: 300s. Total tunnel duration cap: 3600s. Either bound
  limits how long one compromised child can hold resources open.
- Concurrent tunnels: capped at 4096 (configurable; sized for npm
  install's CONNECT bursts — see _DEFAULT_MAX_TUNNELS history). Hard
  limit on resource consumption by a runaway child.
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
import contextlib
import ipaddress
import itertools
import logging
import os
import socket
import threading
import time
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Optional

# Module-top so the import doesn't run on every CONNECT — the proxy
# tunnel handler used to do `from core.security.log_sanitisation
# import has_nonprintable` inline on the hot path. Cached after the
# first call but still a dict lookup + module attribute access per
# request.
from core.security.log_sanitisation import has_nonprintable, sanitise_for_terminal

from . import audit_budget, escalation_signatures

# Process-unique lane ids. Labels are NOT unique (two concurrent
# contexts may share caller_label="sandbox"), so event->buffer
# subscription matching keys on this id, never the label.
_LANE_IDS = itertools.count(1)


@dataclass
class _Lane:
    """One attributed ingress transport with its own policy bits.

    A lane is how the proxy knows WHICH sandbox a CONNECT came from:
    netns-tier sandboxes each own a dedicated unix socket; no-netns
    tiers (Landlock-TCP, seatbelt) each own a dedicated loopback
    listener. The main TCP listener has no lane — in-process
    consumers (LLM clients, EgressClient) ride it and are always
    judged by the legacy global flag, which nothing in production
    sets any more. Handler closures capture the lane OBJECT at
    accept time, so a connection racing lane teardown is decided by
    the lane that accepted it — deterministic, never a lookup miss.
    """

    label: str
    audit_log_only: bool = False
    # Per-lane hostname allowlist (lowercased). None = no lane
    # restriction: the connection is governed by the process-global
    # allowlist alone. A set scopes this lane's CONNECTs to ITS
    # sandbox's registered hosts — the global set is a union across
    # concurrent runs, and without lane scoping any sandbox could
    # egress to hosts a sibling run allowlisted.
    allowed_hosts: "frozenset[str] | None" = None
    lane_id: int = field(default_factory=lambda: next(_LANE_IDS))

logger = logging.getLogger(__name__)


def _stderr_write(message: str) -> None:
    """Best-effort immediate stderr write for live escalation banners
    — raw os.write(2, ...) so it survives redirected/odd stdio state.
    Mirrors core.sandbox.tracer._announce_escape_primitive."""
    try:
        os.write(2, message.encode("ascii", errors="replace"))
    except OSError:
        pass

# Connection bounds — per-tunnel and aggregate. Tunable via EgressProxy
# constructor kwargs but the defaults are deliberately conservative.
_DEFAULT_IDLE_TIMEOUT = 300.0        # seconds of silence before forced close
_DEFAULT_TOTAL_TIMEOUT = 3600.0      # absolute cap on a single tunnel
# Concurrent CONNECT tunnels. The history of this knob:
#
#   64  — original conservative default. SCA stress harness on
#         2026-05-09 hit this on bursty resolvers (npm install with
#         its parallel HTTP agent + keep-alive lingering) → cascade
#         of refused tunnels + retries → 14% of popular npm
#         packages timed out at 90s.
#   256 — first bump (#407). Helped marginally but ``npm install
#         --maxsockets=8`` STILL bursts to ~280 concurrent tunnels
#         because npm install via ``HTTPS_PROXY`` ignores
#         ``--maxsockets`` (the flag caps direct fetches, not
#         CONNECT-tunneled fetches; verified with both CLI and
#         ``npm_config_maxsockets`` env var). Direct probe: peak 257
#         tunnels for ``debug``, peak 298 for ``eslint``.
#   1024 — interim (#411). Looked safe at first; later sampling at
#         finer resolution showed peaks up to 792 for ``debug`` and
#         655 for ``eslint`` (earlier 250ms-tick samples missed the
#         instantaneous spikes), so 1024 was only ~1.3× the real
#         burst, not the ~3× the prior comment claimed.
#   4096 — current. Sized at ~5× the observed peak so the per-run
#         burst variance (network jitter + proxy event-loop
#         scheduling can inflate a peak 2× run-to-run) does not
#         brush the cap. Resource-wise this is still cheap (each
#         tunnel ≈ 2 sockets + ~1 KiB proxy-thread state; system
#         FD limit is 524288 by default — a runaway client would
#         need to drive ~250× the cap before exhausting the
#         process FD ceiling).
#
# Consumer note: caps below ~2048 will eventually refuse CONNECTs
# from real-world npm install runs against bursty manifests — set
# the cap via the ``max_tunnels=`` constructor kwarg only when you
# have concrete evidence of FD exhaustion at the default.
_DEFAULT_MAX_TUNNELS = 4096
_DEFAULT_BUFFER_SIZE = 64 * 1024     # relay buffer per direction

# DNS cache TTL. Holds (expires_at, addrinfo_list) per (host, port)
# key (lookups are pinned to SOCK_STREAM, so socktype adds no
# discrimination). 60s is a balance: short enough that a legit DNS
# rotation propagates within a normal scan run, long enough that the
# typical npm/pip-style burst (dozens of CONNECTs to one registry host
# in seconds) only pays the resolver cost once. Gate 2 (resolved-IP
# block) still runs against the cached IP on every CONNECT, so a
# DNS-rebinding attack window doesn't widen.
_DNS_CACHE_TTL = 60.0

# Happy-eyeballs per-attempt budget. RFC 8305 recommends 250ms
# before kicking off the next address family's attempt. We keep that
# default — it matches the broad assumption Linux/macOS/Windows
# stacks already use, so behaviour stays predictable for operators
# who are used to OS-level happy-eyeballs.
_HAPPY_EYEBALLS_DELAY = 0.25

# Per-call timeouts for the proxy's asyncio operations. Promoted from
# inline literals so operators tuning latency/throughput have a single
# knob to adjust. _READ_TIMEOUT_S is the per-IO read budget (between
# successive bytes from upstream/downstream); _CONNECT_TIMEOUT_S is
# the larger budget for CONNECT-time waits where TLS handshake +
# happy-eyeballs eat into the window.
_PROXY_READ_TIMEOUT_S = 10.0
_PROXY_CONNECT_TIMEOUT_S = 30.0

# TCP keepalive for established tunnel legs. Corporate proxies, NAT
# gateways, and stateful firewalls drop connection state for tunnels
# that go quiet — a thinking model can be silent for minutes while
# its tunnel carries zero bytes, and the response then lands on a
# dead connection. Keepalive probes refresh that per-TCP-leg state.
# They are TCP-level, not tunnel payload: an upstream proxy applying
# an application-level idle timer to RELAYED bytes still fires — the
# probes only keep the transport under the tunnel alive.
_TCP_KEEPALIVE_IDLE_S = 30
_TCP_KEEPALIVE_INTERVAL_S = 10
_TCP_KEEPALIVE_COUNT = 3

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

# Live-escalation: default distinct-denied-host threshold before the
# proxy prints an immediate stderr recon-pattern banner. Shared with
# triage.py's post-hoc `host_recon_pattern` signal via the leaf
# core.sandbox.escalation_signatures module (triage.py depends on this
# module already; importing triage back would be circular), so the
# live notice and the post-hoc signal agree on what counts as recon
# by construction. Re-exported here because context.py and triage.py
# already consume it under this name.
#
# Recon state is LANE-SCOPED (see _live_recon in __init__), mirroring
# _record()'s lane-scoped buffer fan-out: a distinct-host counter per
# registered sandbox context, torn down when its last registration
# unregisters. A process-global counter would conflate
# concurrently-registered sandboxes AND accumulate distinct denied
# hosts across sequential runs for the life of the proxy singleton —
# five unrelated one-host runs would eventually trip a "recon"
# banner no single run earned.
DEFAULT_HOST_RECON_THRESHOLD = (
    escalation_signatures.DEFAULT_HOST_RECON_THRESHOLD)

# Distinct resolved IPs that get their own live denied_resolved_ip
# banner before further alerts collapse into a single "suppressed"
# notice. Bounds both operator-terminal spam and the dedup set's
# memory: a hostile target driving DNS rebinding can mint an unbounded
# stream of distinct resolved IPs, and each is attacker-paced. The
# full, uncapped record remains in proxy-events.jsonl and the run-end
# sandbox-triage.json.
_LIVE_RESOLVED_IP_BANNER_CAP = 8

# Thread-safe singleton. `get_proxy()` is the sole entry point.
_lock = threading.Lock()
_instance: Optional["EgressProxy"] = None

# One-shot guard for the SIGTERM cleanup hook (see
# _install_sigterm_cleanup). Module-level so a stop/restart of the
# singleton doesn't stack handlers.
_sigterm_hook_installed = False


def _install_sigterm_cleanup() -> None:
    """Best-effort SIGTERM hook so the proxy tears down on TERM.

    ``atexit`` only runs on normal interpreter exit — a SIGTERM'd
    RAPTOR (operator Ctrl-backslash-less kill, CI timeout, systemd
    stop) died without closing listeners or unlinking the unix-lane
    ``.sock`` files, stranding them in output dirs / $TMPDIR. The hook
    runs ``stop(drain_timeout=0)`` (which unbinds + unlinks every unix
    lane) and then re-delivers the signal so the process still dies
    with the default TERM disposition, or chains to a pre-existing
    handler when one was installed before us.

    Constraints, all deliberate:

    - main-thread only: ``signal.signal`` raises ValueError elsewhere;
      when ``get_proxy`` first runs off the main thread the hook is
      simply skipped (atexit still covers normal exit).
    - never clobbers SIG_IGN: an operator who ignored TERM keeps that.
    - installed once per process; a callable prior handler is chained
      after our cleanup rather than replaced.
    - SIGKILL residual: nothing can run on KILL — stale lane sockets
      are then bounded by the per-run output dir / $TMPDIR hygiene,
      and the random per-context socket names mean a later run never
      collides with a stale file.
    """
    global _sigterm_hook_installed
    if _sigterm_hook_installed:
        return
    import signal as _signal
    if threading.current_thread() is not threading.main_thread():
        logger.debug(
            "egress proxy: get_proxy() first called off the main "
            "thread — SIGTERM cleanup hook not installed (atexit "
            "still covers normal exit)"
        )
        return
    try:
        prev = _signal.getsignal(_signal.SIGTERM)
    except (ValueError, OSError):
        return
    if prev is _signal.SIG_IGN:
        return

    def _on_sigterm(signum, frame):
        inst = _instance
        if inst is not None:
            with contextlib.suppress(Exception):
                inst.stop(drain_timeout=0)
        if callable(prev) and prev not in (_signal.SIG_DFL,
                                           _signal.SIG_IGN):
            prev(signum, frame)
        else:
            # Restore the default disposition and re-deliver so the
            # process exits with the conventional killed-by-TERM
            # status instead of swallowing the signal.
            with contextlib.suppress(ValueError, OSError):
                _signal.signal(_signal.SIGTERM, _signal.SIG_DFL)
            os.kill(os.getpid(), _signal.SIGTERM)

    try:
        _signal.signal(_signal.SIGTERM, _on_sigterm)
    except (ValueError, OSError):
        return
    _sigterm_hook_installed = True


def _record_proxy_denial(host: str, port: int, resolved_ip: str | None,
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
    except Exception:
        # Deliberate scope: Exception, not BaseException. SystemExit and
        # KeyboardInterrupt SHOULD propagate so the process can exit.
        # record_denial is documented to never raise either of those —
        # if a future change makes it raise SystemExit, the gate-2 deny
        # path's `await self._write_error(...)` would be skipped because
        # the exception escapes this helper. Don't introduce that path.
        #
        # WARNING (not DEBUG): operators rarely run with DEBUG enabled in
        # production, so a regressed summary writer was effectively
        # invisible — the audit-mode would-deny never lands in
        # sandbox-summary.json and nobody knows. Mirrors the family-wide
        # convention established in c5a4505 ("fix(scorecard): promote
        # producer-error logs DEBUG -> WARNING") — same shape (best-
        # effort recorder), same rationale (default-log visibility).
        logger.warning("_record_proxy_denial: record_denial failed",
                       exc_info=True)


# RFC 6052 NAT64 well-known prefix — see _ip_is_blocked.
_NAT64_NET = ipaddress.ip_network("64:ff9b::/96")


def _normalise_lane_hosts(hosts) -> "frozenset[str] | None":
    """Lowercased frozenset for a lane allowlist; None/empty -> None
    (no lane restriction — global allowlist alone governs)."""
    if not hosts:
        return None
    return frozenset(h.lower() for h in hosts if h)


def _hex_v4(ip: str) -> str:
    """/proc/net/tcp spelling of an IPv4 address (little-endian hex)."""
    return socket.inet_aton(ip)[::-1].hex().upper()


def _hex_v6(ip: str) -> str:
    """/proc/net/tcp6 spelling of an IPv6 address — four 32-bit words,
    each printed as the little-endian hex of its raw bytes."""
    raw = socket.inet_pton(socket.AF_INET6, ip)
    return b"".join(raw[i:i + 4][::-1] for i in range(0, 16, 4)).hex().upper()


def _loopback_peer_uid(peer, sockname) -> "int | None":
    """Best-effort UID of a connected loopback TCP peer.

    TCP sockets have no SO_PEERCRED, so the equivalent is the kernel's
    per-socket table: find the peer's socket row in /proc/net/tcp{,6}
    (its local_address == the peer's addr:port, its rem_address == our
    listener-side addr:port) and read the uid column.

    Only ESTABLISHED rows (st == 01) are matched: TIME_WAIT rows
    report uid 0 regardless of who created the socket, and a peer we
    are still serving holds an established socket by definition.

    Returns None when the UID cannot be determined — non-Linux hosts
    (no /proc/net), malformed peername tuples, or a row that vanished
    because the peer closed mid-lookup. Callers treat None as
    "unknown, allow": this is a defense-in-depth gate layered on the
    loopback-only bind + hostname allowlist, and failing closed on a
    lookup miss would break macOS and add a kernel-race denial mode.
    Residual: a same-UID process can still hand its connected fd to
    another principal (SCM_RIGHTS); no /proc view defends that.

    Cost: one bounded /proc read per inbound loopback TCP connection
    (unix-socket lanes never reach this). The scan stops at the first
    matching established row.
    """
    try:
        peer_ip, peer_port = peer[0], peer[1]
        local_ip, local_port = sockname[0], sockname[1]
    except (TypeError, IndexError):
        return None
    try:
        if ":" in peer_ip:
            table = "/proc/net/tcp6"
            local_hex = f"{_hex_v6(peer_ip)}:{peer_port:04X}"
            rem_hex = f"{_hex_v6(local_ip)}:{local_port:04X}"
        else:
            table = "/proc/net/tcp"
            local_hex = f"{_hex_v4(peer_ip)}:{peer_port:04X}"
            rem_hex = f"{_hex_v4(local_ip)}:{local_port:04X}"
    except OSError:
        return None
    try:
        with open(table, encoding="ascii") as f:
            next(f, None)  # column header
            for line in f:
                cols = line.split()
                if len(cols) < 8 or cols[3] != "01":
                    continue
                if cols[1] == local_hex and cols[2] == rem_hex:
                    try:
                        return int(cols[7])
                    except ValueError:
                        return None
    except OSError:
        return None
    return None


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
    if not ip.is_global:
        return True
    # IPv6 forms that EMBED an IPv4 address evade the is_global check
    # for the embedded target: NAT64 well-known prefix
    # (64:ff9b::/96, RFC 6052 — a NAT64 gateway forwards to the
    # embedded IPv4) and the deprecated IPv4-compatible ::a.b.c.d
    # form both classify as global while smuggling
    # 169.254.169.254/RFC 1918 targets past gate 2 (verified live:
    # 64:ff9b::169.254.169.254 has is_global=True). ipv4_mapped
    # (::ffff:) is already handled by is_global itself; sixtofour
    # (2002::/16) is classified non-global wholesale. Extract every
    # embedded IPv4 and re-check it.
    if isinstance(ip, ipaddress.IPv6Address):
        embedded = []
        if ip in _NAT64_NET:
            embedded.append(ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF))
        # IPv4-compatible ::a.b.c.d (deprecated, ::/96 minus ::/112).
        if (int(ip) >> 32) == 0 and int(ip) > 1:
            embedded.append(ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF))
        if ip.ipv4_mapped is not None:
            embedded.append(ip.ipv4_mapped)
        for v4 in embedded:
            if not v4.is_global:
                return True
    return False


def _parse_proxy_url(url: str | None) -> tuple | None:
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


def _parse_no_proxy(value: str | None) -> list:
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


# Env knob for the upstream-proxy handshake budget (see
# _upstream_handshake_timeout). Distinct from the per-IO read budget:
# widening THAT would also slow failure detection on dead targets.
_UPSTREAM_HANDSHAKE_TIMEOUT_ENV = "RAPTOR_PROXY_UPSTREAM_HANDSHAKE_TIMEOUT_S"


def _upstream_handshake_timeout() -> float:
    """Budget for connecting to + CONNECT-negotiating with the
    operator's upstream proxy.

    Defaults to the per-IO budget (``_PROXY_READ_TIMEOUT_S``). Slow /
    authenticated / loaded corporate proxies can legitimately need
    more; a too-small budget turns a working-but-slow proxy into a
    502 + full SDK retry cycle. Invalid or non-positive values fall
    back to the default.
    """
    raw = os.environ.get(_UPSTREAM_HANDSHAKE_TIMEOUT_ENV)
    if raw is None:
        return _PROXY_READ_TIMEOUT_S
    try:
        value = float(raw)
    except ValueError:
        logger.warning(
            "%s=%r is not a number — using default %ss",
            _UPSTREAM_HANDSHAKE_TIMEOUT_ENV, raw, _PROXY_READ_TIMEOUT_S,
        )
        return _PROXY_READ_TIMEOUT_S
    if value <= 0:
        logger.warning(
            "%s=%r must be positive — using default %ss",
            _UPSTREAM_HANDSHAKE_TIMEOUT_ENV, raw, _PROXY_READ_TIMEOUT_S,
        )
        return _PROXY_READ_TIMEOUT_S
    return value


def _enable_tcp_keepalive(writer: asyncio.StreamWriter) -> None:
    """Turn on TCP keepalive for one tunnel leg.

    Only meaningful for TCP legs — unix-socket client legs (sandbox
    lanes) are skipped by the family check. Platform spelling: Linux
    exposes TCP_KEEPIDLE, macOS calls the same idle knob
    TCP_KEEPALIVE; interval/count set where the platform has them.
    Failure is non-fatal — keepalive is a resilience optimisation,
    never worth killing an established tunnel over.
    """
    sock = writer.get_extra_info("socket")
    if sock is None or sock.family not in (socket.AF_INET, socket.AF_INET6):
        return
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        if hasattr(socket, "TCP_KEEPIDLE"):
            sock.setsockopt(
                socket.IPPROTO_TCP, socket.TCP_KEEPIDLE,
                _TCP_KEEPALIVE_IDLE_S,
            )
        elif hasattr(socket, "TCP_KEEPALIVE"):
            sock.setsockopt(
                socket.IPPROTO_TCP, socket.TCP_KEEPALIVE,
                _TCP_KEEPALIVE_IDLE_S,
            )
        if hasattr(socket, "TCP_KEEPINTVL"):
            sock.setsockopt(
                socket.IPPROTO_TCP, socket.TCP_KEEPINTVL,
                _TCP_KEEPALIVE_INTERVAL_S,
            )
        if hasattr(socket, "TCP_KEEPCNT"):
            sock.setsockopt(
                socket.IPPROTO_TCP, socket.TCP_KEEPCNT,
                _TCP_KEEPALIVE_COUNT,
            )
    except OSError:
        logger.debug("egress proxy: TCP keepalive setup failed",
                     exc_info=True)


def _split_addrinfo_by_family(
    addrinfo: list,
) -> tuple[list, list]:
    """Partition an addrinfo list into (v6, v4) buckets, preserving
    each bucket's internal order.

    Happy-eyeballs (RFC 8305) prefers attempting IPv6 first because
    when v6 works it usually has the better path; v4 is the fallback
    if v6 stalls. Splitting by family lets the dialer race one
    address from each bucket in parallel rather than walking the
    full list serially with a 10s OS timeout per attempt — which is
    what bites npm-style burst traffic when an upstream's first
    addrinfo entry happens to be an IPv6 address the local link
    can't reach.
    """
    v6, v4 = [], []
    for entry in addrinfo:
        family = entry[0]
        if family == socket.AF_INET6:
            v6.append(entry)
        elif family == socket.AF_INET:
            v4.append(entry)
        # Other families (AF_UNIX etc) ignored — getaddrinfo with
        # SOCK_STREAM on a hostname won't yield them in practice.
    return v6, v4


class EgressProxy:
    """HTTPS CONNECT proxy with hostname allowlist.

    Not typically constructed directly — use module-level get_proxy().
    """

    def __init__(self, allowed_hosts: Iterable[str],
                 idle_timeout: float = _DEFAULT_IDLE_TIMEOUT,
                 total_timeout: float = _DEFAULT_TOTAL_TIMEOUT,
                 max_tunnels: int = _DEFAULT_MAX_TUNNELS,
                 buffer_size: int = _DEFAULT_BUFFER_SIZE,
                 upstream_proxy: str | None = None,
                 no_proxy: str | None = None,
                 audit_log_only: bool = False,
                 audit_enforce: bool = False):
        self._hosts_lock = threading.Lock()
        self._allowed_hosts: set[str] = {h.lower() for h in allowed_hosts}
        # When True, gate 1 (hostname allowlist) emits a `would_deny_host`
        # event AND a record_denial entry, then falls through to the
        # connect path — operator workflows that hit gate 1 keep working
        # but the policy violation is logged. Gate 2 (resolved-IP block)
        # is the proxy's DNS-rebinding/DNS-poisoning defense and stays
        # ENFORCING regardless — on the direct path AND on the
        # upstream-proxy path (see _vet_upstream_target): it has no
        # legitimate-workflow false positives (an allowlisted hostname
        # resolving to a private/loopback IP is purely an attack
        # signal). In audit mode gate 2 additionally records the deny
        # into the summary.
        #
        # Scope: this global flag now governs ONLY connections with
        # no lane — i.e. the shared main TCP listener that in-process
        # consumers ride. Sandbox contexts get per-lane audit bits
        # (set_lane_audit on their unix socket / TCP lane), so a
        # concurrent non-audit sandbox is never downgraded by an
        # audit sibling. Production code no longer calls
        # acquire/release_audit_log_only; the API and the constructor
        # kwarg remain for direct test construction and as the legacy
        # main-listener toggle.
        self._audit_log_only = audit_log_only
        # When True, gate 1 in audit mode switches from log-and-allow to
        # log-and-deny — the allowlist is enforced even in audit mode.
        # Default False preserves the documented audit-permissive semantics
        # (gate 1 audit mode is for diagnosis while building an allowlist;
        # once the allowlist is mature, operators can set audit_enforce=True
        # or set the RAPTOR_PROXY_AUDIT_ENFORCE env var to one of the
        # accepted truthy spellings — case-insensitive, whitespace-stripped:
        #     "1" / "true" / "yes" / "on"
        # Any other value (including "0" / "false" / "no" / "off" / "" /
        # the unset variable) leaves audit-mode in its default log-only
        # behaviour. The env-var parse lives at the `get_proxy()` read
        # below; this kwarg accepts the already-parsed bool.
        # Gate 2 is always enforcing regardless of this flag — on the
        # direct path and on the upstream-proxy path alike.
        self._audit_enforce = audit_enforce
        # Ref-count for concurrent acquire/release. Each audit-mode
        # sandbox via use_egress_proxy=True acquires on entry, releases
        # on exit. Gate 1 is in audit-log mode iff count > 0. Without
        # this, mixed-profile concurrent sandboxes would race —
        # specifically, a non-audit sandbox could see its CONNECTs
        # silently downgraded to allow-and-log (security weakening)
        # because a sibling audit sandbox flipped the singleton's flag.
        self._audit_lock = threading.Lock()
        self._audit_count = 1 if audit_log_only else 0
        # Lane registries: unix lanes keyed by socket path, TCP lanes
        # by listener port. Guarded by _lanes_lock; handler closures
        # hold direct lane references so decisions never require the
        # registry after accept.
        self._lanes_lock = threading.Lock()
        self._unix_lanes: dict[str, _Lane] = {}
        self._tcp_lanes: dict[int, _Lane] = {}
        self._tcp_lane_servers: dict[int, object] = {}
        self._idle_timeout = idle_timeout
        self._idle_timeout_lock = threading.Lock()
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
        self._upstream: tuple | None = _parse_proxy_url(upstream_proxy)
        # Budget for the upstream-proxy leg: TCP connect to the
        # corporate proxy plus the CONNECT negotiation round-trip.
        # Slow, authenticated, or loaded corporate proxies can
        # legitimately exceed the 10s per-IO default — and each 502
        # this side returns costs the caller a full SDK retry cycle.
        # Read once at construction (the proxy is a long-lived
        # singleton); the default stays at the per-IO budget so a
        # genuinely dead upstream keeps failing fast.
        self._upstream_handshake_timeout = _upstream_handshake_timeout()
        # NO_PROXY honoured when an upstream is configured: any host
        # matching a pattern bypasses the upstream and connects directly
        # (so internal services like git-server.corp remain reachable).
        self._no_proxy_patterns: list = _parse_no_proxy(no_proxy)
        # Per-(host, port) DNS cache. Map key → (expires_at,
        # addrinfo_list). Bursty resolvers (npm install, pip-compile)
        # hit the same registry host dozens of times in seconds; without
        # caching, each CONNECT pays a fresh getaddrinfo. The cache lives
        # only on the proxy's event-loop thread so no lock is needed —
        # asyncio is single-threaded and reads/writes serialise on the
        # loop.
        self._dns_cache: dict = {}
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
        # back its accumulated event list via unregister_sandbox().
        # Fan-out is lane-aware (D3): run-global buffers get every
        # event; lane-subscribed buffers get only their own lane's
        # events (see _record for the rule).
        # Per-sandbox buffers (rather than one shared ring) eliminate
        # the flood-masks-attack evasion of the old time-windowed deque
        # design: a child making 10 000 CONNECTs to allow-listed hosts
        # can no longer push an earlier denied CONNECT out of a shared
        # 1024-entry deque before the sandbox ends and flushes to file.
        # Each sandbox's buffer grows independently. Memory cost is
        # ~300 bytes per event per active sandbox.
        self._sandbox_buffers: dict = {}
        self._sandbox_labels: dict = {}
        # Per-token lane subscription (lane_id or None). None = the
        # run-global view: the buffer receives EVERY event (the
        # pre-lane fan-out behaviour). A lane_id-subscribed buffer
        # receives only its own lane's events, so concurrent runs no
        # longer see each other's would-deny records (design doc D3).
        self._sandbox_lane_subs: dict = {}
        self._next_token = 0
        self._buffer_lock = threading.Lock()
        # Live host-recon escalation state, LANE-SCOPED like the event
        # buffers: bucket key is a lane_id (int) or None for run-global
        # registrations, value is {"hosts": set, "escalated": bool,
        # "threshold": int, "refs": int}. Created by register_sandbox
        # (refs counts registrations sharing the bucket), torn down
        # when the last registration on the bucket unregisters — so
        # distinct-host counts are per sandbox context, never
        # accumulated across sequential runs or conflated across
        # concurrent ones. `escalated` makes the recon banner one-shot
        # per bucket. `threshold` starts at the default and can only
        # be tightened (never loosened) within a bucket — same
        # "callers can tighten, never accidentally weaken a sibling's
        # setting" pattern as update_idle_timeout's max-semantics
        # above, scoped to the bucket.
        self._live_recon: dict = {}
        # Fallback resolved-IP state for events recorded outside any active
        # sandbox registration. Registered runs keep their own state in the
        # lane bucket below so one run hitting the cap cannot silence another.
        self._live_resolved_ip_escalated: set[str] = set()
        self._live_resolved_ip_cap_announced = False
        # Atomic snapshot of the buffer-list refs for the hot path.
        # `_record` is called once per CONNECT and used to acquire
        # `_buffer_lock` to iterate `_sandbox_buffers.values()`. Under
        # bursty traffic that single lock serialises every recorder.
        # The snapshot is a tuple — re-bound (atomic ref-write under
        # CPython's GIL) by register/unregister inside the lock; the
        # hot path reads the tuple ref without the lock and iterates
        # to append. Race window: between snapshot read and append, a
        # concurrent unregister may have popped a buffer; the append
        # still lands on that orphaned list. The unregistered caller's
        # returned events are a defensive copy taken at unregister
        # time, so the late append is silently dropped from the
        # caller's view — same end-state as the previous design where
        # the late event would have been recorded into a buffer the
        # caller had already left behind.
        # Snapshot entries are (buffer, lane_subscription) pairs.
        self._sandbox_buffers_snapshot: tuple = ()

        # Synchronise startup: the thread runs the asyncio loop and signals
        # `_ready` once the server is bound and port is known. The calling
        # thread blocks on _ready before returning from __init__, so
        # callers see a fully-ready proxy or an exception.
        self._ready = threading.Event()
        self._start_error: BaseException | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._server: asyncio.AbstractServer | None = None
        self.port: int = 0
        self._unix_servers: dict = {}
        self._unix_lock = threading.Lock()
        self._unix_tasks: set = set()
        self._client_tasks: set = set()
        self._stopping = False

        self._thread = threading.Thread(
            target=self._run_loop,
            name="raptor-egress-proxy",
            daemon=True,
        )
        self._thread.start()
        # Bound the readiness wait. Pre-fix `self._ready.wait()` was
        # unbounded — if the proxy thread crashed before reaching the
        # `self._ready.set()` call AND before assigning to
        # `_start_error` (race window between thread start and the
        # first listening-socket bind), the caller would block forever
        # holding the singleton lock that wraps `EgressProxy.start()`.
        # Every subsequent sandbox acquire would then block waiting
        # for the same lock — operator saw "everything hung after
        # /scan started". 30s is well above any realistic
        # asyncio-loop-startup latency on a busy host (sub-second in
        # practice).
        if not self._ready.wait(timeout=_PROXY_CONNECT_TIMEOUT_S):
            # Defensive: stop the thread so we don't leak a zombie
            # background loop trying forever to bind. Pre-fix the
            # raise just abandoned ``self._thread`` (daemon, so it
            # died with the process — but every retry stacked another
            # daemon thread on top, multiplying the bind churn).
            self._stop_thread_best_effort()
            # Use the actual timeout constant in the message so an
            # operator bumping ``_PROXY_CONNECT_TIMEOUT_S`` sees a
            # consistent error rather than the hardcoded "30s" lie.
            raise RuntimeError(
                f"egress proxy did not become ready within "
                f"{_PROXY_CONNECT_TIMEOUT_S:.0f}s "
                f"(thread may have crashed before signalling)"
            )
        if self._start_error is not None:
            # Same cleanup: if the thread came up far enough to set
            # ``_start_error`` but not ``_ready``, stop it before
            # propagating so a future retry from the same process
            # doesn't see an orphan thread holding the listening
            # socket.
            self._stop_thread_best_effort()
            raise RuntimeError(
                f"egress proxy failed to start: {self._start_error}"
            ) from self._start_error

    # ----- public API -----

    def add_hosts(self, hosts: Iterable[str]) -> None:
        """Extend the allowlist. Idempotent. Thread-safe."""
        with self._hosts_lock:
            self._allowed_hosts.update(h.lower() for h in hosts)

    def update_idle_timeout(self, seconds: float) -> None:
        """Raise the idle timeout if *seconds* exceeds the current value.

        Max semantics: callers can widen the window but never shrink it,
        so a late caller (e.g. LLM egress needing 1800s for thinking
        models) doesn't regress the timeout for earlier callers.
        """
        with self._idle_timeout_lock:
            if seconds > self._idle_timeout:
                prev = self._idle_timeout
                self._idle_timeout = seconds
                logger.info(
                    "egress proxy: idle timeout raised %.0fs → %.0fs",
                    prev, seconds,
                )

    def acquire_audit_log_only(self) -> None:
        """Increment the audit-mode reference count and ensure
        audit-log mode is engaged on the hostname gate.

        LEGACY SCOPE: after lane scoping, this global flag decides
        only un-laned connections (the shared main listener).
        Sandbox contexts use set_lane_audit on their own transport
        instead; production code has no callers of this API.

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

    def bind_unix(self, path: str, *, label: str = "sandbox",
                  allowed_hosts: "Iterable[str] | None" = None) -> None:
        """Start an additional asyncio Unix socket server at *path*.

        Reuses ``_handle_client`` — the CONNECT protocol is transport-
        agnostic (StreamReader/StreamWriter work identically over TCP
        and Unix sockets). Multiple Unix sockets can be active at once
        (one per concurrent netns-enforced sandbox).

        Thread-safe: schedules server creation on the proxy's event
        loop and blocks until it is ready.
        """
        if self._loop is None or not self._loop.is_running():
            raise RuntimeError("proxy event loop not running")

        import os as _os

        lane = _Lane(label=label,
                     allowed_hosts=_normalise_lane_hosts(allowed_hosts))
        with self._lanes_lock:
            self._unix_lanes[path] = lane

        async def _bind():
            old_umask = _os.umask(0o077)
            try:
                srv = await asyncio.start_unix_server(
                    lambda r, w: self._handle_unix_client(r, w, lane=lane),
                    path=path,
                )
            finally:
                _os.umask(old_umask)
            with self._unix_lock:
                self._unix_servers[path] = srv
            return srv

        future = asyncio.run_coroutine_threadsafe(_bind(), self._loop)
        future.result(timeout=_PROXY_CONNECT_TIMEOUT_S)
        logger.info("egress proxy: unix socket bound at %s", path)

    def bind_tcp_lane(self, *, label: str = "sandbox",
                      allowed_hosts: "Iterable[str] | None" = None) -> int:
        """Start a dedicated loopback listener with its own lane.

        For sandbox tiers that cannot use a unix socket (Landlock-TCP
        children pinned by ``allowed_tcp_ports``, macOS seatbelt
        children pinned by SBPL): a per-context port gives their
        connections the same attribution the netns tier gets from its
        per-context unix socket — and pins the children AWAY from the
        shared main listener that in-process consumers ride.

        Returns the kernel-assigned port. Raises RuntimeError if the
        event loop is not running or the bind fails; callers treat
        that as "no lane" and fail CLOSED (audit leniency unavailable,
        enforcement intact).
        """
        if self._loop is None or not self._loop.is_running():
            raise RuntimeError("proxy event loop not running")

        lane = _Lane(label=label,
                     allowed_hosts=_normalise_lane_hosts(allowed_hosts))

        async def _bind():
            srv = await asyncio.start_server(
                lambda r, w: self._handle_unix_client(r, w, lane=lane),
                host="127.0.0.1", port=0,
            )
            port = srv.sockets[0].getsockname()[1]
            with self._lanes_lock:
                self._tcp_lanes[port] = lane
                self._tcp_lane_servers[port] = srv
            return port

        future = asyncio.run_coroutine_threadsafe(_bind(), self._loop)
        port = future.result(timeout=_PROXY_CONNECT_TIMEOUT_S)
        logger.info("egress proxy: tcp lane %r bound at 127.0.0.1:%d",
                    label, port)
        return port

    def close_tcp_lane(self, port: int) -> None:
        """Stop the TCP lane listener at *port*. Idempotent.

        Mirrors unbind_unix: stops accepting, does not cancel tunnels
        already relaying (their handler holds the lane object).
        """
        with self._lanes_lock:
            srv = self._tcp_lane_servers.pop(port, None)
            self._tcp_lanes.pop(port, None)
        if srv is None:
            return
        if self._loop is not None and self._loop.is_running():
            async def _close():
                srv.close()
            # Loop may shut down between the is_running() check and
            # scheduling (RuntimeError); a wedged loop times out the
            # future (TimeoutError).
            with contextlib.suppress(RuntimeError, TimeoutError):
                future = asyncio.run_coroutine_threadsafe(
                    _close(), self._loop,
                )
                future.result(timeout=2.0)
        logger.info("egress proxy: tcp lane at 127.0.0.1:%d closed", port)

    def set_lane_audit(self, key: "str | int", value: bool) -> bool:
        """Set the audit-log-only bit on one lane.

        *key* is the unix socket path (netns tier) or the TCP lane
        port. Returns False when no such lane exists — callers MUST
        treat False as "leniency unavailable" and stay enforcing,
        never fall back to the global flag.
        """
        with self._lanes_lock:
            lane = (self._unix_lanes.get(key) if isinstance(key, str)
                    else self._tcp_lanes.get(key))
        if lane is None:
            return False
        with self._audit_lock:
            lane.audit_log_only = value
        if value:
            logger.warning(
                "egress proxy: lane %r switched to AUDIT-LOG mode "
                "(this sandbox's CONNECTs to non-allowlisted hosts "
                "will be ALLOWED and logged; other lanes and the "
                "main listener stay ENFORCING).", lane.label,
            )
        return True

    def unbind_unix(self, path: str) -> None:
        """Stop the Unix socket server at *path* and unlink the file.

        Thread-safe. Idempotent — no-op if *path* was never bound or
        was already unbound.
        """
        with self._unix_lock:
            srv = self._unix_servers.pop(path, None)
        with self._lanes_lock:
            self._unix_lanes.pop(path, None)
        if srv is None:
            return

        if self._loop is not None and self._loop.is_running():
            async def _close():
                srv.close()
            # Same failure modes as close_tcp_lane: loop shutdown race
            # (RuntimeError) or a wedged loop (TimeoutError).
            with contextlib.suppress(RuntimeError, TimeoutError):
                future = asyncio.run_coroutine_threadsafe(
                    _close(), self._loop,
                )
                future.result(timeout=2.0)
        import os as _os
        try:
            _os.unlink(path)
        except OSError:
            pass
        logger.info("egress proxy: unix socket unbound at %s", path)

    async def _handle_unix_client(
        self, reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        lane: "_Lane | None" = None,
    ) -> None:
        """Wrapper for Unix socket connections.

        Delegates to ``_handle_client``. The only difference: Unix
        socket peers have no IP address, so the loopback-only peer
        check in ``_handle_client`` sees ``peername=None`` — we
        override the extra-info so it reports ``("unix", 0)`` instead
        of failing the non-loopback rejection.
        """
        task = asyncio.current_task()
        if task is not None:
            self._unix_tasks.add(task)
        try:
            await self._handle_client(reader, writer, lane=lane)
        finally:
            if task is not None:
                self._unix_tasks.discard(task)

    def is_host_allowed(self, host: str) -> bool:
        """Check if a host is in the allowlist (case-insensitive)."""
        with self._hosts_lock:
            return host.lower() in self._allowed_hosts

    def register_sandbox(self, caller_label: str | None = None,
                         lane_key: "str | int | None" = None,
                         host_recon_threshold: int | None = None) -> int:
        """Register an active sandbox and receive a token.

        While registered, tunnel events the proxy records are fanned
        into this sandbox's private event list. `caller_label`
        (if provided) is stamped onto each event as `event["caller"]`
        so post-mortem filtering can separate, e.g., claude-sub-agent
        traffic from codeql-pack-download even when they share the
        proxy singleton.

        ``lane_key`` scopes the buffer to ONE lane (the unix socket
        path or TCP lane port the caller's sandbox transport rides):
        only events attributed to that lane land in this buffer, so
        concurrent runs no longer see each other's would-deny records.
        With ``lane_key=None`` (default) the buffer is run-global and
        receives every event — the pre-lane behaviour, and the home
        for events that carry no lane attribution (main-listener
        traffic, handler errors): un-laned events are never dropped
        from the global view, and never leak into lane-scoped views.

        Fail-open on lookup miss BY DESIGN for the audit trail: a
        ``lane_key`` that matches no live lane degrades to the
        run-global subscription (over-capture, never under-capture) —
        the caller keeps a complete event view rather than a silently
        empty one.

        `host_recon_threshold` (optional): a per-profile override for
        the live host-recon escalation threshold (see
        DEFAULT_HOST_RECON_THRESHOLD). Scoped to this registration's
        recon bucket (the resolved lane, or the run-global bucket for
        lane-less registrations) and min-combined within it: a
        registration passing a looser threshold never weakens an
        already-tighter sibling ON THE SAME bucket — mirrors
        update_idle_timeout's max-semantics, inverted because tighter
        is the more-sensitive direction here. Different lanes keep
        fully independent thresholds, so a debug-profile sandbox never
        loosens (or tightens) a concurrent full-profile run's recon
        sensitivity.

        Must be paired with `unregister_sandbox(token)` — typically via
        try/finally around the sandboxed subprocess invocation. The
        token is opaque; callers must not inspect it.
        """
        lane_sub = None
        if lane_key is not None:
            with self._lanes_lock:
                lane = (self._unix_lanes.get(lane_key)
                        if isinstance(lane_key, str)
                        else self._tcp_lanes.get(lane_key))
            if lane is not None:
                lane_sub = lane.lane_id
            else:
                logger.warning(
                    "egress proxy: register_sandbox lane_key %r matches "
                    "no live lane — buffer degrades to the run-global "
                    "view (over-capture, never dropped).", lane_key,
                )
        with self._buffer_lock:
            self._next_token += 1
            token = self._next_token
            self._sandbox_buffers[token] = []
            self._sandbox_labels[token] = caller_label
            self._sandbox_lane_subs[token] = lane_sub
            self._sandbox_buffers_snapshot = tuple(
                (buf, self._sandbox_lane_subs[tok])
                for tok, buf in self._sandbox_buffers.items()
            )
            state = self._live_recon.get(lane_sub)
            if state is None:
                state = {"hosts": set(), "escalated": False,
                         "threshold": DEFAULT_HOST_RECON_THRESHOLD,
                         "resolved_ips": set(),
                         "resolved_ip_cap_announced": False,
                         "refs": 0}
                self._live_recon[lane_sub] = state
            state["refs"] += 1
            if host_recon_threshold is not None:
                state["threshold"] = min(state["threshold"],
                                         host_recon_threshold)
            return token

    def unregister_sandbox(self, token: int) -> list[dict]:
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
            if token in self._sandbox_buffers:
                # Tear down this registration's recon bucket when the
                # last registration sharing it leaves — per-context
                # distinct-host counts must not survive into the next
                # run on the same proxy singleton. Guarded by buffer
                # membership so the idempotent-unknown-token path
                # never decrements a live bucket.
                lane_sub = self._sandbox_lane_subs.get(token)
                state = self._live_recon.get(lane_sub)
                if state is not None:
                    state["refs"] -= 1
                    if state["refs"] <= 0:
                        del self._live_recon[lane_sub]
            events = self._sandbox_buffers.pop(token, [])
            label = self._sandbox_labels.pop(token, None)
            self._sandbox_lane_subs.pop(token, None)
            self._sandbox_buffers_snapshot = tuple(
                (buf, self._sandbox_lane_subs[tok])
                for tok, buf in self._sandbox_buffers.items()
            )
            # Pre-fix the copy `[{**e, "caller": label} for e in events]`
            # happened OUTSIDE the lock. Per the docstring some event
            # fields (bytes_c2u, bytes_u2c, duration) are mutated in
            # place after the at-open record. If the recorder thread
            # mid-mutated a dict during the spread (`{**e}` reads
            # keys/values one at a time, not atomically), the copied
            # dict captured a half-updated state — bytes_c2u updated
            # but bytes_u2c stale, or duration updated but the bytes
            # counters not yet. Operators reading the audit trail saw
            # nonsensical inconsistencies they had to filter out.
            #
            # Move the copy inside the lock. The one post-record
            # mutate path — the close-time counters/duration update in
            # `_serve_tunnel`'s finally — goes through
            # `_finalize_tunnel_event`, which also takes
            # `_buffer_lock`, so the spread happens with the mutator
            # serialised out. (`_record` itself stays lock-free — it
            # only APPENDS references; it never mutates event fields.)
            # Cost: a few extra microseconds per event in unregister;
            # benefit: consistent snapshots in the audit trail.
            if label is not None:
                return [{**e, "caller": label} for e in events]
            return [dict(e) for e in events]

    def _finalize_tunnel_event(self, event: dict, **fields) -> None:
        """Apply the close-time in-place update (byte counters,
        duration, outcome) to an already-recorded event.

        MUST hold ``_buffer_lock``: ``unregister_sandbox`` copies the
        buffered events under that lock precisely so a concurrent
        mutation can't be observed half-applied (bytes_c2u updated,
        duration stale). This runs once per tunnel CLOSE — not the
        hot path — so the lock cost is irrelevant; without it the
        torn-snapshot race the unregister comment describes is back.
        """
        with self._buffer_lock:
            event.update(**fields)

    def _record(self, event: dict) -> None:
        """Fan a tunnel event into the subscribed sandbox buffers.

        Fan-out rule (design doc D3 — lane-scoped buffers):

          - run-global buffers (registered with ``lane_key=None``)
            receive EVERY event — the pre-lane behaviour;
          - lane-subscribed buffers receive only events whose
            ``lane_id`` matches their subscription, so concurrent
            runs' events segregate;
          - an event with no lane attribution (``lane_id`` absent or
            None: main-listener traffic, handler errors) goes to the
            run-global buffers only — never dropped from the global
            view, never leaked into another run's lane view.

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

        Lock-free hot path: reads `_sandbox_buffers_snapshot` (atomic
        ref-read under the GIL) and iterates without acquiring
        `_buffer_lock`. Append to a Python list is atomic per the GIL.
        Under bursty traffic this avoids serialising every recorder on
        a single mutex shared with register/unregister.
        """
        lane_id = event.get("lane_id")
        for buf, sub in self._sandbox_buffers_snapshot:
            if sub is None or (lane_id is not None and sub == lane_id):
                buf.append(event)
        self._live_escalate(event)

    def _live_bucket_states(self, event: dict) -> list[dict]:
        """Return the active lane/global live-escalation buckets for event."""
        lane_id = event.get("lane_id")
        buckets = []
        if lane_id is not None:
            lane_state = self._live_recon.get(lane_id)
            if lane_state is not None:
                buckets.append(lane_state)
        global_state = self._live_recon.get(None)
        if global_state is not None and all(
                global_state is not state for state in buckets):
            buckets.append(global_state)
        return buckets

    def _live_escalate(self, event: dict) -> None:
        """Immediate stderr escalation for HIGH-severity proxy signals,
        ahead of the run-end sandbox-triage.json classification —
        mirrors core.sandbox.tracer._announce_escape_primitive /
        seatbelt_audit._announce_credential_path_touch. Print-only, no
        change to the CONNECT decision already made by gates 1/2 above.

        Called from `_record()` on the proxy's single event-loop
        thread — no lock taken for the dedup-state mutations below,
        same reasoning as `_record`'s own lock-free hot path. The
        recon buckets ARE created/torn down by register/unregister on
        other threads (under `_buffer_lock`), but this path only
        `.get()`s a bucket ref and mutates its contents — GIL-atomic
        dict/set ops; the worst-case race is one host counted into a
        bucket mid-teardown, which is discarded with the bucket.
        """
        if audit_budget.live_escalation_disabled():
            return
        result = event.get("result")

        if result == "denied_resolved_ip":
            resolved_ip = event.get("resolved_ip")
            if not resolved_ip:
                return
            buckets = self._live_bucket_states(event)
            emit_banner = False
            emit_suppression = False
            if buckets:
                for state in buckets:
                    escalated = state["resolved_ips"]
                    if resolved_ip in escalated:
                        continue
                    if len(escalated) >= _LIVE_RESOLVED_IP_BANNER_CAP:
                        if not state["resolved_ip_cap_announced"]:
                            state["resolved_ip_cap_announced"] = True
                            emit_suppression = True
                        continue
                    escalated.add(resolved_ip)
                    emit_banner = True
            else:
                # Events outside a register/unregister window keep the
                # pre-lane fallback behaviour for diagnostics/tests.
                if resolved_ip in self._live_resolved_ip_escalated:
                    return
                if (len(self._live_resolved_ip_escalated)
                        >= _LIVE_RESOLVED_IP_BANNER_CAP):
                    if not self._live_resolved_ip_cap_announced:
                        self._live_resolved_ip_cap_announced = True
                        emit_suppression = True
                else:
                    self._live_resolved_ip_escalated.add(resolved_ip)
                    emit_banner = True
            if not emit_banner and not emit_suppression:
                return
            if emit_banner:
                # The hostname is attacker-controlled (the sandboxed
                # target picked it); sanitise + bound before it reaches
                # the operator's terminal. resolved_ip comes from our own
                # resolver — safe to embed as-is.
                _host = sanitise_for_terminal(str(event.get("host")))
                _stderr_write(
                    f"RAPTOR sandbox ALERT: proxy CONNECT resolved to a "
                    f"blocked IP range: {resolved_ip} (host="
                    f"'{_host}'). Consistent with an "
                    f"SSRF/DNS-rebinding/cloud-metadata probing attempt, "
                    f"not ordinary allowlist noise. See sandbox-"
                    f"triage.json at run end for full context.\n"
                )
            if emit_suppression:
                # Bound the dedup set AND the terminal spam — a DNS-
                # rebinding target can mint unlimited distinct IPs.
                _stderr_write(
                    f"RAPTOR sandbox ALERT: further blocked-"
                    f"resolved-IP alerts suppressed after "
                    f"{_LIVE_RESOLVED_IP_BANNER_CAP} distinct IPs — "
                    f"full list in proxy-events.jsonl / sandbox-"
                    f"triage.json at run end.\n"
                )
            return

        if result in ("denied_host", "would_deny_host"):
            host = event.get("host")
            if not host:
                return
            # Mirror the buffer fan-out: the event counts toward its
            # own lane's recon bucket (if one is registered) AND the
            # run-global bucket (if a lane-less registration exists) —
            # over-capture into the global view, never leakage into a
            # sibling lane's view. No registered bucket → no live
            # counting, matching the buffer semantics for events that
            # arrive outside any register/unregister window; triage
            # still sees them post-hoc via proxy-events.jsonl.
            buckets = self._live_bucket_states(event)
            for state in buckets:
                if state["escalated"]:
                    continue
                state["hosts"].add(host)
                if len(state["hosts"]) >= state["threshold"]:
                    state["escalated"] = True
                    _stderr_write(
                        f"RAPTOR sandbox ALERT: {len(state['hosts'])} "
                        f"distinct hosts denied by the egress proxy "
                        f"within one sandbox context "
                        f"(threshold={state['threshold']}) — "
                        f"consistent with a host-recon/C2-discovery "
                        f"pattern, not a single missing allowlist entry. "
                        f"See sandbox-triage.json at run end for full "
                        f"context.\n"
                    )

    async def _cached_getaddrinfo(self, host: str, port: int) -> list:
        """Resolve `host:port` with a TTL cache.

        On the proxy event-loop thread; no lock needed (asyncio is
        single-threaded and the cache dict is only touched from this
        thread). Cache miss → call `loop.getaddrinfo` and stash the
        result with `now + _DNS_CACHE_TTL` as expiry. Cache hit →
        return the stored addrinfo list directly.

        Cache is bounded by the natural diversity of (host, port)
        pairs the sandboxed children touch — typically a handful of
        registry hosts per scan. We do not LRU-evict; entries simply
        expire by TTL. If a future workload generates an unbounded
        host set, add a max-entries cap here.

        Errors are NOT cached — getaddrinfo failures are usually
        transient (DNS hiccup, brief network glitch) and caching
        NXDOMAIN would amplify the outage's impact for as long as the
        TTL.
        """
        key = (host, port)
        now = time.monotonic()
        cached = self._dns_cache.get(key)
        if cached is not None and cached[0] > now:
            return cached[1]
        addrinfo = await asyncio.wait_for(
            self._loop.getaddrinfo(host, port, type=socket.SOCK_STREAM),
            timeout=_PROXY_READ_TIMEOUT_S,
        )
        self._dns_cache[key] = (now + _DNS_CACHE_TTL, addrinfo)
        return addrinfo

    async def _vet_upstream_target(self, host: str, port: int) -> str | None:
        """Gate 2 (blocked-IP defense) for the upstream-proxy path.

        Returns the offending address when the CONNECT must be denied,
        or None when it may be forwarded to the upstream. Pre-fix the
        upstream branch forwarded every allowlist-passing CONNECT with
        NO IP vetting at all — a child on a corporate-proxy host could
        CONNECT to ``10.0.0.5:443`` or ``169.254.169.254:443`` and the
        upstream (which legitimately reaches private space) would
        happily complete the pivot that gate 2 exists to stop.

        Two cases:

        - literal-IP target: judged directly by ``_ip_is_blocked`` —
          no resolver involved, no TOCTOU, unconditional.
        - hostname target: resolved LOCALLY and every returned address
          is vetted; any blocked record denies the CONNECT
          (fail-closed on mixed public/private answers, because we
          cannot control which record the upstream dials).

        Documented residual (TOCTOU vs the upstream resolver): the
        upstream proxy resolves the hostname independently, so a DNS
        server that answers differently for the upstream (split-horizon
        or an active rebinding attack timed between our resolve and
        the upstream's) can still steer the tunnel to a private
        address from the upstream's vantage point. Closing that fully
        would require the upstream to accept pre-resolved IP CONNECTs,
        which HTTP proxies do not offer. Local resolution failure
        (NXDOMAIN/timeout) proceeds WITH a warning rather than
        denying: on locked-down corporate networks external names
        often resolve only at the upstream proxy, and failing closed
        there would break the entire upstream path. In that case the
        upstream proxy's own egress policy is the remaining control.

        Like the direct-path gate 2, this is ENFORCING in audit mode
        too — an allowlisted target vetting to a private/loopback/
        metadata address is purely an attack signal, never a
        legitimate-workflow false positive.
        """
        try:
            ipaddress.ip_address(host)
        except ValueError:
            literal_ip = False
        else:
            literal_ip = True
        if literal_ip:
            return host if _ip_is_blocked(host) else None
        try:
            addrinfo = await self._cached_getaddrinfo(host, port)
        except (asyncio.TimeoutError, socket.gaierror) as e:
            logger.warning(
                "egress proxy: could not resolve %s locally to vet the "
                "upstream-path CONNECT (%s) — forwarding; the upstream "
                "proxy's own egress policy is the remaining control "
                "for this tunnel.",
                host, e.__class__.__name__,
            )
            return None
        for entry in (addrinfo or []):
            candidate = entry[4][0]
            if _ip_is_blocked(candidate):
                return candidate
        return None

    async def _happy_eyeballs_connect(
        self, addrinfo: list, port: int,
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter, str]:
        """RFC 8305 happy-eyeballs dial across an addrinfo list.

        Returns ``(reader, writer, dialed_ip)`` for the first address
        that connects. Cancels the loser. Falls back to the original
        sequential walk if the addrinfo list has only one family
        (no race needed).

        Why this matters: the previous code did
        ``asyncio.open_connection(host=addrinfo[0][4][0], ...)`` and
        ate a 10s ``asyncio.wait_for`` per attempt. When a host's
        first record is an IPv6 address the local link can't reach,
        the entire CONNECT stalled 10s before failing. Under bursty
        npm traffic that's a wallclock catastrophe. Happy-eyeballs
        kicks off the v4 attempt 250ms after v6 starts; whichever
        wins wins, and the loser is cancelled.

        Gate-2 (resolved-IP block) is re-applied per attempt — a
        DNS-poisoned response that returns one good and one bad IP
        won't slip the bad one in via the race.
        """
        v6, v4 = _split_addrinfo_by_family(addrinfo)

        # Gate-2 (resolved-IP block) lives in _attempt so EVERY dialed
        # address — raced or walked as fallback — is re-checked.
        async def _attempt(entry):
            family, _socktype, _proto, _, sockaddr = entry
            ip = sockaddr[0]
            if _ip_is_blocked(ip):
                raise OSError(f"IP {ip} blocked by gate 2")
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host=ip, port=port,
                                         family=family),
                timeout=_PROXY_READ_TIMEOUT_S,
            )
            return reader, writer, ip

        async def _walk_serial(entries):
            last_exc: Exception | None = None
            for entry in entries:
                try:
                    return await _attempt(entry)
                except (OSError, asyncio.TimeoutError) as e:
                    last_exc = e
                    continue
            raise last_exc if last_exc is not None else OSError(
                "no addresses to dial"
            )

        # Single-family path: no race needed, just walk in order.
        if not v6 or not v4:
            return await _walk_serial(v6 if v6 else v4)

        # Dual-family: race v6 first, kick v4 _HAPPY_EYEBALLS_DELAY later.
        # Take the first connector to succeed; cancel the other. We only
        # race the FIRST address of each family — if both fail, the
        # remaining addresses (interleaved v6/v4, preserving resolver
        # order within each family) are walked serially below. (Most
        # upstream registries return one address per family, so the
        # common case is exactly two attempts and an empty remainder.)
        remainder = []
        for i in range(1, max(len(v6), len(v4))):
            if i < len(v6):
                remainder.append(v6[i])
            if i < len(v4):
                remainder.append(v4[i])

        v6_task = asyncio.ensure_future(_attempt(v6[0]))
        v4_task: asyncio.Task | None = None

        try:
            done, pending = await asyncio.wait(
                {v6_task},
                timeout=_HAPPY_EYEBALLS_DELAY,
                return_when=asyncio.FIRST_COMPLETED,
            )
            # If v6 finished within the delay (success OR failure), and
            # it succeeded, take it. If it failed, race v4 directly.
            if v6_task in done:
                try:
                    return v6_task.result()
                except (OSError, asyncio.TimeoutError):
                    try:
                        return await _attempt(v4[0])
                    except (OSError, asyncio.TimeoutError):
                        if not remainder:
                            raise
                        return await _walk_serial(remainder)
            # v6 still pending after delay: kick off v4 in parallel.
            v4_task = asyncio.ensure_future(_attempt(v4[0]))
            done, pending = await asyncio.wait(
                {v6_task, v4_task},
                return_when=asyncio.FIRST_COMPLETED,
            )
            # First to finish — if it succeeded, take it; close/cancel
            # the loser. When both land in `done` simultaneously,
            # cancel() is a no-op — close the writer explicitly.
            winner = None
            for t in done:
                try:
                    result = t.result()
                    if winner is None:
                        winner = result
                    else:
                        result[1].close()
                except (OSError, asyncio.TimeoutError):
                    pass
            if winner is not None:
                for p in pending:
                    p.cancel()
                return winner
            # Both done in this iteration with failures? Wait the rest.
            last_err: Exception | None = None
            for t in pending:
                try:
                    result = await t
                    return result
                except (OSError, asyncio.TimeoutError) as e:
                    last_err = e
            # First address of each family failed — walk the rest
            # serially before giving up.
            if remainder:
                return await _walk_serial(remainder)
            raise last_err if last_err is not None else OSError(
                "all dual-stack attempts failed"
            )
        finally:
            # Best-effort: ensure no task is left dangling. Tasks that
            # already returned a result are no-op'd on cancel; in-flight
            # tasks get torn down so we don't leak a half-open socket.
            for t in (v6_task, v4_task):
                if t is not None and not t.done():
                    t.cancel()

    def stop(self, *, drain_timeout: float = 5.0) -> None:
        """Close the server and stop the event loop. Safe to call twice.

        Pre-fix `stop()` called `self._loop.stop` immediately, which
        terminated in-flight CONNECT tunnels mid-stream. Tunnels that
        had completed their TLS handshake but not yet finished proxying
        bytes were dropped — clients saw connection-reset mid-request,
        and the proxy's audit-log entries for those tunnels were
        truncated.

        With `drain_timeout > 0` we first stop ACCEPTING new connections
        (close the server socket via `_server.close()`), then wait up to
        `drain_timeout` seconds for existing tunnels to complete
        naturally before stopping the event loop. New connections that
        arrive during the drain window get connection-refused at the
        OS level, which is the correct behaviour for a graceful
        shutdown.

        Set `drain_timeout=0` to preserve the legacy abrupt-stop
        behaviour (callers that need synchronous teardown for tests).
        """
        if self._loop is None:
            return
        # Suppress CLOSE logging during teardown — tunnels completing
        # during the drain window would otherwise hit "I/O operation on
        # closed file" when the interpreter has already closed stderr.
        self._stopping = True
        with self._unix_lock:
            unix_paths = list(self._unix_servers.keys())
        for p in unix_paths:
            # unbind_unix handles its own loop/unlink failures; what
            # can still escape at teardown is logging to an already-
            # closed stream (ValueError) or a broken fd (OSError).
            with contextlib.suppress(OSError, ValueError):
                self.unbind_unix(p)
        if drain_timeout > 0 and self._server is not None and self._loop.is_running():
            async def _graceful():
                try:
                    self._server.close()
                    await asyncio.wait_for(
                        self._server.wait_closed(),
                        timeout=drain_timeout,
                    )
                except (asyncio.TimeoutError, RuntimeError):
                    pass
                stale = [t for t in self._unix_tasks if not t.done()]
                for t in stale:
                    t.cancel()
                if stale:
                    await asyncio.gather(*stale, return_exceptions=True)
                stale_clients = [t for t in self._client_tasks if not t.done()]
                for t in stale_clients:
                    t.cancel()
                if stale_clients:
                    await asyncio.gather(*stale_clients, return_exceptions=True)
                self._client_tasks.clear()
                self._loop.stop()
            try:
                asyncio.run_coroutine_threadsafe(_graceful(), self._loop)
            except RuntimeError:
                _graceful().close()
        elif self._loop is not None and self._loop.is_running():
            async def _cancel_unix():
                stale = [t for t in self._unix_tasks if not t.done()]
                for t in stale:
                    t.cancel()
                if stale:
                    await asyncio.gather(*stale, return_exceptions=True)
                self._loop.stop()
            try:
                asyncio.run_coroutine_threadsafe(_cancel_unix(), self._loop)
            except RuntimeError:
                pass
        else:
            try:
                self._loop.call_soon_threadsafe(self._loop.stop)
            except RuntimeError:
                pass  # loop already stopped
        # Join the daemon thread so transport _call_connection_lost
        # callbacks complete before stop() returns.  Without this,
        # the thread keeps running and may close recycled fd numbers
        # that belong to the caller's next subprocess.run pipes.
        if self._thread is not None:
            self._thread.join(timeout=drain_timeout + 2.0)

    def _stop_thread_best_effort(self) -> None:
        """Defensive cleanup helper called from ``__init__`` when the
        proxy thread fails to come up (readiness timeout or
        ``_start_error`` populated). Tries to stop the asyncio loop
        if one was assigned, then joins the thread briefly. Never
        raises — caller will re-raise its own startup error.
        """
        if self._loop is not None:
            try:
                self._loop.call_soon_threadsafe(self._loop.stop)
            except RuntimeError:
                pass
        if self._thread is not None:
            self._thread.join(timeout=2.0)

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
                    self._on_client_connected,
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
            logger.debug(
                f"egress proxy listening on 127.0.0.1:{self.port} "
                f"(allowlist: {sorted(self._allowed_hosts)})"
            )
            self._ready.set()
            self._loop.run_forever()
        except BaseException as e:  # noqa: BLE001
            self._start_error = e
            self._ready.set()
            return
        finally:
            for task in list(self._client_tasks):
                task.cancel()
            self._client_tasks.clear()
            if self._server is not None and self._loop is not None:
                self._server.close()
                # run_until_complete on a loop that crashed or was
                # stopped above raises RuntimeError; socket teardown
                # can surface OSError.
                with contextlib.suppress(RuntimeError, OSError):
                    self._loop.run_until_complete(self._server.wait_closed())
            if self._loop is not None:
                self._loop.close()

    # ----- async CONNECT handler -----

    def _on_client_connected(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
    ) -> None:
        task = asyncio.ensure_future(self._handle_client(reader, writer))
        self._client_tasks.add(task)
        task.add_done_callback(self._client_tasks.discard)

    async def _handle_client(self, reader: asyncio.StreamReader,
                             writer: asyncio.StreamWriter,
                             lane: "_Lane | None" = None) -> None:
        peer = writer.get_extra_info("peername")
        # Unix socket peers: peername is "" (empty string) or None.
        if peer is None or peer == "" or peer == b"":
            client_ip = "unix"
        elif isinstance(peer, tuple):
            client_ip = peer[0] if peer else "?"
        else:
            client_ip = str(peer) or "unix"

        # Belt-and-braces: reject any inbound connection that isn't
        # from loopback or a unix socket. Unix socket connections have
        # no peer IP — they're trusted because bind_unix() restricts
        # the socket file to mode 0600.
        if client_ip not in ("127.0.0.1", "::1", "unix"):
            logger.warning("egress proxy: rejecting non-loopback peer %s", client_ip)
            writer.close()
            return

        # Same-UID gate for loopback TCP peers (main listener AND TCP
        # lanes; unix lanes are already mode-0600 via bind_unix's
        # umask). Loopback is shared with EVERY local user — without
        # this, any other account on the host could ride the proxy's
        # allowlisted egress. TCP has no SO_PEERCRED, so the peer's
        # UID comes from its /proc/net/tcp{,6} socket row; an
        # undeterminable UID (None) is allowed by design — see
        # _loopback_peer_uid for the fail-open rationale + residuals.
        if client_ip != "unix" and isinstance(peer, tuple) and len(peer) >= 2:
            peer_uid = _loopback_peer_uid(
                peer, writer.get_extra_info("sockname"),
            )
            if peer_uid is not None and peer_uid != os.geteuid():
                logger.warning(
                    "egress proxy: rejecting loopback peer %s:%s owned "
                    "by uid %d (proxy runs as uid %d) — cross-user "
                    "loopback connections are refused",
                    client_ip, peer[1], peer_uid, os.geteuid(),
                )
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
                # Peer may already be gone (OSError); transport may be
                # detached during loop shutdown (RuntimeError).
                with contextlib.suppress(OSError, RuntimeError):
                    writer.close()
                    await writer.wait_closed()
            return

        try:
            await self._serve_tunnel(reader, writer, lane=lane)
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
            # Peer may already be gone (OSError); transport may be
            # detached during loop shutdown (RuntimeError).
            with contextlib.suppress(OSError, RuntimeError):
                writer.close()
                await writer.wait_closed()

    async def _serve_tunnel(self, reader: asyncio.StreamReader,
                            writer: asyncio.StreamWriter,
                            lane: "_Lane | None" = None) -> None:
        t_start = time.monotonic()
        event = {
            "t": t_start, "host": None, "port": None,
            "result": None, "reason": None, "resolved_ip": None,
            "lane": lane.label if lane is not None else "main",
            # Subscription key for lane-scoped buffers (labels are not
            # unique across concurrent contexts; the id is). None =
            # main listener — such events reach only run-global
            # (unsubscribed) buffers.
            "lane_id": lane.lane_id if lane is not None else None,
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
        # core.security.log_sanitisation.has_nonprintable. Imported at
        # module top to avoid a per-CONNECT dict-lookup + module-attr
        # access on the hot path.
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

        # Policy gate 1: hostname allowlist. A lane carrying its own
        # allowlist additionally scopes the connection to the hosts
        # ITS sandbox registered: the process-global set is a UNION
        # across concurrent runs (get_proxy semantics), so without
        # the lane check any sandbox could ride hosts a sibling run
        # allowlisted (cross-run confused-deputy egress).
        _lane_blocked = (
            lane is not None
            and lane.allowed_hosts is not None
            and host.lower() not in lane.allowed_hosts
        )
        if not self.is_host_allowed(host) or _lane_blocked:
            _reason = ("host not in lane allowlist" if _lane_blocked
                       else "host not in allowlist")
            # Snapshot the audit-log flag under the audit lock at the
            # decision point. The flag is mutated by acquire/release
            # ref-counting from other threads; an unlocked read here
            # (CPython-atomic for bools, but no happens-before edge
            # against the increment in acquire_audit_log_only) could
            # in principle read a stale True after a concurrent
            # release dropped the count to zero. The snapshot pattern
            # makes the race window explicit and the outcome
            # consistent with the count value at the snapshot moment.
            # Lane-scoped decision: an attributed connection is
            # judged by ITS sandbox's audit bit; only the un-laned
            # main listener consults the legacy global flag (which
            # production no longer sets — direct-construction tests
            # do). Enforce stays a global operator knob.
            with self._audit_lock:
                _audit_now = (lane.audit_log_only if lane is not None
                              else self._audit_log_only)
                _enforce_now = self._audit_enforce
            if _audit_now:
                # Audit mode: record the would-deny event. When
                # audit_enforce=False (default), fall through to allow —
                # the allowlist is advisory while operators build it.
                # When audit_enforce=True (RAPTOR_PROXY_AUDIT_ENFORCE=1),
                # deny even in audit mode: log-AND-deny semantics.
                _action = "denying" if _enforce_now else "allowing"
                logger.warning(
                    f"egress proxy: AUDIT would-deny {host}:{port} — "
                    f"{_reason} (audit mode: {_action})"
                )
                audit_event = {**event, "result": "would_deny_host",
                               "reason": f"{_reason} (audit mode)",
                               "duration": time.monotonic() - t_start,
                               "audit_enforce": _enforce_now}
                self._record(audit_event)
                _record_proxy_denial(host, port, None,
                                     "host_not_in_allowlist")
                if _enforce_now:
                    await self._write_error(writer, 403, "Forbidden")
                    return
                # Fall through to the connect path (audit_enforce=False).
            else:
                logger.warning(
                    f"egress proxy: DENY {host}:{port} — {_reason}"
                )
                event.update(result="denied_host", reason=_reason,
                             duration=time.monotonic() - t_start)
                self._record(event)
                await self._write_error(writer, 403, "Forbidden")
                return

        # Decide path: direct or via upstream proxy.
        use_upstream = (self._upstream is not None
                        and not _host_in_no_proxy(host, self._no_proxy_patterns))

        if use_upstream:
            # Tunnel through the user's upstream HTTPS_PROXY. The
            # upstream PROXY itself is trusted to live on a private IP
            # (corporate proxies legitimately do), but the TARGET is
            # not: gate 2 vets it here before any bytes reach the
            # upstream — literal non-global IPs are denied outright,
            # hostnames are locally resolved and every returned
            # address checked. See _vet_upstream_target for the
            # documented residual vs the upstream's own resolver.
            # Blocking (not log-only) in audit mode as well, matching
            # the direct-path gate 2.
            blocked_ip = await self._vet_upstream_target(host, port)
            if blocked_ip is not None:
                logger.warning(
                    "egress proxy: DENY %s:%s — upstream path, target "
                    "vets to blocked IP %s",
                    host, port, blocked_ip,
                )
                event["resolved_ip"] = blocked_ip
                event.update(
                    result="denied_resolved_ip",
                    reason=(f"resolved to blocked range: {blocked_ip} "
                            f"(upstream path)"),
                    duration=time.monotonic() - t_start,
                )
                self._record(event)
                # Same audit-mode summary routing as the direct-path
                # gate 2: the deny stays enforcing, but the attack
                # signal also lands in sandbox-summary.json.
                with self._audit_lock:
                    _audit_now = (lane.audit_log_only
                                  if lane is not None
                                  else self._audit_log_only)
                if _audit_now:
                    _record_proxy_denial(host, port, blocked_ip,
                                         "resolved_ip_blocked")
                await self._write_error(writer, 403, "Forbidden")
                return
            up_host, up_port = self._upstream
            event["resolved_ip"] = f"{up_host}:{up_port} (upstream)"
            try:
                up_reader, up_writer = await asyncio.wait_for(
                    asyncio.open_connection(host=up_host, port=up_port),
                    timeout=self._upstream_handshake_timeout,
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
                await asyncio.wait_for(
                    up_writer.drain(),
                    timeout=self._upstream_handshake_timeout,
                )
                resp_line = await asyncio.wait_for(
                    up_reader.readuntil(b"\r\n"),
                    timeout=self._upstream_handshake_timeout,
                )
            except (asyncio.TimeoutError, asyncio.IncompleteReadError,
                    ConnectionError) as e:
                logger.warning("egress proxy: upstream CONNECT failed: %s", e)
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
            # open connection via happy-eyeballs.
            try:
                addrinfo = await self._cached_getaddrinfo(host, port)
            except asyncio.TimeoutError:
                logger.warning("egress proxy: DNS timeout for %s:%s",
                                host, port)
                event.update(result="dns_failed", reason="DNS timeout",
                             duration=time.monotonic() - t_start)
                self._record(event)
                await self._write_error(writer, 504, "Gateway Timeout")
                return
            except socket.gaierror as e:
                logger.warning("egress proxy: DNS failure for %s:%s: %s",
                                host, port, e)
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
            # private / link-local. The check runs against the FIRST
            # candidate (and the happy-eyeballs dial below also re-runs
            # gate 2 on each per-attempt connect) so a multi-A-record
            # hostname where one record is private and another is public
            # still gets caught. The "first record wins gate 2" semantic
            # matches the original code; happy-eyeballs only changes
            # which record we end up CONNECTING to, not which we VET.
            _family, _socktype, _proto, _, sockaddr = addrinfo[0]
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
                    "egress proxy: DENY %s:%s — resolved to blocked IP %s",
                    host, port, resolved_ip,
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
                    _audit_now = (lane.audit_log_only
                                  if lane is not None
                                  else self._audit_log_only)
                if _audit_now:
                    _record_proxy_denial(host, port, resolved_ip,
                                         "resolved_ip_blocked")
                await self._write_error(writer, 403, "Forbidden")
                return

            try:
                up_reader, up_writer, dialed_ip = (
                    await self._happy_eyeballs_connect(addrinfo, port)
                )
            except (OSError, asyncio.TimeoutError) as e:
                logger.warning(
                    "egress proxy: upstream connect failed %s:%s (%s): %s",
                    host, port, resolved_ip, e,
                )
                event.update(result="upstream_failed",
                             reason=f"{e.__class__.__name__}: {e}",
                             duration=time.monotonic() - t_start)
                self._record(event)
                await self._write_error(writer, 502, "Bad Gateway")
                return
            # Update event with the IP we actually dialled (may differ
            # from `resolved_ip` if happy-eyeballs preferred a v4
            # address while the addrinfo's first record was v6).
            if dialed_ip != resolved_ip:
                event["resolved_ip"] = dialed_ip

        # Acknowledge tunnel established, then relay bytes both ways.
        writer.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
        await writer.drain()
        # Both legs get TCP keepalive so middlebox/NAT state survives
        # long silent stretches (thinking models). The client leg is
        # a no-op when the child rides a unix-socket lane.
        _enable_tcp_keepalive(writer)
        _enable_tcp_keepalive(up_writer)
        # Pull resolved_ip from the event dict — the direct path sets it
        # as a local variable, but the upstream-proxy branch only populates
        # event["resolved_ip"]. Referencing a bare `resolved_ip` here would
        # NameError on every upstream-proxy CONNECT, crashing the tunnel
        # handler mid-request. Read through the event dict so both paths
        # produce a valid log line.
        # Lazy %-style format so the string isn't built when INFO is
        # below the logger threshold — every CONNECT used to pay the
        # f-string formatting cost regardless of whether anything
        # consumed the line.
        logger.debug(
            "egress proxy: OPEN %s:%s -> %s",
            host, port, event.get("resolved_ip", "?"),
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
        reason: str | None = None
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
        except Exception as e:  # noqa: BLE001
            reason = f"relay ended: {e.__class__.__name__}"
            logger.debug(
                f"egress proxy: relay ended {host}:{port}: {e.__class__.__name__}"
            )
        finally:
            # Upstream may already be gone (OSError); transport may be
            # detached during loop shutdown (RuntimeError).
            with contextlib.suppress(OSError, RuntimeError):
                up_writer.close()
                await up_writer.wait_closed()
            # Update the already-recorded event with final byte counts
            # and outcome. Ring buffer holds a reference; consumers who
            # called events_since() between establishment and close will
            # see the in-progress state (result="allowed", bytes=0) and
            # those calling after close see the final state. Serialised
            # against unregister_sandbox's copy via _buffer_lock — see
            # _finalize_tunnel_event.
            self._finalize_tunnel_event(
                event, result=result, reason=reason,
                bytes_c2u=total["c2u"], bytes_u2c=total["u2c"],
                duration=time.monotonic() - t_start)
            if not self._stopping:
                logger.debug(
                    "egress proxy: CLOSE %s:%s (c2u=%s u2c=%s)",
                    host, port, total["c2u"], total["u2c"],
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
            # Pre-fix the counter was bumped BEFORE `dst.drain()`. If
            # drain raised (peer reset, broken pipe), the counter
            # had already recorded the chunk as "delivered" even
            # though the write never completed end-to-end. Audit
            # logs over-reported bytes-relayed; capacity-planning
            # off the bytes_c2u/bytes_u2c counters drifted up by
            # the size of every aborted final chunk.
            #
            # Move the increment AFTER successful drain. The
            # ConnectionResetError / BrokenPipeError branch returns
            # early without bumping so the count reflects "bytes
            # actually pushed through" rather than "bytes attempted".
            dst.write(chunk)
            try:
                await dst.drain()
            except (ConnectionResetError, BrokenPipeError):
                return
            counters[counter_key] += len(chunk)

    async def _write_error(self, writer: asyncio.StreamWriter,
                           code: int, reason: str) -> None:
        body = f"HTTP/1.1 {code} {reason}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        # Client may have hung up before the error line (OSError);
        # transport may be detached during loop shutdown (RuntimeError).
        with contextlib.suppress(OSError, RuntimeError):
            writer.write(body.encode("ascii"))
            await writer.drain()


async def _read_line(reader: asyncio.StreamReader, max_len: int) -> str | None:
    """Read one CRLF-terminated line, max_len bytes. None on error/EOF."""
    try:
        data = await asyncio.wait_for(reader.readuntil(b"\r\n"), timeout=_PROXY_CONNECT_TIMEOUT_S)
    except (asyncio.IncompleteReadError, asyncio.LimitOverrunError,
            asyncio.TimeoutError):
        return None
    if len(data) > max_len:
        return None
    return data[:-2].decode("latin-1")  # latin-1 never fails on bytes


# ----- module-level singleton API -----

def get_proxy(
    allowed_hosts: Iterable[str],
    *,
    idle_timeout: float | None = None,
) -> EgressProxy:
    """Return the process-wide proxy singleton, creating it on first call.

    Additional calls mutate the allowlist in place (UNION semantics) and
    return the same instance. Thread-safe.

    *idle_timeout* widens the per-tunnel idle timeout via max semantics:
    on first call it overrides the default (300s); on subsequent calls
    it raises the singleton's timeout if the new value is higher.
    Callers that need longer tunnels (e.g. LLM thinking models) pass
    their own timeout; callers that don't care omit it and get the
    default or whatever a previous caller already raised it to.

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
            # Broad by design: stop() on a proxy whose loop thread
            # already died runs against violated internal invariants —
            # any failure mode is acceptable as long as the stale
            # instance is discarded below.
            with contextlib.suppress(Exception):
                _instance.stop()
            _instance = None

        if _instance is None:
            import os as _os
            # Fall back through the whole conventional family: an
            # HTTP_PROXY-only or ALL_PROXY-only host is still a
            # mandatory-proxy host, and every value here is an HTTP
            # CONNECT-capable proxy URL usable for our tunnels.
            upstream = (_os.environ.get("HTTPS_PROXY")
                        or _os.environ.get("https_proxy")
                        or _os.environ.get("ALL_PROXY")
                        or _os.environ.get("all_proxy")
                        or _os.environ.get("HTTP_PROXY")
                        or _os.environ.get("http_proxy"))
            if upstream:
                from core.security.env_sanitisation import (
                    normalise_proxy_url,
                )
                upstream = normalise_proxy_url(upstream) or None
            no_proxy = (_os.environ.get("NO_PROXY")
                        or _os.environ.get("no_proxy"))
            # bool(env_var) treats any non-empty string as truthy,
            # so RAPTOR_PROXY_AUDIT_ENFORCE=0 / false / no / off all
            # accidentally enabled strict mode. That's the fail-SAFE
            # direction (the operator gets MORE security than they
            # asked for), but it contradicts the standard env-var
            # convention and confuses anyone scripting against the
            # documented "=1" example. Allowlist the truthy spellings
            # explicitly; everything else (including "0" / "false" /
            # the absent var) leaves audit-mode in its default log-
            # only behaviour.
            _enforce_raw = _os.environ.get(
                "RAPTOR_PROXY_AUDIT_ENFORCE", "",
            ).strip().lower()
            audit_enforce = _enforce_raw in ("1", "true", "yes", "on")
            _instance = EgressProxy(allowed_hosts,
                                    upstream_proxy=upstream,
                                    no_proxy=no_proxy,
                                    audit_enforce=audit_enforce)
            atexit.register(_instance.stop)
            # atexit never fires on SIGTERM — add the signal-aware
            # teardown (closes listeners, unlinks unix-lane sockets)
            # with the default disposition re-delivered afterwards.
            # SIGKILL remains uncatchable; see the hook's docstring
            # for the residual.
            _install_sigterm_cleanup()
            if upstream:
                logger.info(
                    f"egress proxy: tunnelling via upstream {upstream} "
                    f"(no_proxy={no_proxy or 'none'})"
                )
        else:
            _instance.add_hosts(allowed_hosts)
        if idle_timeout is not None:
            _instance.update_idle_timeout(idle_timeout)
        return _instance


def _reset_for_tests() -> None:
    """Tear down the singleton and join its thread. Test-only."""
    global _instance
    with _lock:
        if _instance is not None:
            _instance.stop(drain_timeout=0)
            _instance = None
