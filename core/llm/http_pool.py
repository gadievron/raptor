"""Pooled ``httpx`` clients for the in-process LLM SDK transports.

Why this exists
---------------
Every LLM SDK RAPTOR drives in-process (anthropic, openai,
google-genai) builds its transport on ``httpx``, and httpx's default
pool expires idle keepalive connections after 5 seconds
(``httpx.Limits().keepalive_expiry``). RAPTOR's call pattern has
think-time gaps between LLM calls — prompt assembly, tool runs,
verdict processing — that routinely exceed 5 seconds, so the pooled
connection is already gone when the next call starts and every call
pays connection establishment again.

On a direct network that is one TCP + TLS handshake. Behind the
in-process egress chokepoint chained to a corporate proxy
(:mod:`core.llm.egress`) it is TCP to the chokepoint, a fresh TCP +
CONNECT negotiation to the corporate proxy, a CONNECT to the API
host, then the TLS handshake over both hops — several round trips,
each inflated by proxy latency, on every call. A keepalive window
that matches the actual inter-call gap makes connection reuse happen
at all.

Trade-off: a longer keepalive widens the stale-connection race — the
far side of an idle connection goes away and the next request fails
on first byte. The SDKs already retry connection errors, and the
same race exists today for any gap over 5 seconds; the window moves,
it does not appear.

Knobs (all optional; invalid values fall back to the default):

``RAPTOR_HTTP_KEEPALIVE_S``
    Idle keepalive expiry in seconds (default 60).
``RAPTOR_HTTP_MAX_KEEPALIVE``
    Idle connections kept in the pool (default 20).
``RAPTOR_HTTP_MAX_CONNECTIONS``
    Total concurrent connections per client (default 100).
``RAPTOR_HTTP2``
    Opt-in HTTP/2 (default off; needs the ``h2`` package). Concurrent
    calls multiplex over very few connections — one CONNECT chain and
    one TLS handshake per connection instead of one per pooled
    HTTP/1.1 connection. Off by default because the failure modes are
    real: TCP head-of-line blocking stalls every multiplexed stream
    on one lost packet, and some middleboxes misbehave on long-lived
    multiplexed tunnels. Enable per-deployment and verify.

    A single multiplexed connection is also a single point of
    failure: httpcore assigns every request to the first available
    connection, and its per-connection stream ceiling (hardcoded
    ``MAX_CONCURRENT_STREAMS = 100`` in httpcore 1.0.9, no
    constructor or ``httpx.Limits`` knob) is far above RAPTOR's
    concurrency, so ALL in-flight calls ride one connection — one
    tunnel termination aborts every one of them at once. Consumers
    that need blast-radius control shard across a small pool of
    independent clients via :class:`ClientShards` (the dispatcher's
    forwarding leg does).
``RAPTOR_HTTP2_SHARDS``
    Number of independent upstream clients the dispatcher's
    forwarding leg spreads relays across (default 4 under HTTP/2,
    1 otherwise — see :func:`upstream_shard_count`).
``RAPTOR_HTTP2_SHARD_FAIL_THRESHOLD``
    Consecutive transport failures on one shard before it is drained
    and replaced with a fresh client (default 3; active in both HTTP
    modes — see :func:`shard_failure_threshold`).
``RAPTOR_HTTP2_SHARD_MAX_AGE_S``
    Proactive shard rotation age in seconds under HTTP/2 (default
    2400 — see :func:`shard_max_age_s`). A shard past this age is
    drained at a moment with no live streams and replaced fresh,
    instead of waiting for a middlebox to terminate the long-lived
    tunnel mid-flight. Inert on HTTP/1.1, where connection lifetime
    is managed per-connection by the pool.
"""

from __future__ import annotations

import importlib.util
import logging
import math
import os
import threading
import time
from collections.abc import Callable

import httpx

logger = logging.getLogger(__name__)

_KEEPALIVE_ENV = "RAPTOR_HTTP_KEEPALIVE_S"
_MAX_KEEPALIVE_ENV = "RAPTOR_HTTP_MAX_KEEPALIVE"
_MAX_CONNECTIONS_ENV = "RAPTOR_HTTP_MAX_CONNECTIONS"
_HTTP2_ENV = "RAPTOR_HTTP2"

# Warn-once flag for "opted in but h2 not installed" — the fallback
# is silent-safe (HTTP/1.1 keeps working) but the operator asked for
# something they are not getting, so say so exactly once.
_http2_missing_warned = False

_DEFAULT_KEEPALIVE_S = 60.0
_DEFAULT_MAX_KEEPALIVE = 20
_DEFAULT_MAX_CONNECTIONS = 100


def _env_number(name: str, default: float) -> float:
    """Parse a positive number from ``name``; fall back on anything
    that is absent, unparseable, non-finite, or not strictly
    positive."""
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        value = float(raw)
    except ValueError:
        logger.warning(
            "%s=%r is not a number — using default %s", name, raw, default,
        )
        return default
    if not math.isfinite(value):
        # float() parses "nan" and "inf", and both sail past the
        # strictly-positive check below (every nan comparison is
        # False; inf really is positive). Downstream they are poison:
        # int(nan)/int(inf) in _env_count raise on the relay hot
        # path, and a nan age makes the rotation comparison always
        # False. Non-finite is invalid — warn and fall back like the
        # other invalid shapes.
        logger.warning(
            "%s=%r is not a finite number — using default %s",
            name, raw, default,
        )
        return default
    if value <= 0:
        logger.warning(
            "%s=%r must be positive — using default %s", name, raw, default,
        )
        return default
    return value


def _env_count(name: str, default: int) -> int:
    """Parse a connection count (>= 1) from ``name``; fall back on
    anything invalid. A fractional value below 1 (e.g. ``0.5``) passes
    the strictly-positive check but truncates to 0 connections — a
    pool that can never serve a request — so anything that truncates
    below 1 falls back to the default like the other invalid shapes."""
    count = int(_env_number(name, default))
    if count < 1:
        logger.warning(
            "%s=%r truncates below 1 connection — using default %s",
            name, os.environ.get(name), default,
        )
        return default
    return count


def http2_enabled() -> bool:
    """True when the operator opted in via ``RAPTOR_HTTP2`` AND the
    ``h2`` stack is installed.

    ALPN happens end-to-end inside the CONNECT tunnel, so HTTP/2
    works through the egress chokepoint and a chained corporate
    proxy. Opted-in-but-missing-h2 warns once and stays on HTTP/1.1
    — httpx would otherwise raise at client construction.
    """
    if os.environ.get(_HTTP2_ENV, "").strip().lower() not in (
        "1", "true", "yes", "on",
    ):
        return False
    if importlib.util.find_spec("h2") is None:
        global _http2_missing_warned
        if not _http2_missing_warned:
            _http2_missing_warned = True
            logger.warning(
                "%s is set but the 'h2' package is not installed — "
                "staying on HTTP/1.1. Install with: pip install h2",
                _HTTP2_ENV,
            )
        return False
    return True


# ── Negotiated-protocol observability ─────────────────────────────
#
# ``RAPTOR_HTTP2=1`` requests HTTP/2, but what actually got
# negotiated (ALPN, end-to-end through CONNECT tunnels) was invisible
# in run artifacts — "h2 active" could not be proven or disproven
# after the fact. Every client built here (and the dispatcher's
# upstream client) installs the response hook below; the LLM
# telemetry records attach ``last_http_version()`` per call so the
# negotiated protocol is provable from ``llm-telemetry.jsonl``.

_protocol_lock = threading.Lock()
_protocol_counts: dict[str, int] = {}
_last_http_version: str | None = None


def _normalize_http_version(raw: str) -> str:
    v = (raw or "").strip().upper()
    if v == "HTTP/2":
        return "h2"
    if v == "HTTP/1.1":
        return "h1"
    return v.lower() or "unknown"


def note_http_version(raw: str) -> None:
    """Record one response's negotiated protocol (normalized h1/h2)."""
    global _last_http_version
    v = _normalize_http_version(raw)
    with _protocol_lock:
        _last_http_version = v
        _protocol_counts[v] = _protocol_counts.get(v, 0) + 1


def last_http_version() -> str | None:
    """Most recently negotiated protocol seen by any pooled client in
    this process (``"h2"`` / ``"h1"``), or None before the first
    response. Telemetry attaches this per call — best-effort under
    concurrency, exact when the pool multiplexes one protocol."""
    return _last_http_version


def protocol_counts() -> dict[str, int]:
    """Snapshot of responses seen per negotiated protocol."""
    with _protocol_lock:
        return dict(_protocol_counts)


def _response_hook(response: httpx.Response) -> None:
    try:
        note_http_version(response.http_version)
    except Exception:  # noqa: BLE001 — observability must never break a call
        logger.debug("http_version note failed", exc_info=True)


def response_event_hooks() -> dict[str, list]:
    """``event_hooks`` mapping that records negotiated protocols.
    Shared by :func:`sdk_http_client` and the dispatcher's upstream
    client so both transport legs feed the same registry."""
    return {"response": [_response_hook]}


def pool_limits() -> httpx.Limits:
    """Connection-pool limits for LLM transports.

    Read from the env on every call (cheap — three lookups) so the
    knobs behave like the dispatcher's timeout knob: tunable without
    code edits, effective for every client built after the change.
    """
    return httpx.Limits(
        keepalive_expiry=_env_number(_KEEPALIVE_ENV, _DEFAULT_KEEPALIVE_S),
        max_keepalive_connections=_env_count(
            _MAX_KEEPALIVE_ENV, _DEFAULT_MAX_KEEPALIVE
        ),
        max_connections=_env_count(
            _MAX_CONNECTIONS_ENV, _DEFAULT_MAX_CONNECTIONS
        ),
    )


_HTTP2_SHARDS_ENV = "RAPTOR_HTTP2_SHARDS"

# Default shard count for the HTTP/2 forwarding leg. Both directions
# matter: fewer shards re-concentrate in-flight streams — at 1 the
# pool degenerates to the single multiplexed connection whose loss
# aborts every concurrent call at once; more shards erode HTTP/2's
# whole benefit — each shard is an independent connection paying its
# own CONNECT chain + TLS handshake and holding its own keepalive
# slot, and the blast-radius reduction plateaus fast (4 shards
# already cap the collateral of one dropped connection at roughly a
# quarter of in-flight streams).
_DEFAULT_HTTP2_SHARDS = 4


def upstream_shard_count() -> int:
    """Shard count for the dispatcher's forwarding leg.

    Default 4 under HTTP/2 (spread multiplexed streams so one dropped
    connection cannot abort every in-flight relay), 1 otherwise
    (HTTP/1.1 already uses one connection per concurrent request —
    extra client objects would only duplicate pool bookkeeping).
    ``RAPTOR_HTTP2_SHARDS`` overrides in either mode; invalid values
    (non-numeric, non-finite, zero/negative, fractional below 1) warn
    and fall back to the mode's default like every other knob here.
    """
    default = _DEFAULT_HTTP2_SHARDS if http2_enabled() else 1
    return _env_count(_HTTP2_SHARDS_ENV, default)


_SHARD_FAIL_THRESHOLD_ENV = "RAPTOR_HTTP2_SHARD_FAIL_THRESHOLD"
_SHARD_MAX_AGE_ENV = "RAPTOR_HTTP2_SHARD_MAX_AGE_S"

# Consecutive transport failures before a shard is drained. Both
# directions matter: lower (1) drains on every isolated blip —
# ordinary keepalive churn after an idle gap would rebuild shards
# continuously, each rebuild paying a fresh CONNECT chain + TLS
# handshake for a connection that was never sick; higher keeps
# routing relays onto a client whose connections have already failed
# several times in a row — every extra strike required is another
# aborted relay before the repair happens.
_DEFAULT_SHARD_FAIL_THRESHOLD = 3

# Proactive rotation age for HTTP/2 shards, in seconds. Middleboxes
# impose hard lifetimes on long-lived tunnels under load; when the
# middlebox wins the race it terminates the connection with every
# multiplexed stream still on it. Rotating proactively replaces the
# connection at a moment of our choosing — drained, zero live streams
# — instead of the middlebox's. Both directions: lower churns
# handshakes (each rotation is a fresh CONNECT chain + TLS) and, near
# the floor, degenerates toward per-request clients — the pool stops
# pooling; higher loses the race to the imposed lifetime and the
# rotation protects nothing.
_DEFAULT_SHARD_MAX_AGE_S = 2400.0
_SHARD_MAX_AGE_FLOOR_S = 60.0


def shard_failure_threshold() -> int:
    """Consecutive transport failures that drain a shard.

    Active in both HTTP modes — a repeatedly-failing HTTP/1.1 pool
    benefits from a fresh client exactly like a broken multiplexed
    connection does. ``RAPTOR_HTTP2_SHARD_FAIL_THRESHOLD`` overrides;
    invalid values (non-numeric, below 1) warn and fall back like the
    other knobs here.
    """
    return _env_count(_SHARD_FAIL_THRESHOLD_ENV, _DEFAULT_SHARD_FAIL_THRESHOLD)


def shard_max_age_s() -> float | None:
    """Proactive rotation age for the forwarding-leg shards, or None
    when rotation is off.

    Only meaningful under HTTP/2 — that is where one long-lived
    multiplexed connection concentrates every in-flight stream behind
    a middlebox-imposed tunnel lifetime. On HTTP/1.1 the pool already
    manages per-connection lifetime, so rotation is disabled rather
    than churning whole clients for nothing.
    """
    if not http2_enabled():
        return None
    value = _env_number(_SHARD_MAX_AGE_ENV, _DEFAULT_SHARD_MAX_AGE_S)
    if value < _SHARD_MAX_AGE_FLOOR_S:
        logger.warning(
            "%s=%r is below the %.0fs floor — using default %.0f",
            _SHARD_MAX_AGE_ENV, os.environ.get(_SHARD_MAX_AGE_ENV),
            _SHARD_MAX_AGE_FLOOR_S, _DEFAULT_SHARD_MAX_AGE_S,
        )
        return _DEFAULT_SHARD_MAX_AGE_S
    return value


class _Shard:
    """One slot's live client plus its lifecycle state (all fields
    guarded by the owning :class:`ClientShards` lock)."""

    __slots__ = ("born", "client", "draining", "failures", "in_flight")

    def __init__(self, client: httpx.Client) -> None:
        self.client = client
        self.in_flight = 0
        self.failures = 0
        self.born = time.monotonic()
        self.draining = False


class ClientShards:
    """A small pool of independent ``httpx.Client`` instances with
    least-in-flight selection and drain-shaped repair.

    Under HTTP/2 a single client funnels every concurrent request
    onto one multiplexed connection (see the module docstring), so
    one connection loss — e.g. a forward proxy periodically
    terminating long-lived tunnels — aborts all in-flight streams
    simultaneously. Spreading requests across N independent clients
    caps that blast radius at roughly ``1/N`` of in-flight requests.

    ``acquire()`` returns the client with the fewest in-flight
    holds plus its shard index; callers hold the shard for the full
    request lifetime and MUST ``release(index)`` in a ``finally``.
    Thread-safe; ``close()`` is idempotent.

    Lifecycle: a shard whose caller-reported consecutive transport
    failures reach ``failure_threshold``, or whose age exceeds
    ``max_age_s`` (None disables either mechanism), enters DRAINING —
    excluded from selection, never closed with live holds, retired
    (closed + slot replaced fresh or tombstoned back toward the
    target count) the moment its in-flight count reaches zero. The
    pool always has at least one selectable shard: if every live
    shard is draining with holds still in flight, ``acquire``
    provisions a fresh one rather than blocking or riding a dying
    connection. Slot indices are stable for the life of a hold —
    slots are appended or replaced in place, never shifted — so a
    caller's ``release``/``report_*`` always lands on the shard it
    acquired.
    """

    def __init__(
        self,
        build: Callable[[], httpx.Client],
        count: int,
        *,
        failure_threshold: int | None = None,
        max_age_s: float | None = None,
    ) -> None:
        if count < 1:
            raise ValueError("ClientShards needs at least one shard")
        self._build = build
        self._count = count
        self._failure_threshold = failure_threshold
        self._max_age_s = max_age_s
        self._slots: list[_Shard | None] = [
            _Shard(build()) for _ in range(count)
        ]
        self._lock = threading.Lock()
        self._closed = False

    def __len__(self) -> int:
        with self._lock:
            return sum(1 for shard in self._slots if shard is not None)

    @property
    def clients(self) -> tuple[httpx.Client, ...]:
        """The live shard clients (introspection — e.g. asserting
        every shard carries the protocol-observability hook)."""
        with self._lock:
            return tuple(
                shard.client for shard in self._slots if shard is not None
            )

    @property
    def in_flight(self) -> tuple[int, ...]:
        """Snapshot of per-live-shard in-flight hold counts."""
        with self._lock:
            return tuple(
                shard.in_flight
                for shard in self._slots
                if shard is not None
            )

    def _retire_idle_draining_locked(self) -> list[httpx.Client]:
        """Retire every draining shard with zero holds: close its
        client (returned for closing OUTSIDE the lock — close does
        I/O) and either refill the slot with a fresh shard or
        tombstone it, whichever moves the live-slot count toward the
        target. Caller holds the lock."""
        stale: list[httpx.Client] = []
        for i, shard in enumerate(self._slots):
            if shard is None or not shard.draining or shard.in_flight:
                continue
            stale.append(shard.client)
            others = sum(
                1 for j, s in enumerate(self._slots)
                if s is not None and j != i
            )
            self._slots[i] = (
                _Shard(self._build()) if others < self._count else None
            )
        return stale

    def _holds_locked(self, index: int) -> int:
        """Least-loaded selection key. Caller holds the lock and only
        passes live-slot indices."""
        shard = self._slots[index]
        return shard.in_flight if shard is not None else 0

    @staticmethod
    def _close_stale(stale: list[httpx.Client]) -> None:
        for client in stale:
            try:
                client.close()
            except Exception:  # noqa: BLE001 — close the rest regardless
                logger.debug("shard client close failed", exc_info=True)

    def acquire(self) -> tuple[httpx.Client, int]:
        """Reserve the least-loaded selectable shard: ``(client,
        index)``. Also the rotation seam: overdue shards are marked
        draining here, and idle draining shards are retired."""
        with self._lock:
            if self._closed:
                raise RuntimeError("ClientShards is closed")
            if self._max_age_s is not None:
                now = time.monotonic()
                for i, shard in enumerate(self._slots):
                    if (
                        shard is not None
                        and not shard.draining
                        and now - shard.born >= self._max_age_s
                    ):
                        shard.draining = True
                        logger.info(
                            "http shard %d rotating out at age %.0fs",
                            i, now - shard.born,
                        )
            stale = self._retire_idle_draining_locked()
            candidates = [
                i for i, shard in enumerate(self._slots)
                if shard is not None and not shard.draining
            ]
            if candidates:
                index = min(candidates, key=self._holds_locked)
            else:
                # Invariant: at least one selectable shard. Every
                # live slot is draining with holds still in flight —
                # provision fresh rather than block the relay or ride
                # a connection already condemned.
                self._slots.append(_Shard(self._build()))
                index = len(self._slots) - 1
            shard = self._slots[index]
            if shard is None:  # pragma: no cover — candidates are live
                raise RuntimeError("selected shard slot is empty")
            shard.in_flight += 1
            client = shard.client
        self._close_stale(stale)
        return client, index

    def release(self, index: int) -> None:
        """Return a hold taken by :meth:`acquire`. The last hold off
        a draining shard retires it here — the drain-shaped repair
        never closes a client with live streams."""
        with self._lock:
            shard = self._slots[index]
            if shard is None:
                return
            if shard.in_flight > 0:
                shard.in_flight -= 1
            stale = (
                self._retire_idle_draining_locked()
                if not self._closed and shard.draining
                and shard.in_flight == 0
                else []
            )
        self._close_stale(stale)

    def report_success(self, index: int) -> None:
        """Caller seam: the held shard carried a request to clean
        completion — reset its consecutive-failure count."""
        with self._lock:
            shard = self._slots[index]
            if shard is not None:
                shard.failures = 0

    def report_failure(self, index: int) -> None:
        """Caller seam: the held shard's request died a transport
        death attributable to the shard's own connections. At the
        threshold the shard drains (stops being selected) and is
        replaced once its live holds finish."""
        if self._failure_threshold is None:
            return
        with self._lock:
            shard = self._slots[index]
            if shard is None:
                return
            shard.failures += 1
            if (
                shard.failures >= self._failure_threshold
                and not shard.draining
            ):
                shard.draining = True
                logger.warning(
                    "http shard %d draining after %d consecutive "
                    "transport failures — will be replaced when its "
                    "in-flight requests finish",
                    index, shard.failures,
                )

    def close(self) -> None:
        """Close every live shard client. Idempotent."""
        with self._lock:
            if self._closed:
                return
            self._closed = True
            clients = [
                shard.client for shard in self._slots if shard is not None
            ]
        self._close_stale(clients)


def sdk_http_client(
    timeout: float | httpx.Timeout,
    *,
    trust_env: bool = True,
) -> httpx.Client:
    """Build the transport client an LLM SDK constructor receives.

    ``trust_env=False`` pins a client that ignores proxy env — for
    loopback gateways (Ollama, vLLM, LM Studio) that must never
    detour through a corporate proxy. Remote bases keep proxy-env
    behaviour so calls flow through the egress chokepoint.

    The client's own ``timeout`` is a fallback — the SDKs set their
    per-request timeout on each request they send.
    """
    return httpx.Client(
        timeout=timeout,
        trust_env=trust_env,
        limits=pool_limits(),
        http2=http2_enabled(),
        event_hooks=response_event_hooks(),
    )


__all__ = [
    "ClientShards",
    "http2_enabled",
    "last_http_version",
    "note_http_version",
    "pool_limits",
    "protocol_counts",
    "response_event_hooks",
    "sdk_http_client",
    "shard_failure_threshold",
    "shard_max_age_s",
    "upstream_shard_count",
]
