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
"""

from __future__ import annotations

import importlib.util
import logging
import math
import os
import threading
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


class ClientShards:
    """A fixed set of independent ``httpx.Client`` instances with
    least-in-flight selection.

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
    """

    def __init__(
        self,
        build: Callable[[], httpx.Client],
        count: int,
    ) -> None:
        if count < 1:
            raise ValueError("ClientShards needs at least one shard")
        self._clients: list[httpx.Client] = [build() for _ in range(count)]
        self._in_flight: list[int] = [0] * count
        self._lock = threading.Lock()
        self._closed = False

    def __len__(self) -> int:
        return len(self._clients)

    @property
    def clients(self) -> tuple[httpx.Client, ...]:
        """The shard clients (introspection — e.g. asserting every
        shard carries the protocol-observability hook)."""
        return tuple(self._clients)

    @property
    def in_flight(self) -> tuple[int, ...]:
        """Snapshot of per-shard in-flight hold counts."""
        with self._lock:
            return tuple(self._in_flight)

    def acquire(self) -> tuple[httpx.Client, int]:
        """Reserve the least-loaded shard: ``(client, index)``."""
        with self._lock:
            if self._closed:
                raise RuntimeError("ClientShards is closed")
            index = min(
                range(len(self._in_flight)),
                key=self._in_flight.__getitem__,
            )
            self._in_flight[index] += 1
            return self._clients[index], index

    def release(self, index: int) -> None:
        """Return a hold taken by :meth:`acquire`."""
        with self._lock:
            if self._in_flight[index] > 0:
                self._in_flight[index] -= 1

    def close(self) -> None:
        """Close every shard client. Idempotent."""
        with self._lock:
            if self._closed:
                return
            self._closed = True
            clients = list(self._clients)
        for client in clients:
            try:
                client.close()
            except Exception:  # noqa: BLE001 — close the rest regardless
                logger.debug("shard client close failed", exc_info=True)


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
    "upstream_shard_count",
]
