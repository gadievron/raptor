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
    Opt-in HTTP/2 (default off; needs the ``h2`` package). All
    concurrent calls multiplex over one connection — one CONNECT
    chain and one TLS handshake total instead of one per pooled
    connection. Off by default because the failure modes are real:
    TCP head-of-line blocking stalls every multiplexed stream on one
    lost packet, and some middleboxes misbehave on long-lived
    multiplexed tunnels. Enable per-deployment and verify.
"""

from __future__ import annotations

import importlib.util
import logging
import os
import threading

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
    that is absent, unparseable, or not strictly positive."""
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
    if value <= 0:
        logger.warning(
            "%s=%r must be positive — using default %s", name, raw, default,
        )
        return default
    return value


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
        max_keepalive_connections=int(
            _env_number(_MAX_KEEPALIVE_ENV, _DEFAULT_MAX_KEEPALIVE)
        ),
        max_connections=int(
            _env_number(_MAX_CONNECTIONS_ENV, _DEFAULT_MAX_CONNECTIONS)
        ),
    )


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
    "http2_enabled",
    "last_http_version",
    "note_http_version",
    "pool_limits",
    "protocol_counts",
    "response_event_hooks",
    "sdk_http_client",
]
