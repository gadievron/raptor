"""Generic HTTP GET for agent research.

Agentic-first: the agent's research tools call this to retrieve
advisories, vendor docs, release notes, vulhub raw files, etc. Returns
the body (capped) plus selected headers so the LLM can reason about
content type.

Transport is :mod:`core.http` (``UrllibClient``) — RAPTOR's single
outbound chokepoint: pooled, size-capped, Retry-After-aware, and it
snapshots the operator's ``https_proxy``/``no_proxy`` at construction.
The pre-integration implementation drove ``requests`` directly and
*disabled proxy resolution entirely*; on operator hosts whose only
egress is a proxy, every research fetch timed out.

What stays here is cve-env domain logic:

* SSRF guards — block loopback / link-local / private ranges, resolve
  hostnames up front, PIN each request's connection to the vetted
  addresses (the transport would otherwise re-resolve at connect time,
  leaving a check/connect TOCTOU for low-TTL rebinding DNS), and
  re-check every redirect hop, so the agent cannot probe internal
  networks. (The old best-effort post-connect peer-socket introspection
  is gone — core.http's pooling doesn't expose the socket; on proxied
  deployments name resolution happens at the operator's trusted proxy,
  where the pin is a passthrough.)
* The ``ReasonClass`` taxonomy + ``FetchResult`` shape the research
  tools and the LLM consume.

Retries on transients are core.http's (429/5xx/network with
Retry-After honoured); ``enable_retry`` maps onto the client's retry
count instead of a local sleep loop.
"""

from __future__ import annotations

import contextlib
import ipaddress
import logging
import socket
import threading
from dataclasses import dataclass, field
from typing import Any, Iterator, Literal
from urllib.parse import urlparse

from core.http import HttpError, SizeLimitExceeded

from cve_env.config import WEB_FETCH_MAX_BYTES, WEB_FETCH_TIMEOUT_SECONDS

logger = logging.getLogger(__name__)

_USER_AGENT = "cve-env/0.1 (agentic CVE env builder)"

# Hop budget for the caller-side redirect loop in :func:`web_fetch`.
_MAX_REDIRECTS = 5

ReasonClass = Literal["ok", "rate_limited", "transport", "auth", "not_found"]
"""Coarse categorization of why a fetch failed (or 'ok' if it succeeded).

Mapping:
* ``ok``           — HTTP 2xx
* ``rate_limited`` — HTTP 429 (retry-eligible after backoff)
* ``transport``    — timeout / connection error / HTTP 5xx (retry-eligible)
* ``auth``         — HTTP 401 / 403 (do not retry; fix credentials)
* ``not_found``    — HTTP 404 / 410 / SSRF block / scheme reject (permanent)
"""

_client_singleton = None


def _client():
    """Lazy singleton UrllibClient (constructor snapshots proxy env)."""
    global _client_singleton
    if _client_singleton is None:
        from core.http.urllib_backend import UrllibClient

        _client_singleton = UrllibClient(user_agent=_USER_AGENT)
    return _client_singleton


def _classify_http_status(status: int) -> ReasonClass:
    """Map an HTTP status code to a ReasonClass."""
    if 200 <= status < 300:
        return "ok"
    if status == 429:
        return "rate_limited"
    if status in (401, 403):
        return "auth"
    if status in (404, 410):
        return "not_found"
    if 500 <= status < 600:
        return "transport"
    # Other 3xx/4xx: treat as not_found (permanent) by default.
    return "not_found"


@dataclass
class FetchResult:
    ok: bool
    url: str
    status: int = 0
    content_type: str = ""
    body: str = ""
    body_bytes: int = 0
    truncated: bool = False
    reason: str = ""
    reason_class: ReasonClass = "ok"
    headers: dict[str, str] = field(default_factory=dict)


def _ip_is_unsafe(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """True if ``ip`` is an SSRF-class destination (loopback / private /
    link-local / multicast / reserved / unspecified). Shared between
    ``_is_loopback_or_private`` and ``_resolve_hostname_safe`` so the two
    SSRF guards can never drift apart — adding a new disallowed class
    here updates both call sites.
    """
    return bool(
        ip.is_loopback
        or ip.is_private
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def _is_loopback_or_private(hostname: str) -> bool:
    """True for localhost / private / link-local / cloud metadata IPs."""
    if not hostname:
        return False
    lowered = hostname.lower().strip(".")
    if lowered in {"localhost", "metadata.google.internal"}:
        return True
    try:
        ip = ipaddress.ip_address(lowered)
    except ValueError:
        return False
    return _ip_is_unsafe(ip)


def _scheme_allowed(scheme: str) -> bool:
    return scheme.lower() in {"http", "https"}


def _vet_hostname(
    hostname: str, port: int | None = None
) -> tuple[str | None, list[Any]]:
    """Resolve ``hostname`` and reject if any IP is private.

    Closes half of the DNS-rebinding bypass: a hostname like
    ``evil.example.com`` passes ``_is_loopback_or_private`` (which only
    checks IP literals + two hardcoded names) but the transport then
    resolves DNS and may fetch ``127.0.0.1`` / ``169.254.169.254``. We
    resolve via ``socket.getaddrinfo`` BEFORE the request and reject if
    ANY returned address is loopback / private / link-local / metadata.

    Returns ``(reason, vetted_addrs)``. ``reason`` is ``None`` when the
    hostname resolves only to public addresses; the vetted addrinfo list
    is what the caller must PIN the actual connection to (see
    ``_pinned_dns``) — checking here and letting the transport
    re-resolve independently would leave the check-time/connect-time
    TOCTOU open for a low-TTL attacker DNS.
    """
    try:
        infos = socket.getaddrinfo(hostname, port, proto=socket.IPPROTO_TCP)
    except (OSError, UnicodeError) as exc:
        # Resolution failure: fail closed — block the request rather
        # than letting the transport resolve independently and possibly
        # succeed where getaddrinfo failed.
        logger.debug("getaddrinfo(%s) failed: %s", hostname, exc)
        return (
            f"hostname {hostname!r} DNS resolution failed: {exc} "
            f"(SSRF guard: fail closed on resolution failure)"
        ), []
    for info in infos:
        sockaddr = info[4]
        if not sockaddr:
            continue
        ip_str = sockaddr[0]
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            continue
        if _ip_is_unsafe(ip):
            return (
                f"hostname {hostname!r} resolves to {ip_str} "
                f"which is loopback/private (SSRF guard)"
            ), []
    return None, list(infos)


def _resolve_hostname_safe(hostname: str) -> str | None:
    """Vet ``hostname``'s DNS (see :func:`_vet_hostname`); reason or None."""
    return _vet_hostname(hostname)[0]


# One process-wide getaddrinfo wrapper consulting a THREAD-LOCAL pin
# stack (installed once, passthrough when the current thread holds no
# pin). A per-request save/patch/restore of ``socket.getaddrinfo`` would
# race under concurrent callers and could leave a stale closure
# installed process-wide; the thread-local stack keeps the pin visible
# exactly on the resolving thread for exactly one request.
_pin_local = threading.local()
# Captured at import (not lazily at first pin): a lazy capture taken while
# a caller had temporarily replaced socket.getaddrinfo would freeze that
# replacement in as the "original" forever.
_original_getaddrinfo = socket.getaddrinfo


def _pinning_getaddrinfo(host, port, *args, **kwargs):  # noqa: ANN001, ANN002, ANN003
    pins = getattr(_pin_local, "stack", None)
    if pins:
        for mapping in reversed(pins):
            addrs = mapping.get(host)
            if addrs is not None:
                return addrs
    return _original_getaddrinfo(host, port, *args, **kwargs)


# Installed once at import (pure passthrough while no pin is active on the
# calling thread). Lazy installation would race with callers that
# temporarily replace socket.getaddrinfo: a save/restore around a lazy
# install can strip the wrapper back out, silently disabling every later
# pin.
socket.getaddrinfo = _pinning_getaddrinfo


@contextlib.contextmanager
def _pinned_dns(hostname: str, addrs: list[Any]) -> Iterator[None]:
    """Pin ``hostname`` to the already-vetted addresses for one request.

    The transport resolves hostnames itself at connect time; without the
    pin, a low-TTL attacker DNS can answer a public IP to the guard and
    a private one to the connection. On proxied deployments the
    transport resolves the PROXY host instead, so the pin is simply a
    passthrough there.
    """
    if not addrs:
        yield
        return
    stack = getattr(_pin_local, "stack", None)
    if stack is None:
        stack = []
        _pin_local.stack = stack
    stack.append({hostname: addrs})
    try:
        yield
    finally:
        stack.pop()


def _guard_url(
    url: str,
) -> tuple[FetchResult | None, tuple[str, list[Any]] | None]:
    """Run the pre-request SSRF/scheme guards.

    Returns ``(rejection, pin)``: rejection is ``None`` to proceed;
    ``pin`` is the ``(hostname, vetted_addrs)`` the request must be
    connection-pinned to (``None`` for IP-literal URLs, which need no
    resolution)."""
    parsed = urlparse(url)
    if not _scheme_allowed(parsed.scheme):
        return FetchResult(
            ok=False,
            url=url,
            reason=f"scheme {parsed.scheme!r} not allowed; use http/https",
            reason_class="not_found",
        ), None
    if not parsed.hostname:
        return FetchResult(
            ok=False, url=url, reason="url has no hostname", reason_class="not_found"
        ), None
    if _is_loopback_or_private(parsed.hostname):
        return FetchResult(
            ok=False,
            url=url,
            reason=(
                f"hostname {parsed.hostname!r} resolves to a local/private "
                f"range (SSRF guard)"
            ),
            reason_class="not_found",
        ), None
    try:
        port = parsed.port
    except ValueError:
        port = None
    default_port = 443 if parsed.scheme.lower() == "https" else 80
    rebind_reason, vetted = _vet_hostname(
        parsed.hostname, port or default_port
    )
    if rebind_reason is not None:
        return FetchResult(
            ok=False, url=url, reason=rebind_reason, reason_class="not_found"
        ), None
    return None, (parsed.hostname, vetted)


def _fetch_truncated_body(
    url: str, headers: dict[str, str] | None, timeout_seconds: float,
    max_bytes: int,
) -> bytes:
    """Stream the body of an over-cap response, keeping the first
    ``max_bytes``. Chunks yielded before core.http raises
    ``SizeLimitExceeded`` are kept — that raise is expected here."""
    buf = bytearray()
    try:
        for chunk in _client().stream_bytes(
            url,
            timeout=max(1, int(timeout_seconds)),
            max_bytes=max_bytes,
            headers=headers,
            retries=0,
        ):
            buf.extend(chunk)
    except SizeLimitExceeded:
        pass
    except HttpError:
        # Second fetch racing the first can fail; whatever we captured
        # (possibly nothing) is still the best available body.
        logger.debug("truncated-body re-fetch failed for %s", url, exc_info=True)
    return bytes(buf[:max_bytes])


def _probe_status(
    url: str, headers: dict[str, str] | None, timeout: int
) -> int:
    """Best-effort HEAD to learn the status of an oversize response.

    The size-capped GET aborts mid-read without the status, so an
    oversize 429/500 error page would otherwise masquerade as a
    successful truncated fetch. Returns 0 when the status stays
    unknown (never raises)."""
    try:
        resp = _client().request(
            "HEAD",
            url,
            headers=headers or None,
            timeout=timeout,
            max_bytes=1024,
            retries=0,
            raise_on_status=False,
        )
        return int(resp.status or 0)
    except HttpError as exc:
        return int(exc.status or 0)
    except Exception:  # noqa: BLE001 — status probe must never raise
        return 0


def _fetch_once(
    *,
    url: str,
    headers: dict[str, str] | None,
    timeout_seconds: float,
    max_bytes: int,
    retries: int,
) -> FetchResult:
    """Single guarded GET through core.http. Sets ``reason_class`` on
    every return."""
    guard, pin = _guard_url(url)
    if guard is not None:
        return guard

    timeout = max(1, int(timeout_seconds))
    # Every transport call for this URL (the GET, the oversize-status
    # probe, the truncated-body re-stream) runs under the DNS pin so it
    # connects to the addresses the guard vetted — never a re-resolved
    # (possibly rebinded) one. The pin also spans the post-response
    # re-checks: for the requested hostname they must judge the address
    # actually connected to, while a DIFFERENT final hostname misses the
    # pin and re-resolves for real.
    pin_host, pin_addrs = pin if pin is not None else ("", [])
    with _pinned_dns(pin_host, pin_addrs):
        return _fetch_once_pinned(
            url=url,
            headers=headers,
            timeout=timeout,
            max_bytes=max_bytes,
            retries=retries,
            timeout_seconds=timeout_seconds,
        )


def _fetch_once_pinned(
    *,
    url: str,
    headers: dict[str, str] | None,
    timeout: int,
    max_bytes: int,
    retries: int,
    timeout_seconds: float,
) -> FetchResult:
    """Transport + response handling for :func:`_fetch_once`; runs with
    the caller's DNS pin active."""
    try:
        resp = _client().request(
            "GET",
            url,
            headers=headers or None,
            timeout=timeout,
            total_timeout=max(timeout * (retries + 2), timeout + 10),
            max_bytes=max_bytes,
            retries=retries,
            follow_redirects=True,
            raise_on_status=False,
        )
    except SizeLimitExceeded as exc:
        # Body exceeded the cap mid-read. When the exception carries the
        # real status and it's an error, report it honestly — an oversize
        # 429/404/500 page is NOT a successful fetch, and fabricating a
        # 200 would hide rate-limits from the consumers' budget/cooldown
        # logic. Only the 2xx/unknown case re-streams the truncated body.
        exc_status = exc.status or 0
        if not exc_status:
            exc_status = _probe_status(url, headers, timeout)
        # 405/501 just mean the server refuses HEAD — not the GET's
        # status.
        if exc_status in (405, 501):
            exc_status = 0
        if exc_status and not (200 <= exc_status < 300):
            return FetchResult(
                ok=False,
                url=url,
                status=exc_status,
                truncated=True,
                reason=(
                    f"HTTP {exc_status} (body exceeded {max_bytes} bytes)"
                ),
                reason_class=_classify_http_status(exc_status),
            )
        body_raw = _fetch_truncated_body(
            url, headers, timeout_seconds, max_bytes
        )
        return FetchResult(
            ok=True,
            url=url,
            status=exc_status or 200,
            body=body_raw.decode("utf-8", errors="replace"),
            body_bytes=len(body_raw),
            truncated=True,
            reason_class="ok",
        )
    except HttpError as exc:
        status = exc.status or 0
        reason_class: ReasonClass = (
            _classify_http_status(status) if status else "transport"
        )
        if reason_class == "ok":  # defensive: HttpError never carries 2xx
            reason_class = "transport"
        return FetchResult(
            ok=False,
            url=url,
            status=status,
            reason=str(exc)[:300],
            reason_class=reason_class,
        )

    # Re-check the final URL after redirects for SSRF: literal/private
    # names first, then re-resolve so a public-LOOKING redirect target
    # whose A record points inside is also rejected.
    final_url = resp.url or url
    final_parsed = urlparse(final_url)
    if _is_loopback_or_private(final_parsed.hostname or ""):
        return FetchResult(
            ok=False,
            url=final_url,
            status=resp.status,
            reason=(
                f"post-redirect hostname {final_parsed.hostname!r} is "
                f"local/private"
            ),
            reason_class="not_found",
        )
    if final_parsed.hostname:
        post_redirect_reason = _resolve_hostname_safe(final_parsed.hostname)
        if post_redirect_reason is not None:
            return FetchResult(
                ok=False,
                url=final_url,
                status=resp.status,
                reason=f"post-redirect {post_redirect_reason}",
                reason_class="not_found",
            )

    raw = resp.body
    truncated = False
    if len(raw) > max_bytes:  # defensive: the client should have capped
        raw = raw[:max_bytes]
        truncated = True

    body = raw.decode("utf-8", errors="replace")

    # "location" is kept so the caller-side redirect loop (the transport
    # backend never follows redirects itself) can resolve the next hop.
    _keep = {"content-type", "etag", "last-modified", "location"}
    kept_headers = {
        k: v for k, v in resp.headers.items() if k.lower() in _keep
    }
    ok = 200 <= resp.status < 300
    return FetchResult(
        ok=ok,
        url=final_url,
        status=resp.status,
        content_type=str(resp.headers.get("content-type", "")),
        body=body,
        body_bytes=len(raw),
        truncated=truncated,
        reason="" if ok else f"HTTP {resp.status}",
        reason_class=_classify_http_status(resp.status),
        headers=kept_headers,
    )


def web_fetch(
    *,
    url: str,
    headers: dict[str, str] | None = None,
    timeout_seconds: float = WEB_FETCH_TIMEOUT_SECONDS,
    max_bytes: int = WEB_FETCH_MAX_BYTES,
    enable_retry: bool = True,
) -> FetchResult:
    """GET ``url`` with SSRF + size guards. Never raises.

    When ``enable_retry`` is True (default), core.http retries once on
    transient failures (429 with Retry-After honoured, 5xx, network
    errors). Permanent classes (``auth``, ``not_found``) surface
    immediately — core.http does not retry those.

    Redirects are followed HERE (bounded), not in the transport — the
    pinned core.http backend never follows them, so each hop re-enters
    :func:`_fetch_once` and re-runs the full SSRF guard chain. A 3xx
    that cannot be followed (no Location, or hop budget exhausted) is
    reported as what it is — a redirect — rather than a permanent
    ``not_found`` (GitHub 301s the contents API for renamed repos;
    advisory hosts 301 http→https).
    """
    from urllib.parse import urljoin

    current_url = url
    r = None
    for _hop in range(_MAX_REDIRECTS + 1):
        r = _fetch_once(
            url=current_url,
            headers=headers,
            timeout_seconds=timeout_seconds,
            max_bytes=max_bytes,
            retries=1 if enable_retry else 0,
        )
        if not (300 <= r.status < 400):
            return r
        location = r.headers.get("location", "")
        if not location:
            return FetchResult(
                ok=False,
                url=r.url,
                status=r.status,
                reason=f"HTTP {r.status} redirect without a Location header",
                reason_class="transport",
                headers=r.headers,
            )
        current_url = urljoin(current_url, location)
    return FetchResult(
        ok=False,
        url=current_url,
        status=r.status if r is not None else 0,
        reason=(
            f"redirect limit ({_MAX_REDIRECTS}) exceeded; "
            f"last Location: {current_url}"
        ),
        reason_class="transport",
    )


def web_fetch_payload(
    *,
    url: str,
    headers: dict[str, str] | None = None,
    timeout_seconds: float = WEB_FETCH_TIMEOUT_SECONDS,
    max_bytes: int = WEB_FETCH_MAX_BYTES,
) -> dict[str, Any]:
    """Agent-tool dict shape."""
    r = web_fetch(
        url=url,
        headers=headers,
        timeout_seconds=timeout_seconds,
        max_bytes=max_bytes,
    )
    return {
        "ok": r.ok,
        "url": r.url,
        "status": r.status,
        "content_type": r.content_type,
        "body": r.body,
        "body_bytes": r.body_bytes,
        "truncated": r.truncated,
        "reason": r.reason,
        "reason_class": r.reason_class,
    }
