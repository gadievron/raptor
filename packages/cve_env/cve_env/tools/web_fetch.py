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
  hostnames up front (DNS-rebinding pre-check), and re-check the final
  post-redirect hostname, so the agent cannot probe internal networks.
  (The old best-effort post-connect peer-socket introspection is gone —
  core.http's pooling doesn't expose the socket; on proxied deployments
  name resolution happens at the operator's trusted proxy anyway.)
* The ``ReasonClass`` taxonomy + ``FetchResult`` shape the research
  tools and the LLM consume.

Retries on transients are core.http's (429/5xx/network with
Retry-After honoured); ``enable_retry`` maps onto the client's retry
count instead of a local sleep loop.
"""

from __future__ import annotations

import ipaddress
import logging
import socket
from dataclasses import dataclass, field
from typing import Any, Literal
from urllib.parse import urlparse

from core.http import HttpError, SizeLimitExceeded

from cve_env.config import WEB_FETCH_MAX_BYTES, WEB_FETCH_TIMEOUT_SECONDS

logger = logging.getLogger(__name__)

_USER_AGENT = "cve-env/0.1 (agentic CVE env builder)"

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


def _resolve_hostname_safe(hostname: str) -> str | None:
    """Resolve ``hostname`` and reject if any IP is private.

    Closes the DNS-rebinding bypass: a hostname like ``evil.example.com``
    passes ``_is_loopback_or_private`` (which only checks IP literals +
    two hardcoded names) but the transport then resolves DNS and may
    fetch ``127.0.0.1`` / ``169.254.169.254``. We resolve via
    ``socket.getaddrinfo`` BEFORE the request and reject if ANY returned
    address is loopback / private / link-local / metadata.

    Returns ``None`` if the hostname resolves to only public addresses.
    Returns a reason string (suitable for ``FetchResult.reason``) if any
    resolved IP is unsafe OR if resolution failed.
    """
    try:
        infos = socket.getaddrinfo(hostname, None)
    except (OSError, UnicodeError) as exc:
        # Resolution failure: fail closed — block the request rather
        # than letting the transport resolve independently and possibly
        # succeed where getaddrinfo failed.
        logger.debug("getaddrinfo(%s) failed: %s", hostname, exc)
        return (
            f"hostname {hostname!r} DNS resolution failed: {exc} "
            f"(SSRF guard: fail closed on resolution failure)"
        )
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
            )
    return None


def _guard_url(url: str) -> FetchResult | None:
    """Run the pre-request SSRF/scheme guards. None = proceed."""
    parsed = urlparse(url)
    if not _scheme_allowed(parsed.scheme):
        return FetchResult(
            ok=False,
            url=url,
            reason=f"scheme {parsed.scheme!r} not allowed; use http/https",
            reason_class="not_found",
        )
    if not parsed.hostname:
        return FetchResult(
            ok=False, url=url, reason="url has no hostname", reason_class="not_found"
        )
    if _is_loopback_or_private(parsed.hostname):
        return FetchResult(
            ok=False,
            url=url,
            reason=(
                f"hostname {parsed.hostname!r} resolves to a local/private "
                f"range (SSRF guard)"
            ),
            reason_class="not_found",
        )
    rebind_reason = _resolve_hostname_safe(parsed.hostname)
    if rebind_reason is not None:
        return FetchResult(
            ok=False, url=url, reason=rebind_reason, reason_class="not_found"
        )
    return None


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
    guard = _guard_url(url)
    if guard is not None:
        return guard

    timeout = max(1, int(timeout_seconds))
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
    except SizeLimitExceeded:
        # Body exceeded the cap mid-read. Re-stream to recover the
        # first max_bytes; status/headers of the oversize response are
        # not recoverable through this path.
        body_raw = _fetch_truncated_body(url, headers, timeout_seconds, max_bytes)
        return FetchResult(
            ok=True,
            url=url,
            status=200,
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

    _keep = {"content-type", "etag", "last-modified"}
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
    """
    return _fetch_once(
        url=url,
        headers=headers,
        timeout_seconds=timeout_seconds,
        max_bytes=max_bytes,
        retries=1 if enable_retry else 0,
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
