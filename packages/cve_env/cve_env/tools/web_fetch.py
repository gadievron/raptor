"""Generic HTTP GET for agent research.

Agentic-first: the agent calls this to retrieve advisories, vendor docs,
release notes, vulhub raw files, etc. Returns the body (capped) plus
headers so the LLM can reason about content type.

SSRF guards: block loopback / link-local / private ranges so the agent
cannot probe the host's internal network. Size-cap the response.
Timeout is aggressive.

Network resilience:
* ``reason_class`` categorical field on every result so the agent / callers
  can distinguish transient (rate-limited, timeout, 5xx) from permanent
  (404, blocked URL) failures.
* Built-in single-retry on transients (rate_limited / transport) before
  surfacing the failure.
"""

from __future__ import annotations

import ipaddress
import logging
import socket
import time
from dataclasses import dataclass, field
from typing import Any, Literal
from urllib.parse import urlparse

import requests

from cve_env.config import WEB_FETCH_MAX_BYTES, WEB_FETCH_TIMEOUT_SECONDS

logger = logging.getLogger(__name__)

ReasonClass = Literal["ok", "rate_limited", "transport", "auth", "not_found"]
"""Coarse categorization of why a fetch failed (or 'ok' if it succeeded).

Mapping:
* ``ok``           — HTTP 2xx
* ``rate_limited`` — HTTP 429 (retry-eligible after backoff)
* ``transport``    — timeout / connection error / HTTP 5xx (retry-eligible)
* ``auth``         — HTTP 401 / 403 (do not retry; fix credentials)
* ``not_found``    — HTTP 404 / 410 / SSRF block / scheme reject (permanent)
"""

# Transients eligible for one retry.
_TRANSIENT_CLASSES: frozenset[ReasonClass] = frozenset({"rate_limited", "transport"})
_RETRY_BACKOFF_RATE_LIMITED_S: float = 10.0
_RETRY_BACKOFF_TRANSPORT_S: float = 5.0


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
    two hardcoded names) but ``requests.get`` then resolves DNS and may
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
        # Resolution failure: fail closed — block the request rather than
        # allowing it through to requests.get which would resolve
        # independently and could succeed where getaddrinfo failed.
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


def _fetch_once(
    *,
    url: str,
    headers: dict[str, str] | None,
    timeout_seconds: float,
    max_bytes: int,
) -> FetchResult:
    """Single HTTP GET attempt. Sets ``reason_class`` on every return."""
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
            reason=f"hostname {parsed.hostname!r} resolves to a local/private range (SSRF guard)",
            reason_class="not_found",
        )

    # DNS-rebinding guard. Even if the hostname is not a literal
    # private IP and not in our hardcoded name set, the agent could still pass
    # an attacker-controlled hostname whose A record points at 127.0.0.1 or
    # 169.254.169.254. Resolve once up-front and check ALL returned addresses.
    # TOCTOU: getaddrinfo and requests.get resolve independently. DNS rebinding
    # possible with short-TTL records. Post-redirect check (below) partially
    # mitigates.
    rebind_reason = _resolve_hostname_safe(parsed.hostname)
    if rebind_reason is not None:
        return FetchResult(
            ok=False,
            url=url,
            reason=rebind_reason,
            reason_class="not_found",
        )

    req_headers: dict[str, str] = {
        "User-Agent": "cve-env/0.1 (agentic CVE env builder)",
    }
    if headers:
        req_headers.update(headers)

    try:
        resp = requests.get(
            url,
            headers=req_headers,
            timeout=timeout_seconds,
            stream=True,
            allow_redirects=True,
            # Defeat env-based proxy injection (HTTP_PROXY / HTTPS_PROXY).
            # Empty dict ({}) is a no-op in `requests` — env vars still merge —
            # so the explicit empty-string sentinel is required.
            proxies={"http": "", "https": ""},
        )
    except requests.exceptions.Timeout:
        return FetchResult(
            ok=False,
            url=url,
            reason=f"timeout after {timeout_seconds}s",
            reason_class="transport",
        )
    except requests.exceptions.RequestException as exc:
        return FetchResult(
            ok=False, url=url, reason=f"request error: {exc}", reason_class="transport"
        )

    # DNS-rebinding post-connect check: verify the actual peer IP is safe.
    # The pre-request _resolve_hostname_safe check can be bypassed via
    # short-TTL DNS rebinding (requests.get resolves independently).
    # This check catches rebinding by inspecting the actual connection.
    _peer_ip_str = None
    try:
        _raw_sock = getattr(
            getattr(
                getattr(resp, "raw", None), "_connection", None
            ),
            "sock",
            None,
        )
        if _raw_sock is None:
            _raw_sock = getattr(
                getattr(resp, "raw", None), "_fp", None
            )
            if _raw_sock is not None:
                _raw_sock = getattr(_raw_sock, "raw", None)
                if _raw_sock is not None:
                    _raw_sock = getattr(_raw_sock, "_sock", None)
        if _raw_sock is not None and hasattr(_raw_sock, "getpeername"):
            _peer_addr = _raw_sock.getpeername()
            if _peer_addr:
                _peer_ip_str = _peer_addr[0]
    except Exception:
        pass
    if _peer_ip_str is not None:
        try:
            if _ip_is_unsafe(ipaddress.ip_address(_peer_ip_str)):
                resp.close()
                return FetchResult(
                    ok=False,
                    url=url,
                    reason=(
                        f"DNS rebinding detected: pre-check passed but "
                        f"connected to unsafe IP {_peer_ip_str}"
                    ),
                    reason_class="not_found",
                )
        except ValueError:
            pass

    # Re-check the final URL after redirects for SSRF.
    final_url = resp.url
    final_parsed = urlparse(final_url)
    if _is_loopback_or_private(final_parsed.hostname or ""):
        return FetchResult(
            ok=False,
            url=final_url,
            status=resp.status_code,
            reason=f"post-redirect hostname {final_parsed.hostname!r} is local/private",
            reason_class="not_found",
        )

    # Defense-in-depth (RACE-2): the check above only catches IP-literal /
    # hardcoded-name redirect targets. A redirect to a public-LOOKING hostname
    # whose A record resolves to an internal IP (10.x / 169.254.169.254) would
    # otherwise pass — the pre-request guard at line 189 resolves DNS but the
    # post-redirect path did not. Bring it to parity by re-resolving the final
    # hostname. No-op for legitimate redirects (they resolve to public IPs).
    if final_parsed.hostname:
        post_redirect_reason = _resolve_hostname_safe(final_parsed.hostname)
        if post_redirect_reason is not None:
            return FetchResult(
                ok=False,
                url=final_url,
                status=resp.status_code,
                reason=f"post-redirect {post_redirect_reason}",
                reason_class="not_found",
            )

    raw = b""
    truncated = False
    with resp:
        for chunk in resp.iter_content(chunk_size=8192):
            raw += chunk
            if len(raw) >= max_bytes:
                raw = raw[:max_bytes]
                truncated = True
                break

    body: str
    try:
        body = raw.decode("utf-8")
    except UnicodeDecodeError:
        body = raw.decode("utf-8", errors="replace")

    _keep = {"content-type", "etag", "last-modified"}
    kept_headers = {k: v for k, v in resp.headers.items() if k.lower() in _keep}
    return FetchResult(
        ok=resp.ok,
        url=final_url,
        status=resp.status_code,
        content_type=str(resp.headers.get("Content-Type", "")),
        body=body,
        body_bytes=len(raw),
        truncated=truncated,
        reason="" if resp.ok else f"HTTP {resp.status_code}",
        reason_class=_classify_http_status(resp.status_code),
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

    When ``enable_retry`` is True (default), a single retry fires on a
    transient classification (``rate_limited`` or ``transport``) with a
    category-specific backoff. Permanent classes (``auth``, ``not_found``)
    surface immediately.
    """
    result = _fetch_once(
        url=url,
        headers=headers,
        timeout_seconds=timeout_seconds,
        max_bytes=max_bytes,
    )
    if not enable_retry or result.ok or result.reason_class not in _TRANSIENT_CLASSES:
        return result

    backoff = (
        _RETRY_BACKOFF_RATE_LIMITED_S
        if result.reason_class == "rate_limited"
        else _RETRY_BACKOFF_TRANSPORT_S
    )
    logger.info(
        "web_fetch transient (%s) on %s; retrying in %ss",
        result.reason_class,
        url,
        backoff,
    )
    time.sleep(backoff)
    retry_result = _fetch_once(
        url=url,
        headers=headers,
        timeout_seconds=timeout_seconds,
        max_bytes=max_bytes,
    )
    return retry_result


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
