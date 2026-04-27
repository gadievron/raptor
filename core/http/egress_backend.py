"""Egress-allowlisted backend for :class:`core.http.HttpClient`.

Routes outbound HTTPS through the in-process proxy at
:mod:`core.sandbox.proxy`. The proxy enforces a hostname allowlist —
CONNECT to anything outside the registered hosts is refused — closing
the gap that direct urlopen leaves open: a parser compromise can't
exfiltrate to attacker hosts, only to the small set of feeds the
caller declared.

Backend swap is transparent to consumers: same :class:`HttpClient`
Protocol, same retry/backoff/size-cap behaviour (inherited from
UrllibClient via the injected pool manager). Only the network path
changes — every request is forwarded through the in-process
``ProxyManager``.

``no_proxy`` semantics — important to understand:

  - ``no_proxy`` is honoured **at the chaining layer**, NOT at the
    chokepoint layer. The in-process proxy reads ``NO_PROXY`` /
    ``no_proxy`` env vars on first call and uses them to decide
    whether to chain through ``HTTPS_PROXY`` upstream for a given
    backend host. So in a corporate-proxy setup
    (``HTTPS_PROXY=http://corp:8080``, ``no_proxy=internal.corp``),
    requests to ``internal.corp`` correctly bypass the corporate
    proxy and connect direct from the in-process proxy. This is
    the most common ``no_proxy`` use case and works as expected.

  - ``no_proxy`` does NOT bypass the in-process proxy itself.
    Every EgressClient request is forwarded through the in-process
    proxy unconditionally — the urllib3 ``ProxyManager`` doesn't
    read ``no_proxy`` at request time. **The hostname allowlist
    on the in-process proxy supersedes ``no_proxy``.** If a host
    needs to bypass the chokepoint, add it to ``allowed_hosts`` at
    construction; don't expect ``no_proxy`` to do it.

This is intentional: pre-urllib3 we used the stdlib
``urllib.request.ProxyHandler``, which silently honoured
``no_proxy`` AT THE CHOKEPOINT and would route direct (skipping
the in-process proxy entirely) for matching hosts — defeating
the allowlist. urllib3 closes that bypass; if it accepted a
``respect_no_proxy=True`` opt-out, the bypass would re-open.

Hosts are registered with the proxy on construction. The proxy is
process-wide singleton with UNION-of-all-callers allowlist semantics
(see :func:`core.sandbox.proxy.get_proxy`), so two EgressClient
instances with different ``allowed_hosts`` lists each see the union
— acceptable in our threat model since RAPTOR's own code is trusted
and the allowlist exists to constrain the attack surface, not to
isolate caller-from-caller.

Upstream proxy autodetect: when ``HTTPS_PROXY`` is set in the parent
environment at first ``get_proxy`` call, the in-process proxy chains
through it for outbound connections (except ``NO_PROXY`` matches).
Lets RAPTOR work behind corporate proxies transparently.
"""

from __future__ import annotations

import logging
from typing import Iterable

import urllib3

from core.http import DEFAULT_USER_AGENT
from core.http.urllib_backend import UrllibClient

logger = logging.getLogger(__name__)


class EgressClient(UrllibClient):
    """HttpClient backend that routes via :mod:`core.sandbox.proxy`.

    Restricts URLs to https only — the underlying proxy is
    HTTPS-CONNECT-only, so an http:// request would forward-proxy as
    ``GET http://host/`` and fail at the proxy. Rejecting at the
    validator gives the caller a clear immediate error rather than
    a confusing late one.
    """

    _ALLOWED_SCHEMES = ("https",)

    def __init__(
        self,
        allowed_hosts: Iterable[str],
        user_agent: str = DEFAULT_USER_AGENT,
    ) -> None:
        from core.sandbox.proxy import get_proxy
        proxy = get_proxy(list(allowed_hosts))
        proxy_url = f"http://127.0.0.1:{proxy.port}"
        # urllib3.ProxyManager forwards every request through the proxy
        # unconditionally — no no_proxy autodetect (unlike the stdlib
        # urllib.request.ProxyHandler we used pre-pooling). retries=False
        # so urllib3's retry doesn't fight UrllibClient's own.
        # maxsize matches UrllibClient (10) — connections to the proxy.
        # Each carries its own CONNECT tunnel; 10 simultaneous tunnels
        # is well within the in-process proxy's 64-tunnel cap.
        from core.http.urllib_backend import _DEFAULT_POOL_MAXSIZE
        proxy_pool = urllib3.ProxyManager(
            proxy_url,
            retries=False,
            cert_reqs="CERT_REQUIRED",
            maxsize=_DEFAULT_POOL_MAXSIZE,
        )
        logger.debug(
            "core.http.EgressClient: routing via in-process proxy at %s",
            proxy_url,
        )
        super().__init__(user_agent=user_agent, _http=proxy_pool)


__all__ = ["EgressClient"]
