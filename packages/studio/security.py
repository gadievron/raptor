"""HTTP security controls for raptor-studio.

Studio is a local, single-user tool, but "local" does not mean "safe from
the web": any website open in the operator's browser can fire cross-origin
form POSTs at ``127.0.0.1`` and mutate settings or enqueue raptor jobs
without ever reading a response. The controls here close that class:

- ``CrossOriginProtection`` (ASGI middleware) rejects state-changing
  requests whose ``Sec-Fetch-Site`` / ``Origin`` headers prove they were
  initiated by another web origin.
- ``require_csrf_token`` (FastAPI dependency) enforces a synchronizer
  token on every state-changing form route. The token is generated per
  server instance and embedded into forms server-side, so a foreign
  origin can never obtain it (same-origin policy blocks reading our HTML).

Both layers are deliberate: fetch-metadata/Origin headers cover modern
browsers cheaply, the token covers header-less or header-spoofing clients
and any future route someone forgets to think about.
"""

from __future__ import annotations

import hmac
import secrets

from fastapi import HTTPException, Request
from starlette.datastructures import Headers
from starlette.responses import PlainTextResponse

CSRF_FORM_FIELD = "csrf_token"

# Methods that must never change state (RFC 9110); everything else is
# subject to cross-origin rejection + token validation.
_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})

# One token per server process. Studio has no user sessions — the browser
# obtains the token only by loading a form from us, which a cross-origin
# attacker cannot do.
_CSRF_TOKEN = secrets.token_urlsafe(32)


def csrf_token() -> str:
    """Return the instance CSRF token (exposed to Jinja as a global)."""
    return _CSRF_TOKEN


async def require_csrf_token(request: Request) -> None:
    """FastAPI dependency: reject form POSTs without a valid CSRF token.

    Reads the (cached) form body, so handlers can still call
    ``request.form()`` or declare ``Form(...)`` params afterwards.
    """
    form = await request.form()
    supplied = str(form.get(CSRF_FORM_FIELD) or "")
    if not hmac.compare_digest(supplied, _CSRF_TOKEN):
        raise HTTPException(403, "missing or invalid CSRF token")


def _host_without_port(host: str) -> str:
    """Normalize a Host-header / Origin-netloc value to a bare hostname."""
    host = host.strip().lower()
    if host.startswith("["):  # bracketed IPv6, e.g. [::1]:8765
        end = host.find("]")
        return host[: end + 1] if end != -1 else host
    if host.count(":") == 1:  # hostname:port
        return host.split(":", 1)[0]
    return host  # no port, or bare IPv6


def cross_origin_reason(headers: Headers) -> str | None:
    """Return a rejection reason if the request provably crossed origins.

    Browser-attached headers are trustworthy signals: a browser never lets
    a page forge ``Origin`` or ``Sec-Fetch-Site``. Requests carrying
    neither header (curl, scripts) fall through to the CSRF token check.
    """
    fetch_site = headers.get("sec-fetch-site")
    if fetch_site and fetch_site not in ("same-origin", "none"):
        return f"cross-origin request rejected (sec-fetch-site: {fetch_site})"

    origin = headers.get("origin")
    if origin:
        # Full netloc comparison, port included: a page on another local
        # port is a different origin and must not write here. "null" and
        # unparsable origins normalize to "" and are rejected.
        origin_netloc = origin.split("://", 1)[-1] if "://" in origin else ""
        host = (headers.get("host") or "").strip().lower()
        if not origin_netloc or origin_netloc.strip().lower() != host:
            return f"cross-origin request rejected (origin: {origin})"
    return None


class CrossOriginProtection:
    """Pure-ASGI middleware rejecting cross-origin state-changing requests.

    Kept as raw ASGI (not BaseHTTPMiddleware) so the SSE streaming
    endpoints pass through without response wrapping.
    """

    def __init__(self, app) -> None:
        self.app = app

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] == "http" and scope.get("method") not in _SAFE_METHODS:
            reason = cross_origin_reason(Headers(scope=scope))
            if reason:
                response = PlainTextResponse(reason, status_code=403)
                await response(scope, receive, send)
                return
        await self.app(scope, receive, send)
