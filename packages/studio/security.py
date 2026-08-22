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
- ``RemoteAccessProtection`` (ASGI middleware) validates the ``Host``
  header against loopback names unless remote binding was explicitly
  allowed (defeats DNS rebinding, which would otherwise let a foreign
  page *read* responses — including the filesystem-browsing API), and
  requires an access token from non-loopback clients when the launcher
  provisioned one (``--allow-remote``).

The layers are deliberate: fetch-metadata/Origin headers cover modern
browsers cheaply, the token covers header-less or header-spoofing clients
and any future route someone forgets to think about.
"""

from __future__ import annotations

import hmac
import ipaddress
import os
import secrets
from http.cookies import SimpleCookie
from urllib.parse import parse_qsl, urlencode

from fastapi import HTTPException, Request
from starlette.datastructures import Headers
from starlette.responses import PlainTextResponse, RedirectResponse

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


def _is_loopback_hostname(hostname: str) -> bool:
    """True if a Host-header hostname can only name this machine."""
    hostname = hostname.strip("[]")
    if hostname == "localhost":
        return True
    try:
        return ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        return False


ACCESS_TOKEN_COOKIE = "studio_auth"


def _supplied_access_token(headers: Headers) -> str:
    auth = headers.get("authorization") or ""
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    cookie = SimpleCookie()
    cookie.load(headers.get("cookie") or "")
    morsel = cookie.get(ACCESS_TOKEN_COOKIE)
    return morsel.value if morsel else ""


class RemoteAccessProtection:
    """Pure-ASGI middleware guarding non-loopback access.

    Two checks, both driven by env the launcher sets (see raptor_studio.py):

    - Unless ``STUDIO_ALLOW_REMOTE=1``, the ``Host`` header must name
      loopback. A DNS-rebinding page resolves its own hostname to
      127.0.0.1 to escape the same-origin policy, but it cannot control
      the Host header its requests carry — rejecting foreign hosts kills
      the read primitive.
    - When ``STUDIO_AUTH_TOKEN`` is set (remote binding), EVERY client —
      loopback included — must present it: ``Authorization: Bearer``, the
      ``studio_auth`` cookie, or a one-time ``?token=`` query param that
      is exchanged for the cookie via redirect. Loopback gets no
      exemption because in remote mode the Host check is off, and a
      DNS-rebinding page in a browser on the studio host connects *from*
      loopback with its own hostname as both Host and Origin. It still
      cannot authenticate: browsers key cookies by host, so the rebound
      hostname's cookie jar never holds ``studio_auth``.
    """

    def __init__(self, app) -> None:
        self.app = app

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = Headers(scope=scope)

        if os.environ.get("STUDIO_ALLOW_REMOTE") != "1":
            host = _host_without_port(headers.get("host") or "")
            if not _is_loopback_hostname(host):
                response = PlainTextResponse(
                    "invalid host header (studio is bound to loopback; "
                    "see --allow-remote)",
                    status_code=400,
                )
                await response(scope, receive, send)
                return

        expected = os.environ.get("STUDIO_AUTH_TOKEN") or ""
        if expected:
            supplied = _supplied_access_token(headers)
            if supplied and hmac.compare_digest(supplied, expected):
                await self.app(scope, receive, send)
                return
            response = self._token_exchange_or_401(scope, expected)
            await response(scope, receive, send)
            return

        await self.app(scope, receive, send)

    @staticmethod
    def _token_exchange_or_401(scope, expected: str):
        """Accept ?token=… once, converting it into the auth cookie."""
        params = parse_qsl(scope.get("query_string", b"").decode("latin-1"))
        supplied = dict(params).get("token") or ""
        if not hmac.compare_digest(supplied, expected):
            return PlainTextResponse(
                "access token required (start studio with --allow-remote "
                "to obtain one)",
                status_code=401,
            )
        remaining = [(k, v) for k, v in params if k != "token"]
        url = scope.get("path", "/")
        if url.startswith("//"):
            # A protocol-relative path would turn the 303 into an
            # off-site redirect. Collapse it to a local absolute path.
            url = "/" + url.lstrip("/")
        if remaining:
            url += "?" + urlencode(remaining)
        response = RedirectResponse(url, status_code=303)
        response.set_cookie(
            ACCESS_TOKEN_COOKIE, expected, httponly=True, samesite="strict"
        )
        return response


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
