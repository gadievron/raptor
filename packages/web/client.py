"""
Secure HTTP Client for Web Testing

Handles HTTP requests with safety features:
- Request/response logging
- Automatic rate limiting
- Session management
- Header manipulation
- Authentication handling
"""

import contextlib
import ipaddress
import socket
import time
from types import TracebackType
from typing import Any
from urllib.parse import urljoin, urlparse

import requests
from typing_extensions import Self

from core.logging import get_logger
from core.security.redaction import redact_secrets

_REDIRECT_STATUSES = {301, 302, 303, 307, 308}
_MAX_REDIRECTS = 10

# Cap on buffered response body. A hostile in-scope endpoint can
# serve multi-GB responses (or chunked-encoding slowloris) and OOM
# the scanner. 128 MiB is generous for real HTML / API responses
# (typical pages <1 MiB) and catches the catastrophic shapes.
_MAX_RESPONSE_BYTES = 128 * 1024 * 1024

# Cap on request_history length — without this, long-running scans
# against large targets accumulate hundreds of MB (full request +
# response captured per call) until process exit.
_MAX_REQUEST_HISTORY = 1024

logger = get_logger()


class WebClient:
    """Secure HTTP client for web application testing."""

    def __init__(self, base_url: str, timeout: int = 30, rate_limit: float = 0.5,
                 verify_ssl: bool = True, reveal_secrets: bool = False,
                 block_private_ips: bool = True):
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self.rate_limit = rate_limit  # Seconds between requests
        self.last_request_time = 0.0
        self.verify_ssl = verify_ssl
        self.reveal_secrets = reveal_secrets
        self.block_private_ips = block_private_ips

        # Session for cookie management
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'RAPTOR Security Scanner (Authorized Testing)',
        })

        # Loopback / private-IP scan targets are on the local segment
        # by definition — routing them through a corporate proxy
        # (requests honours proxy env; host NO_PROXY rarely covers
        # loopback) breaks every request. Disable proxy-env pickup
        # for those targets; internet targets keep trust_env so
        # mandatory-proxy hosts can reach them.
        _host = (urlparse(self.base_url).hostname or '').lower()
        _local = _host in ('localhost',)
        if not _local:
            try:
                _ip = ipaddress.ip_address(_host)
                _local = _ip.is_loopback or _ip.is_private
            except ValueError:
                pass
        if _local:
            self.session.trust_env = False
            logger.info(
                "Web client: %s is a loopback/private target — "
                "proxy env bypassed for this session", _host,
            )

        # Request history — bounded ring buffer. Pre-cap, long scans
        # accumulated full request/response dicts (hundreds of MB on
        # large targets) until process exit.
        from collections import deque
        self.request_history: deque[dict[str, Any]] = deque(
            maxlen=_MAX_REQUEST_HISTORY,
        )

        logger.info("Web client initialized for %s (verify_ssl=%s)", base_url, verify_ssl)

    def _origin(self, url: str) -> tuple:
        """Return normalized (scheme, host, port) tuple for URL scope checks."""
        parsed = urlparse(url)
        default_port = 443 if parsed.scheme == 'https' else 80
        return (parsed.scheme.lower(), (parsed.hostname or '').lower(), parsed.port or default_port)

    def _is_in_scope(self, url: str) -> bool:
        """Check whether URL stays within the configured base origin."""
        return self._origin(url) == self._origin(self.base_url)

    def _resolve_and_validate(self, url: str):
        """Resolve URL hostname, reject non-global IPs, return pinned addrs.

        Returns (hostname, port, addr_list) where addr_list is the
        validated getaddrinfo result, or None if validation is disabled
        or the URL uses a literal IP.  The caller pins socket.getaddrinfo
        to addr_list for the actual request, eliminating the DNS-rebinding
        TOCTOU (resolve-then-connect with a second resolution).
        """
        if not self.block_private_ips:
            return None
        parsed = urlparse(url)
        hostname = parsed.hostname
        if not hostname:
            return None
        try:
            ip_obj = ipaddress.ip_address(hostname)
            if not ip_obj.is_global:
                raise ValueError(
                    f"Blocked request to non-global IP {hostname} — "
                    f"set block_private_ips=False to scan internal targets"
                )
            return None
        except ValueError as exc:
            if "non-global" in str(exc):
                raise
        default_port = 443 if parsed.scheme == "https" else 80
        port = parsed.port or default_port
        try:
            addrs = socket.getaddrinfo(hostname, port, proto=socket.IPPROTO_TCP)
        except socket.gaierror as exc:
            raise ValueError(f"DNS resolution failed for {hostname}: {exc}") from exc
        for _family, _type, _proto, _canonname, sockaddr in addrs:
            ip_str = sockaddr[0]
            try:
                ip_obj = ipaddress.ip_address(ip_str)
            except ValueError:
                continue
            if not ip_obj.is_global:
                raise ValueError(
                    f"DNS for {hostname} resolved to non-global IP {ip_str} — "
                    f"blocked to prevent SSRF (set block_private_ips=False "
                    f"to scan internal targets)"
                )
        return (hostname, port, addrs)

    @staticmethod
    @contextlib.contextmanager
    def _pinned_dns(pinned):
        """Pin socket.getaddrinfo to pre-validated results for one request.

        Eliminates the DNS-rebinding TOCTOU: requests/urllib3 internally
        calls getaddrinfo, which would re-resolve the hostname. By
        returning our already-validated addresses, the connection goes
        to the IP we checked — not a rebinded one.
        """
        if pinned is None:
            yield
            return
        hostname, _port, addrs = pinned
        _original = socket.getaddrinfo

        def _patched(host, p, *args, **kwargs):
            if host == hostname:
                return addrs
            return _original(host, p, *args, **kwargs)

        socket.getaddrinfo = _patched
        try:
            yield
        finally:
            socket.getaddrinfo = _original

    def _build_url(self, path: str) -> str:
        """Build a request URL and reject paths that leave the target origin."""
        url = urljoin(self.base_url + '/', path)
        if not self._is_in_scope(url):
            raise ValueError(f"URL outside configured target scope: {url}")
        return url

    def _resolve_redirect(self, current_url: str, response: requests.Response) -> str | None:
        """Resolve and scope-check a redirect Location header."""
        location = response.headers.get('Location')
        if not location:
            return None
        next_url = urljoin(current_url, location)
        if not self._is_in_scope(next_url):
            raise ValueError(f"Blocked redirect outside configured target scope: {next_url}")
        return next_url

    def _rate_limit_wait(self) -> None:
        """Enforce rate limiting between requests."""
        elapsed = time.time() - self.last_request_time
        if elapsed < self.rate_limit:
            time.sleep(self.rate_limit - elapsed)
        self.last_request_time = time.time()

    def _redact_for_logging(self, value: object) -> str:
        """Apply this client's secret-redaction policy to log/display text."""
        return redact_secrets(value, reveal_secrets=self.reveal_secrets)

    def _log_request(self, method: str, url: str, response: requests.Response,
                     duration: float) -> None:
        """Log request details."""
        log_url = self._redact_for_logging(url)
        self.request_history.append({
            'method': method,
            'url': log_url,
            'status_code': response.status_code,
            'duration': duration,
            'content_length': len(response.content),
            'timestamp': time.time(),
        })

        logger.debug("%s %s -> %s (%.2fs)", method, log_url, response.status_code, duration)

    def _send_scoped_request(self, method: str, url: str, **kwargs) -> requests.Response:
        """Send a request while enforcing target scope across redirects."""
        history = []
        current_url = url
        current_method = method.upper()
        request_kwargs = dict(kwargs)

        for _ in range(_MAX_REDIRECTS + 1):
            pinned = self._resolve_and_validate(current_url)
            with self._pinned_dns(pinned):
                response = self.session.request(
                    current_method,
                    current_url,
                    timeout=self.timeout,
                    allow_redirects=False,
                    verify=self.verify_ssl,
                    stream=True,  # so we can size-cap before reading
                    **request_kwargs,
                )
            response.history = history[:]

            # Bound the buffered response body. requests' default is
            # unbounded; a hostile in-scope endpoint can serve multi-GB
            # responses (or chunked-encoding slowloris) and OOM the
            # scanner. Forcibly stream the body up to the cap; close
            # the connection if the upstream tries to exceed.
            if response.status_code not in _REDIRECT_STATUSES:
                self._enforce_response_cap(response)
                return response

            next_url = self._resolve_redirect(current_url, response)
            if not next_url:
                self._enforce_response_cap(response)
                return response

            # Eagerly close the intermediate response's underlying
            # urllib3 connection back to the pool. Pre-fix
            # `history.append(response)` kept the Response object
            # in memory; the connection stayed checked out of the
            # pool until garbage collection. On long redirect
            # chains (or many requests with redirects in flight),
            # the pool exhausted and subsequent requests blocked
            # waiting for connections to free up.
            #
            # `.close()` only releases the underlying connection;
            # the Response's status_code, headers, and (already-
            # consumed) `.content` / `.text` remain accessible
            # via the object — caller can still inspect
            # `response.history[i].headers` etc. without issue.
            with contextlib.suppress(Exception):
                response.close()

            history.append(response)
            current_url = next_url

            # Match browser/requests behavior for common redirect status codes:
            # 303 always becomes GET; 301/302 switch POST to GET.
            if response.status_code == 303 or (response.status_code in {301, 302} and current_method == 'POST'):
                current_method = 'GET'
                request_kwargs.pop('data', None)
                request_kwargs.pop('json', None)

            # Query params/body should not be replayed to redirect
            # targets. Per-call headers (including Authorization,
            # Cookie, X-API-Key) DO survive redirects — the scope
            # check above already enforces strict scheme+host+port
            # equality on every redirect target, so headers only
            # cross to same-origin endpoints. This is what
            # authenticated scanning needs: OAuth callback chains,
            # API-versioning redirects, streaming-API load-balancer
            # redirects, and cookie-based session state all require
            # the credentials to follow the redirect within the
            # configured origin.
            request_kwargs.pop('params', None)

        raise requests.exceptions.TooManyRedirects(
            f"Exceeded {_MAX_REDIRECTS} redirects within configured target scope"
        )

    def _enforce_response_cap(self, response: requests.Response) -> None:
        """Read the streamed body into ``response._content`` up to
        :data:`_MAX_RESPONSE_BYTES`. If the body exceeds the cap,
        truncate and close the connection — the caller sees a body
        of exactly ``_MAX_RESPONSE_BYTES`` bytes rather than the
        process OOMing on a hostile multi-GB response.
        """
        try:
            chunks: list[bytes] = []
            total = 0
            for chunk in response.iter_content(chunk_size=64 * 1024):
                if not chunk:
                    continue
                chunks.append(chunk)
                total += len(chunk)
                if total >= _MAX_RESPONSE_BYTES:
                    logger.warning(
                        "WebClient: response body exceeded %d-byte cap "
                        "at %s; truncating",
                        _MAX_RESPONSE_BYTES,
                        self._redact_for_logging(response.url or "<unknown>"),
                    )
                    with contextlib.suppress(Exception):
                        response.close()
                    break
            response._content = b"".join(chunks)
        except requests.exceptions.RequestException:
            # Let the caller see whatever was buffered; do not raise
            # from the cap-enforcer.
            response._content = b"".join(chunks) if chunks else b""

    def get(self, path: str, params: dict | None = None,
            headers: dict | None = None) -> requests.Response:
        """Send GET request."""
        self._rate_limit_wait()

        url = self._build_url(path)
        start_time = time.time()

        try:
            response = self._send_scoped_request(
                'GET',
                url,
                params=params,
                headers=headers or {},
            )

            duration = time.time() - start_time
            self._log_request('GET', response.url or url, response, duration)

            return response

        except requests.exceptions.Timeout:
            logger.warning("Timeout on GET %s", self._redact_for_logging(url))
            raise
        except requests.exceptions.RequestException as e:
            logger.error("Request failed: %s", self._redact_for_logging(e))
            raise

    def post(self, path: str, data: dict | None = None,
             json_data: dict | None = None,
             headers: dict | None = None) -> requests.Response:
        """Send POST request."""
        self._rate_limit_wait()

        url = self._build_url(path)
        start_time = time.time()

        try:
            response = self._send_scoped_request(
                'POST',
                url,
                data=data,
                json=json_data,
                headers=headers or {},
            )

            duration = time.time() - start_time
            self._log_request('POST', response.url or url, response, duration)

            return response

        except requests.exceptions.RequestException as e:
            logger.error("POST request failed: %s", self._redact_for_logging(e))
            raise

    def set_auth(self, username: str, password: str) -> None:
        """Set basic authentication."""
        self.session.auth = (username, password)
        logger.info("Authentication set for user: %s", username)

    def set_bearer_token(self, token: str) -> None:
        """Set bearer token authentication."""
        self.session.headers['Authorization'] = f'Bearer {token}'
        logger.info("Bearer token authentication configured")

    def get_cookies(self) -> dict[str, str]:
        """Get current session cookies."""
        return dict(self.session.cookies)

    def set_cookies(self, cookies: dict[str, str]) -> None:
        """Set session cookies."""
        self.session.cookies.update(cookies)

    def get_stats(self) -> dict[str, Any]:
        """Get request statistics."""
        if not self.request_history:
            return {}

        total_requests = len(self.request_history)
        total_duration = sum(r['duration'] for r in self.request_history)
        status_codes = {}

        for req in self.request_history:
            code = req['status_code']
            status_codes[code] = status_codes.get(code, 0) + 1

        return {
            'total_requests': total_requests,
            'total_duration': total_duration,
            'avg_duration': total_duration / total_requests if total_requests > 0 else 0,
            'status_codes': status_codes,
        }

    def close(self) -> None:
        """Close the underlying ``requests.Session`` and free its
        connection pool. Idempotent.

        Without this, long-lived scanner processes that instantiate
        ``WebClient`` per target accumulate one urllib3 connection
        pool (sockets + SSL contexts) per scan until process exit.
        """
        with contextlib.suppress(Exception):
            self.session.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        self.close()
