#!/usr/bin/env python3
"""
Secure HTTP Client for Web Testing

Handles HTTP requests with safety features:
- Request/response logging
- Automatic rate limiting
- Session management
- Header manipulation
- Authentication handling
"""

import time
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse, urljoin

import requests

from core.logging import get_logger
from core.security.redaction import redact_secrets

_REDIRECT_STATUSES = {301, 302, 303, 307, 308}
_MAX_REDIRECTS = 10

logger = get_logger()


class WebClient:
    """Secure HTTP client for web application testing."""

    def __init__(self, base_url: str, timeout: int = 30, rate_limit: float = 0.5,
                 verify_ssl: bool = True, reveal_secrets: bool = False):
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self.rate_limit = rate_limit  # Seconds between requests
        self.last_request_time = 0.0
        self.verify_ssl = verify_ssl
        self.reveal_secrets = reveal_secrets

        # Session for cookie management
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'RAPTOR Security Scanner (Authorized Testing)',
        })

        # Request history
        self.request_history: List[Dict[str, Any]] = []

        logger.info(f"Web client initialized for {base_url} (verify_ssl={verify_ssl})")

    def _origin(self, url: str) -> tuple:
        """Return normalized (scheme, host, port) tuple for URL scope checks."""
        parsed = urlparse(url)
        default_port = 443 if parsed.scheme == 'https' else 80
        return (parsed.scheme.lower(), (parsed.hostname or '').lower(), parsed.port or default_port)

    def _is_in_scope(self, url: str) -> bool:
        """Check whether URL stays within the configured base origin."""
        return self._origin(url) == self._origin(self.base_url)

    def _build_url(self, path: str) -> str:
        """Build a request URL and reject paths that leave the target origin."""
        url = urljoin(self.base_url + '/', path)
        if not self._is_in_scope(url):
            raise ValueError(f"URL outside configured target scope: {url}")
        return url

    def _resolve_redirect(self, current_url: str, response: requests.Response) -> Optional[str]:
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

        logger.debug(f"{method} {log_url} -> {response.status_code} ({duration:.2f}s)")

    def _send_scoped_request(self, method: str, url: str, **kwargs) -> requests.Response:
        """Send a request while enforcing target scope across redirects."""
        history = []
        current_url = url
        current_method = method.upper()
        request_kwargs = dict(kwargs)

        for _ in range(_MAX_REDIRECTS + 1):
            response = self.session.request(
                current_method,
                current_url,
                timeout=self.timeout,
                allow_redirects=False,
                verify=self.verify_ssl,
                **request_kwargs,
            )
            response.history = history[:]

            if response.status_code not in _REDIRECT_STATUSES:
                return response

            next_url = self._resolve_redirect(current_url, response)
            if not next_url:
                return response

            history.append(response)
            current_url = next_url

            # Match browser/requests behavior for common redirect status codes:
            # 303 always becomes GET; 301/302 switch POST to GET.
            if response.status_code == 303 or (response.status_code in {301, 302} and current_method == 'POST'):
                current_method = 'GET'
                request_kwargs.pop('data', None)
                request_kwargs.pop('json', None)

            # Query params/body should not be replayed to redirect targets.
            request_kwargs.pop('params', None)

        raise requests.exceptions.TooManyRedirects(
            f"Exceeded {_MAX_REDIRECTS} redirects within configured target scope"
        )

    def get(self, path: str, params: Optional[Dict] = None,
            headers: Optional[Dict] = None) -> requests.Response:
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
            logger.warning(f"Timeout on GET {self._redact_for_logging(url)}")
            raise
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed: {self._redact_for_logging(e)}")
            raise

    def post(self, path: str, data: Optional[Dict] = None,
             json_data: Optional[Dict] = None,
             headers: Optional[Dict] = None) -> requests.Response:
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
            logger.error(f"POST request failed: {self._redact_for_logging(e)}")
            raise

    def set_auth(self, username: str, password: str) -> None:
        """Set basic authentication."""
        self.session.auth = (username, password)
        logger.info(f"Authentication set for user: {username}")

    def set_bearer_token(self, token: str) -> None:
        """Set bearer token authentication."""
        self.session.headers['Authorization'] = f'Bearer {token}'
        logger.info("Bearer token authentication configured")

    def get_cookies(self) -> Dict[str, str]:
        """Get current session cookies."""
        return dict(self.session.cookies)

    def set_cookies(self, cookies: Dict[str, str]) -> None:
        """Set session cookies."""
        self.session.cookies.update(cookies)

    def get_stats(self) -> Dict[str, Any]:
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
