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
import requests
from urllib.parse import urlparse, urljoin

from core.logging import get_logger

logger = get_logger()


class WebClient:
    """Secure HTTP client for web application testing."""

    def __init__(self, base_url: str, timeout: int = 30, rate_limit: float = 0.5, verify_ssl: bool = True):
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self.rate_limit = rate_limit  # Seconds between requests
        self.last_request_time = 0.0
        self.verify_ssl = verify_ssl

        # Session for cookie management
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'RAPTOR Security Scanner (Authorized Testing)',
        })

        # Request history
        self.request_history: List[Dict[str, Any]] = []

        logger.info(f"Web client initialized for {base_url} (verify_ssl={verify_ssl})")

    def _rate_limit_wait(self) -> None:
        """Enforce rate limiting between requests."""
        elapsed = time.time() - self.last_request_time
        if elapsed < self.rate_limit:
            time.sleep(self.rate_limit - elapsed)
        self.last_request_time = time.time()

    def _log_request(self, method: str, url: str, response: requests.Response,
                     duration: float) -> None:
        """Log request details."""
        self.request_history.append({
            'method': method,
            'url': url,
            'status_code': response.status_code,
            'duration': duration,
            'content_length': len(response.content),
            'timestamp': time.time(),
        })

        logger.debug(f"{method} {url} -> {response.status_code} ({duration:.2f}s)")

    def get(self, path: str, params: Optional[Dict] = None,
            headers: Optional[Dict] = None) -> requests.Response:
        """Send GET request."""
        self._rate_limit_wait()

        url = urljoin(self.base_url, path)
        start_time = time.time()

        try:
            response = self.session.get(
                url,
                params=params,
                headers=headers or {},
                timeout=self.timeout,
                allow_redirects=True,
                verify=self.verify_ssl,
            )

            duration = time.time() - start_time
            self._log_request('GET', url, response, duration)

            return response

        except requests.exceptions.Timeout:
            logger.warning(f"Timeout on GET {url}")
            raise
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed: {e}")
            raise

    def post(self, path: str, data: Optional[Dict] = None,
             json_data: Optional[Dict] = None,
             headers: Optional[Dict] = None) -> requests.Response:
        """Send POST request."""
        self._rate_limit_wait()

        url = urljoin(self.base_url, path)
        start_time = time.time()

        try:
            response = self.session.post(
                url,
                data=data,
                json=json_data,
                headers=headers or {},
                timeout=self.timeout,
                allow_redirects=True,
                verify=self.verify_ssl,
            )

            duration = time.time() - start_time
            self._log_request('POST', url, response, duration)

            return response

        except requests.exceptions.RequestException as e:
            logger.error(f"POST request failed: {e}")
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
