"""Web cache poisoning and cache deception -- Kettle methodology.

Web cache poisoning: inject unkeyed input that the app reflects into a
cached response, delivering malicious content to every subsequent visitor.

Web cache deception: trick the cache into storing an authenticated response
under a path that maps to a cache rule for static files, making it publicly
readable.

Reference: James Kettle, PortSwigger Research
"""

from __future__ import annotations

import re
from typing import List, Optional, TYPE_CHECKING

from packages.web.checks.base import Check, CheckCategory, CheckResult, registry

if TYPE_CHECKING:
    from packages.web.client import WebClient
    from packages.web.auth import AuthSession

_UNKEYED_HEADERS = [
    "X-Forwarded-Host",
    "X-Host",
    "X-Forwarded-Server",
    "X-Original-URL",
    "X-Rewrite-URL",
    "X-Forwarded-Scheme",
]

_CACHE_INDICATORS = {
    "X-Cache", "CF-Cache-Status", "X-Cache-Hit", "X-Varnish",
    "Age", "Via", "X-Drupal-Cache", "X-Proxy-Cache",
}

_PROBE_VALUE = "evil-raptor-probe.example.com"


def _is_cached(headers: dict) -> bool:
    for indicator in _CACHE_INDICATORS:
        val = headers.get(indicator, "")
        if val:
            return True
    return False


@registry.register(CheckCategory.INJECTION, "V5.1.12", "Web cache poisoning via unkeyed headers")
class CachePoisoningCheck(Check):
    def run(self, client, target_url, session=None, discovery=None):
        # First check if there is a cache at all
        try:
            baseline = client.get("/")
        except Exception:
            return []

        if not _is_cached(baseline.headers):
            return []

        findings = []

        for header in _UNKEYED_HEADERS:
            try:
                resp = client.get("/", headers={header: _PROBE_VALUE})
                body = resp.text if isinstance(resp.text, str) else ""

                if _PROBE_VALUE in body:
                    # Is the response still cached?
                    cache_status = resp.headers.get("X-Cache", "") or resp.headers.get("CF-Cache-Status", "")
                    findings.append(self._result(
                        passed=False, url=target_url,
                        evidence=(
                            f"{header}: {_PROBE_VALUE} "
                            f"reflected in cached response "
                            f"(cache status: {cache_status!r})"
                        ),
                        detail=(
                            f"The '{header}' header value is reflected in the application "
                            f"response and the response appears to be served from a cache. "
                            f"If this header is unkeyed (not part of the cache key), an attacker "
                            f"can poison the cache to deliver a malicious response to every user "
                            f"who subsequently requests this URL -- enabling stored XSS at scale, "
                            f"credential theft, or session fixation for all visitors."
                        ),
                        recommendation=(
                            "Add all headers that influence the response to the cache key. "
                            "Configure the CDN/reverse proxy to normalise or strip unrecognised "
                            "headers before they reach the application. "
                            "Validate the Host header against an allowlist."
                        ),
                        severity="critical", asvs_ref="ASVS 5.0 V5.1.12",
                    ))
                    break

            except Exception:
                continue

        return findings


@registry.register(CheckCategory.INJECTION, "V5.1.13", "Web cache deception risk")
class CacheDeceptionCheck(Check):
    def run(self, client, target_url, session=None, discovery=None):
        if not session or not session.authenticated:
            return []

        # Look for profile/account pages in discovery
        sensitive_paths = ["/account", "/profile", "/settings", "/dashboard", "/me"]
        if discovery:
            for url in discovery.get("urls", []):
                from urllib.parse import urlparse
                path = urlparse(url).path.lower()
                if any(k in path for k in ("account", "profile", "settings", "dashboard")):
                    sensitive_paths.insert(0, urlparse(url).path)

        for path in sensitive_paths[:3]:
            try:
                # Try appending a static-file suffix to a sensitive path
                deception_path = path.rstrip("/") + "/nonexistent.css"
                resp = client.get(deception_path)

                if resp.status_code == 200:
                    # Check if the response contains profile/account data
                    body = resp.text if isinstance(resp.text, str) else ""
                    has_user_data = any(
                        kw in body.lower()
                        for kw in ("email", "username", "account", "profile", "address")
                    )

                    if has_user_data and _is_cached(resp.headers):
                        return [self._result(
                            passed=False, url=target_url.rstrip("/") + deception_path,
                            evidence=(
                                f"GET {deception_path} returned HTTP 200 with apparent user data "
                                f"and cache indicators present"
                            ),
                            detail=(
                                f"The application returns authenticated account data for '{path}' "
                                f"even when a static-file suffix is appended ({deception_path}). "
                                f"If the caching layer matches on file extension and caches this "
                                f"response, unauthenticated users can access cached copies of "
                                f"other users' account pages simply by requesting the same URL "
                                f"after the victim visited it."
                            ),
                            recommendation=(
                                "Configure the application to return 404 for paths it doesn't "
                                "recognise rather than falling back to a parent route. "
                                "Ensure the CDN never caches responses that contain "
                                "Cache-Control: private or that require authentication."
                            ),
                            severity="high", asvs_ref="ASVS 5.0 V5.1.13",
                        )]
            except Exception:
                continue

        return []


@registry.register(CheckCategory.INJECTION, "V5.1.14", "HTTP request smuggling probe (CL.TE)")
class RequestSmugglingCheck(Check):
    def run(self, client, target_url, session=None, discovery=None):
        import socket
        import ssl
        import time
        from urllib.parse import urlparse

        parsed = urlparse(target_url)
        host = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        use_tls = parsed.scheme == "https"

        # Send a CL.TE probe: Content-Length says 6 bytes, Transfer-Encoding says chunked.
        # The front-end uses CL (forwards 6 bytes of body), back-end uses TE (reads "0\r\n\r\n"
        # as empty chunk, then "X" as start of next request). A 5-second timeout differential
        # on the second innocent request confirms the smuggle.
        smuggle_request = (
            f"POST / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: 6\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"Connection: close\r\n"
            f"\r\n"
            f"0\r\n"
            f"\r\n"
            f"X"
        )

        try:
            sock = socket.create_connection((host, port), timeout=5)
            if use_tls:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=host)

            sock.sendall(smuggle_request.encode())
            t_start = time.monotonic()
            data = b""
            try:
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    data += chunk
            except Exception:
                pass
            duration = time.monotonic() - t_start
            sock.close()

            response = data.decode("utf-8", errors="replace")

            # A 400 Bad Request with "Invalid request" is a common sign the back-end
            # received our smuggled prefix -- not definitive but warrants manual follow-up
            if "400" in response and duration < 1:
                return [self._result(
                    passed=False, url=target_url,
                    evidence=(
                        f"CL.TE probe: server returned 400 in {duration:.2f}s -- "
                        f"possible back-end desync. Manual verification required."
                    ),
                    detail=(
                        "The server appears to process both Content-Length and Transfer-Encoding "
                        "headers simultaneously on the same request. This is the prerequisite for "
                        "HTTP request smuggling (CL.TE variant). A successful smuggling attack "
                        "allows bypassing front-end security controls, poisoning other users' "
                        "requests, and stealing credentials from other sessions. "
                        "Manual verification with Burp Suite HTTP Request Smuggler is strongly recommended."
                    ),
                    recommendation=(
                        "Configure the front-end proxy to normalise Transfer-Encoding headers "
                        "and reject requests with both Content-Length and Transfer-Encoding. "
                        "Use HTTP/2 end-to-end where possible. "
                        "Apply the same header handling rules on every hop in the proxy chain."
                    ),
                    severity="high", confidence="low", asvs_ref="ASVS 5.0 V5.1.14",
                )]

        except Exception:
            pass

        return []
