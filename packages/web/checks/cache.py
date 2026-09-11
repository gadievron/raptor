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
from typing import TYPE_CHECKING

from packages.web.checks.base import PROBE_HOST, Check, CheckCategory, registry

if TYPE_CHECKING:
    pass

_UNKEYED_HEADERS = [
    "X-Forwarded-Host",
    "X-Host",
    "X-Forwarded-Server",
    "X-Original-URL",
    "X-Rewrite-URL",
    "X-Forwarded-Scheme",
]

# Headers that indicate a CACHE served or recorded the response.
# 'Via' is deliberately absent: it only marks a proxy hop (RFC 9110),
# so treating it as cache evidence flagged every proxied deployment.
_CACHE_INDICATORS = {
    "X-Cache", "CF-Cache-Status", "X-Cache-Hit", "X-Varnish",
    "Age", "X-Drupal-Cache", "X-Proxy-Cache",
}

_PROBE_VALUE = PROBE_HOST


def _is_cached(headers: dict) -> bool:
    for indicator in _CACHE_INDICATORS:
        val = headers.get(indicator, "")
        if val:
            return True
    return False


@registry.register(CheckCategory.INJECTION, "V5.1.12", "Web cache poisoning via unkeyed headers")
class CachePoisoningCheck(Check):
    risk = "active"
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
    risk = "active"
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

        # Catch-all calibration: if a static-file suffix under a path
        # that cannot be sensitive also answers 200, the target routes
        # every unknown path to the same handler (SPA shell) — a 200 on
        # /account/nonexistent.css then proves nothing about deception.
        import secrets
        control_status: int | None = None
        control_length: int | None = None
        try:
            control = client.get(
                f"/raptor-{secrets.token_hex(8)}/nonexistent.css",
            )
            control_status = control.status_code
            control_length = len(control.content or b"")
        except Exception:
            pass

        def _matches_control(resp) -> bool:
            if control_status is None or resp.status_code != control_status:
                return False
            if control_length is None:
                return True
            length = len(resp.content or b"")
            bigger = max(length, control_length) or 1
            return abs(length - control_length) / bigger <= 0.1

        for path in sensitive_paths[:3]:
            try:
                # Try appending a static-file suffix to a sensitive path
                deception_path = path.rstrip("/") + "/nonexistent.css"
                resp = client.get(deception_path)

                if resp.status_code == 200 and not _matches_control(resp):
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
    risk = "active"

    # Desync-prerequisite probes, one per parser-disagreement class.
    # Each is a heuristic ("both framing headers processed" /
    # "body interpreted as a second request"), never a confirmed
    # verdict — findings stay confidence=low with a manual-follow-up
    # instruction, matching the original CL.TE behavior.
    @staticmethod
    def _probe_requests(host: str) -> list[tuple[str, str, str]]:
        clte = (
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
        # Front-end honors Transfer-Encoding (reads the full chunked
        # body); a CL back-end stops after 3 bytes and parses the rest
        # as the start of a new request.
        tecl = (
            f"POST / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: 3\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"Connection: close\r\n"
            f"\r\n"
            f"8\r\n"
            f"SMUGGLED\r\n"
            f"0\r\n"
            f"\r\n"
        )
        # A CL.0 back-end ignores Content-Length entirely: the body
        # arrives as a SECOND request on the same connection, so two
        # responses come back for one send.
        prefix = (
            f"GET /raptor-clzero-probe HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"\r\n"
        )
        clzero = (
            f"POST / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: {len(prefix)}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
            f"{prefix}"
        )
        return [
            ("CL.TE", clte, "stalled_no_response"),
            ("TE.CL", tecl, "stalled_no_response"),
            ("CL.0", clzero, "double_response"),
        ]

    # Response STATUS lines only: anchored at line start with a status
    # code, so an error page quoting the request line ("GET /x HTTP/1.1")
    # or a header/body containing the digits (Content-Length: 2400)
    # never counts.
    _STATUS_LINE_RE = re.compile(r"(?m)^HTTP/1\.[01] (\d{3})")

    # A read that ran into the socket timeout with no parseable status
    # line means the server sat on the ambiguous framing waiting for
    # more body — the classic desync prerequisite. Anything answered
    # promptly (including the RFC-recommended immediate 400 rejection
    # of requests carrying both Content-Length and Transfer-Encoding)
    # is NOT evidence.
    _STALL_SECONDS = 4.0

    def run(self, client, target_url, session=None, discovery=None):
        from urllib.parse import urlparse

        parsed = urlparse(target_url)
        host = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        use_tls = parsed.scheme == "https"

        from packages.web.checks.base import note_transport_error

        for variant, request_text, signal in self._probe_requests(host):
            response, duration = self._raw_exchange(
                host, port, use_tls, request_text,
            )
            if response is None:
                # Raw-socket probes bypass WebClient's counter; a failed
                # exchange is still transport degradation, not a clean run.
                note_transport_error(client)
                continue
            status_lines = self._STATUS_LINE_RE.findall(response)
            if signal == "stalled_no_response":
                hit = duration >= self._STALL_SECONDS and not status_lines
            else:  # double_response
                hit = len(status_lines) >= 2
            if not hit:
                continue
            return [self._result(
                passed=False, url=target_url,
                evidence=(
                    f"{variant} probe: "
                    + (
                        f"server produced no response for {duration:.2f}s -- "
                        "it appears to be waiting for more body under the "
                        "ambiguous framing (possible back-end desync)."
                        if signal == "stalled_no_response" else
                        "two HTTP responses returned for one request -- "
                        "the body was parsed as a second request."
                    )
                    + " Manual verification required."
                ),
                detail=(
                    f"The server's framing behavior is consistent with the "
                    f"{variant} HTTP request smuggling prerequisite: the "
                    "front-end and back-end disagree about where one "
                    "request ends and the next begins. A successful "
                    "smuggling attack allows bypassing front-end security "
                    "controls, poisoning other users' requests, and "
                    "stealing credentials from other sessions. Manual "
                    "verification with Burp Suite HTTP Request Smuggler "
                    "is strongly recommended."
                ),
                recommendation=(
                    "Configure the front-end proxy to normalise "
                    "Transfer-Encoding headers and reject requests with "
                    "both Content-Length and Transfer-Encoding. "
                    "Use HTTP/2 end-to-end where possible. "
                    "Apply the same header handling rules on every hop "
                    "in the proxy chain."
                ),
                severity="high", confidence="low",
                asvs_ref="ASVS 5.0 V5.1.14",
            )]

        return []

    @staticmethod
    def _raw_exchange(
        host: str, port: int, use_tls: bool, request_text: str,
    ) -> tuple:
        """One raw request/response exchange; (None, 0.0) on error."""
        import socket
        import time

        from packages.web._probe_tls import probe_tls_context

        try:
            sock = socket.create_connection((host, port), timeout=5)
            if use_tls:
                # Scanner semantics, not client semantics — see
                # packages/web/_probe_tls.py for why validation is off
                # and the version floor is pinned.
                ctx = probe_tls_context()
                sock = ctx.wrap_socket(sock, server_hostname=host)

            sock.sendall(request_text.encode())
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
            return data.decode("utf-8", errors="replace"), duration
        except Exception:
            return None, 0.0
