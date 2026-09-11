"""SSRF detection -- ASVS V10.3 / Kettle methodology.

Server-Side Request Forgery allows attackers to make the server issue
outbound HTTP requests to attacker-controlled or internal targets.
Checks for URL parameters, fetch-by-URL functionality, and blind SSRF
indicators in common headers. All probes use safe internal targets
(localhost, 127.0.0.1) rather than external infrastructure.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING
from urllib.parse import parse_qs, parse_qsl, urlencode, urlparse, urlunparse

from packages.web.checks.base import Check, CheckCategory, registry

if TYPE_CHECKING:
    pass


def _baseline_body(client) -> str:
    """The homepage body, used to subtract always-present indicator text.

    The generic transport-error indicators (Connection refused, ...)
    appear verbatim on diagnostics pages and error-verbose apps; a
    pattern that already matches WITHOUT any probe is page furniture,
    not evidence that the probe caused an outbound request.
    """
    try:
        resp = client.get("/")
        body = resp.text
        return body if isinstance(body, str) else ""
    except Exception:
        return ""


def _active_indicators(baseline_body: str) -> list[re.Pattern]:
    return [
        pattern for pattern in _SSRF_INDICATORS
        if not pattern.search(baseline_body)
    ]


def _url_with_param(url: str, param: str, value: str) -> str:
    """*url* with ``param`` replaced (not duplicated) in its query."""
    parsed = urlparse(url)
    query = [
        (name, existing)
        for name, existing in parse_qsl(parsed.query, keep_blank_values=True)
        if name != param
    ]
    query.append((param, value))
    return urlunparse(parsed._replace(query=urlencode(query)))

# Parameter names commonly used to pass URLs into the server
_URL_PARAM_NAMES = {
    "url", "uri", "link", "src", "source", "dest", "destination",
    "redirect", "redirect_url", "return", "return_url", "returnurl",
    "next", "target", "endpoint", "webhook", "callback", "proxy",
    "fetch", "load", "img", "image", "icon", "feed", "file",
    "path", "document", "preview", "data", "ref",
}

# SSRF probe payloads -- internal targets
_SSRF_PAYLOADS = [
    "http://127.0.0.1/",
    "http://localhost/",
    "http://169.254.169.254/latest/meta-data/",  # AWS metadata
    "http://metadata.google.internal/",
]

# Signals in a response that indicate the server made an outbound request
_SSRF_INDICATORS = [
    re.compile(r"ami-[0-9a-f]{8,17}", re.I),    # AWS AMI ID
    re.compile(r'"instanceId"\s*:', re.I),
    re.compile(r"computeMetadata", re.I),
    re.compile(r"local-ipv4|public-ipv4", re.I),
    re.compile(r"Connection refused", re.I),
    re.compile(r"Failed to connect|ECONNREFUSED", re.I),
]


@registry.register(CheckCategory.INJECTION, "V10.3.1", "SSRF via URL parameter")
class SsrfParameterCheck(Check):
    risk = "active"
    def run(self, client, target_url, session=None, discovery=None):
        findings = []
        tested: set = set()

        # Probe each URL-shaped parameter AT THE URL WHERE IT WAS
        # DISCOVERED: a real /proxy?url= handler ignores the parameter
        # when it arrives on '/', so probing the root misses every
        # non-root SSRF. Parameters known only by name fall back to '/'.
        params_to_test: list[tuple[str, str]] = []
        if discovery:
            for url in discovery.get("urls", []):
                parsed = urlparse(url)
                for param in parse_qs(parsed.query):
                    if param.lower() in _URL_PARAM_NAMES:
                        params_to_test.append((param, url))
            for param in discovery.get("parameters", []):
                if param.lower() in _URL_PARAM_NAMES:
                    params_to_test.append((param, "/"))

        baseline = _baseline_body(client)
        indicators = _active_indicators(baseline)

        for param, source_url in params_to_test[:10]:
            if param in tested:
                continue
            tested.add(param)

            for payload in _SSRF_PAYLOADS[:2]:
                try:
                    resp = client.get(_url_with_param(source_url, param, payload))
                    body = resp.text if isinstance(resp.text, str) else ""
                    for pattern in indicators:
                        if pattern.search(body):
                            findings.append(self._result(
                                passed=False, url=source_url if source_url != "/" else target_url,
                                evidence=(
                                    f"?{param}={payload} triggered SSRF indicator: "
                                    f"{pattern.pattern[:50]}"
                                ),
                                detail=(
                                    f"Parameter '{param}' appears to accept a URL and the server "
                                    f"may be making outbound requests to the supplied destination. "
                                    f"SSRF allows attackers to reach internal services, cloud "
                                    f"metadata endpoints, and network segments inaccessible from "
                                    f"the internet."
                                ),
                                recommendation=(
                                    "Validate and allowlist permitted URL schemes and destinations. "
                                    "Use an egress proxy that restricts outbound targets. "
                                    "Never use user-supplied URLs for server-side fetch operations "
                                    "without strict validation."
                                ),
                                severity="critical", asvs_ref="ASVS 5.0 V10.3.1",
                            ))
                            break
                except Exception:
                    continue

        return findings


@registry.register(CheckCategory.INJECTION, "V10.3.2", "Blind SSRF via common headers")
class BlindSsrfHeaderCheck(Check):
    risk = "active"
    def run(self, client, target_url, session=None, discovery=None):
        # Probe headers that some applications use for outbound requests
        # We look for timing differences or error messages as confirmation
        ssrf_headers = {
            "X-Forwarded-For": "169.254.169.254",
            "Client-IP": "169.254.169.254",
            "True-Client-IP": "169.254.169.254",
            "X-Real-IP": "169.254.169.254",
        }

        # Subtract indicator text that is already on the un-probed page:
        # a diagnostics page mentioning "Connection refused" would
        # otherwise flag every header.
        baseline = _baseline_body(client)
        indicators = _active_indicators(baseline)

        for header, value in ssrf_headers.items():
            try:
                resp = client.get("/", headers={header: value})
                body = resp.text if isinstance(resp.text, str) else ""
                # Look for metadata indicators -- only flag if we see actual evidence
                for pattern in indicators:
                    if pattern.search(body):
                        return [self._result(
                            passed=False, url=target_url,
                            evidence=f"{header}: {value} -> SSRF indicator in response",
                            detail=(
                                f"The application appears to use the '{header}' header value "
                                f"in an outbound request. This could allow SSRF via crafted "
                                f"IP values passed in commonly-trusted proxy headers."
                            ),
                            recommendation=(
                                "Do not use IP address headers from untrusted sources for "
                                "outbound request routing. Validate all outbound request targets."
                            ),
                            severity="high", asvs_ref="ASVS 5.0 V10.3.2",
                        )]
            except Exception:
                continue

        # Callback-verified leg: headers some backends DEREFERENCE
        # (device-profile fetchers, callback registrations, unfurlers)
        # take a full canary URL. A server-side fetch produces an
        # exact-token callback; Phase 6o replays with a fresh token
        # before anything is confirmed. Injection only — no conclusion
        # is drawn here, and without a listener this leg is silent.
        if self.oob_mint is not None:
            from packages.web.oob import OobContext
            for header in ("Referer", "X-Wap-Profile", "X-Callback-Url"):
                try:
                    canary = self.oob_mint(OobContext(
                        url=target_url,
                        param=header,
                        kind="ssrf_header",
                    ))
                    if canary:
                        client.get("/", headers={header: canary})
                except Exception:
                    continue

        return []
