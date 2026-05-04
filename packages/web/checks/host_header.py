"""Host header injection checks -- ASVS V5.1 / Kettle methodology.

Tests whether the application uses the Host header (or common override
headers) in ways that allow an attacker to control server-side behaviour:
password reset link generation, cache poisoning, routing, and outbound SSRF.
"""

from __future__ import annotations

import re
from typing import List, TYPE_CHECKING

from packages.web.checks.base import Check, CheckCategory, CheckResult, registry

if TYPE_CHECKING:
    from packages.web.client import WebClient
    from packages.web.auth import AuthSession

_ATTACKER_HOST = "evil-raptor-probe.example.com"
_OVERRIDE_HEADERS = [
    "X-Forwarded-Host",
    "X-Host",
    "X-Forwarded-Server",
    "X-HTTP-Host-Override",
    "Forwarded",
]


@registry.register(CheckCategory.INJECTION, "V5.1.10", "Host header reflected in response body")
class HostHeaderInjectionCheck(Check):
    def run(self, client, target_url, session=None, discovery=None):
        findings = []

        # Probe each override header
        for header_name in _OVERRIDE_HEADERS:
            try:
                resp = client.get(
                    "/",
                    headers={header_name: _ATTACKER_HOST},
                )
                body = resp.text
                if isinstance(body, str) and _ATTACKER_HOST in body:
                    findings.append(self._result(
                        passed=False, url=target_url,
                        evidence=(
                            f"{header_name}: {_ATTACKER_HOST} "
                            f"-> attacker host reflected in response body"
                        ),
                        detail=(
                            f"The application reflects the value of the '{header_name}' header "
                            f"into the response body. If this value is used to generate URLs "
                            f"(e.g. password reset links, canonical URLs for caching), an attacker "
                            f"who can manipulate this header can redirect victims to an "
                            f"attacker-controlled domain."
                        ),
                        recommendation=(
                            "Validate the Host header against an allowlist of known good values. "
                            "Never use the Host header directly to generate URLs -- use a "
                            "configured base URL from application settings."
                        ),
                        severity="high", asvs_ref="ASVS 5.0 V5.1.10",
                    ))
                    break

                # Also check Location header on redirects
                if resp.status_code in (301, 302, 307, 308):
                    location = resp.headers.get("Location", "")
                    if _ATTACKER_HOST in location:
                        findings.append(self._result(
                            passed=False, url=target_url,
                            evidence=f"{header_name}: {_ATTACKER_HOST} -> Location: {location}",
                            detail=(
                                f"The redirect Location header reflects the attacker-supplied "
                                f"'{header_name}' value. This allows open redirect attacks and "
                                f"password reset link poisoning."
                            ),
                            recommendation=(
                                "Validate and allowlist all host values used in redirect URLs."
                            ),
                            severity="high", asvs_ref="ASVS 5.0 V5.1.10",
                        ))
                        break
            except Exception:
                continue

        return findings


@registry.register(CheckCategory.INJECTION, "V5.1.11", "Password reset link susceptible to host header poisoning")
class PasswordResetPoisoningCheck(Check):
    def run(self, client, target_url, session=None, discovery=None):
        # Find a password reset / forgot-password endpoint
        candidates = [
            "/forgot-password", "/forgot_password", "/reset-password",
            "/password/reset", "/account/forgot", "/auth/forgot",
            "/api/forgot-password", "/users/password/new",
        ]
        if discovery:
            for url in discovery.get("urls", []):
                from urllib.parse import urlparse
                path = urlparse(url).path.lower()
                if any(k in path for k in ("forgot", "reset-pass", "password/reset")):
                    candidates.insert(0, urlparse(url).path)

        for path in candidates[:5]:
            try:
                # Just check if the page exists and then probe with Host override
                get_resp = client.get(path)
                if get_resp.status_code not in (200, 302):
                    continue

                # Probe the page fetch with a poisoned host
                resp = client.get(path, headers={"X-Forwarded-Host": _ATTACKER_HOST})
                body = resp.text if isinstance(resp.text, str) else ""

                if _ATTACKER_HOST in body:
                    return [self._result(
                        passed=False, url=target_url.rstrip("/") + path,
                        evidence=(
                            f"GET {path} with X-Forwarded-Host: {_ATTACKER_HOST} "
                            f"reflects attacker host in body"
                        ),
                        detail=(
                            "The password reset page reflects the X-Forwarded-Host header "
                            "in its response. If this value is used to construct the reset "
                            "link sent by email, an attacker who can set this header "
                            "(e.g. via a misconfigured reverse proxy) can steal reset tokens "
                            "by directing them to an attacker-controlled server."
                        ),
                        recommendation=(
                            "Generate password reset URLs from a hard-coded base URL in "
                            "application configuration. Never derive the reset link domain "
                            "from any request header."
                        ),
                        severity="high", asvs_ref="ASVS 5.0 V5.1.11",
                    )]
            except Exception:
                continue
        return []
