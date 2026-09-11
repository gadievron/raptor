"""Host header injection checks -- ASVS V5.1 / Kettle methodology.

Tests whether the application uses the Host header (or common override
headers) in ways that allow an attacker to control server-side behaviour:
password reset link generation, cache poisoning, routing, and outbound SSRF.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from packages.web.checks.base import PROBE_HOST, Check, CheckCategory, registry

if TYPE_CHECKING:
    pass

_ATTACKER_HOST = PROBE_HOST
_OVERRIDE_HEADERS = [
    "X-Forwarded-Host",
    "X-Host",
    "X-Forwarded-Server",
    "X-HTTP-Host-Override",
    "Forwarded",
]


@registry.register(CheckCategory.INJECTION, "V5.1.10", "Host header reflected in response body")
class HostHeaderInjectionCheck(Check):
    risk = "active"
    def run(self, client, target_url, session=None, discovery=None):
        findings = []

        # Probe each override header. Redirects are OBSERVED, not
        # followed: with internal following, a Location reflecting the
        # probe host is out-of-scope and raises inside the client, so
        # the redirect-poisoning leg below could never fire.
        for header_name in _OVERRIDE_HEADERS:
            try:
                resp = client.get(
                    "/",
                    headers={header_name: _ATTACKER_HOST},
                    allow_redirects=False,
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

        # Bare-host out-of-band leg: no token can ride a host value, so
        # a probe with the LISTENER's host opens a windowed any-path
        # expectation instead — an inbound request within the window is
        # CORROBORATION Phase 6o reports at needs_review, never
        # confirmation (that ambiguity is why the exact-token tier
        # exists). Silent without a listener.
        if self.oob_host and self.oob_expect:
            from packages.web.oob import OobContext
            probed = list(_OVERRIDE_HEADERS[:2])
            try:
                # ONE expectation for all probed headers: an inbound
                # hit carries no token, so attributing it to a single
                # header would claim more than the evidence supports.
                self.oob_expect(OobContext(
                    url=target_url,
                    param="/".join(probed),
                    kind="host_header",
                    extra={"injected": self.oob_host},
                ))
                for header_name in probed:
                    client.get(
                        "/", headers={header_name: self.oob_host},
                    )
            except Exception:
                pass

        return findings


@registry.register(CheckCategory.INJECTION, "V5.1.11", "Password reset link susceptible to host header poisoning")
class PasswordResetPoisoningCheck(Check):
    risk = "intrusive"
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

                # Bare-host out-of-band leg: the reset link's path is
                # built by the APPLICATION, so no token can ride —
                # open a windowed expectation scoped to reset-shaped
                # paths and re-probe with the listener's host. An
                # in-window hit (the mail pipeline, a link scanner, or
                # the app itself dereferencing the poisoned link) is
                # corroboration Phase 6o reports at needs_review,
                # never confirmation. Same intrusive tier as the rest
                # of this check — the probe may trigger a real reset
                # email.
                if self.oob_host and self.oob_expect:
                    from packages.web.oob import OobContext
                    if not getattr(self, "_reset_expectation_open", False):
                        # One expectation per check run — hits carry
                        # no token, so per-candidate registrations
                        # would multiply findings from a single
                        # unattributable inbound request.
                        self._reset_expectation_open = True
                        self.oob_expect(
                            OobContext(
                                url=target_url.rstrip("/") + path,
                                param="X-Forwarded-Host",
                                kind="reset_poisoning",
                                extra={"injected": self.oob_host},
                            ),
                            path_marker="reset",
                        )
                    client.get(
                        path,
                        headers={"X-Forwarded-Host": self.oob_host},
                    )
            except Exception:
                continue
        return []
