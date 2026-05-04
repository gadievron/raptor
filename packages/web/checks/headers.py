"""ASVS V14.4 -- HTTP Security Response Headers."""

from __future__ import annotations

import re
from typing import List, Optional, TYPE_CHECKING

from packages.web.checks.base import Check, CheckCategory, CheckResult, registry

if TYPE_CHECKING:
    from packages.web.client import WebClient
    from packages.web.auth import AuthSession


@registry.register(CheckCategory.HEADERS, "V14.4.1", "Content-Security-Policy missing or unsafe")
class CspCheck(Check):
    def run(self, client, target_url, session=None, discovery=None):
        try:
            resp = client.get("/")
        except Exception:
            return []

        csp = resp.headers.get("Content-Security-Policy", "")
        if not csp:
            return [self._result(
                passed=False, url=target_url,
                evidence="Content-Security-Policy header absent",
                detail=(
                    "No Content-Security-Policy header was returned. Without CSP, the browser "
                    "applies no restrictions on script sources, making XSS exploitation significantly "
                    "easier and enabling data exfiltration via inline scripts or injected iframes."
                ),
                recommendation=(
                    "Deploy a restrictive Content-Security-Policy. At minimum: "
                    "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'. "
                    "Use nonces for inline scripts rather than 'unsafe-inline'."
                ),
                severity="high", asvs_ref="ASVS 5.0 V14.4.1",
            )]

        issues = []
        if "unsafe-inline" in csp and "nonce-" not in csp and "hash-" not in csp:
            issues.append("'unsafe-inline' in script-src without nonce/hash")
        if "unsafe-eval" in csp:
            issues.append("'unsafe-eval' in script-src")
        if re.search(r"script-src[^;]*\*", csp):
            issues.append("wildcard (*) in script-src")

        if issues:
            return [self._result(
                passed=False, url=target_url,
                evidence=f"Content-Security-Policy: {csp[:300]}",
                detail=f"CSP is present but contains unsafe directives: {'; '.join(issues)}.",
                recommendation=(
                    "Remove 'unsafe-inline' and 'unsafe-eval'. Replace with script nonces "
                    "(nonce-{random} per response). Restrict script-src to known origins."
                ),
                severity="medium", asvs_ref="ASVS 5.0 V14.4.1",
            )]
        return []


@registry.register(CheckCategory.HEADERS, "V14.4.3", "X-Content-Type-Options not set to nosniff")
class XContentTypeOptionsCheck(Check):
    def run(self, client, target_url, session=None, discovery=None):
        try:
            resp = client.get("/")
        except Exception:
            return []

        header = resp.headers.get("X-Content-Type-Options", "")
        if header.lower().strip() == "nosniff":
            return []

        evidence = f"X-Content-Type-Options: {header!r}" if header else "header absent"
        return [self._result(
            passed=False, url=target_url, evidence=evidence,
            detail=(
                "X-Content-Type-Options: nosniff is not set. Browsers may MIME-sniff "
                "responses and execute content as a different type than declared "
                "(e.g. executing a JSONP callback as script)."
            ),
            recommendation="Add 'X-Content-Type-Options: nosniff' to all HTTP responses.",
            severity="low", asvs_ref="ASVS 5.0 V14.4.3",
        )]


@registry.register(CheckCategory.HEADERS, "V14.4.4", "Clickjacking protection missing")
class ClickjackingCheck(Check):
    def run(self, client, target_url, session=None, discovery=None):
        try:
            resp = client.get("/")
        except Exception:
            return []

        xfo = resp.headers.get("X-Frame-Options", "")
        csp = resp.headers.get("Content-Security-Policy", "")

        has_xfo = xfo.upper() in ("DENY", "SAMEORIGIN")
        has_csp_frame = "frame-ancestors" in csp.lower()

        if has_xfo or has_csp_frame:
            return []

        evidence_parts = []
        if xfo:
            evidence_parts.append(f"X-Frame-Options: {xfo!r}")
        else:
            evidence_parts.append("X-Frame-Options: absent")
        if not has_csp_frame:
            evidence_parts.append("CSP frame-ancestors: not set")

        return [self._result(
            passed=False, url=target_url,
            evidence="; ".join(evidence_parts),
            detail=(
                "No clickjacking protection is present. The application can be embedded in an "
                "attacker-controlled iframe, enabling UI redressing attacks that trick users into "
                "performing unintended actions (e.g. approving transactions, changing settings)."
            ),
            recommendation=(
                "Add 'X-Frame-Options: DENY' or, preferably, include 'frame-ancestors 'none'' "
                "(or 'self' if embedding is needed) in the Content-Security-Policy header. "
                "CSP frame-ancestors takes precedence over X-Frame-Options in modern browsers."
            ),
            severity="medium", asvs_ref="ASVS 5.0 V14.4.4",
        )]


@registry.register(CheckCategory.HEADERS, "V14.4.5", "HSTS not configured")
class HstsCheck(Check):
    def run(self, client, target_url, session=None, discovery=None):
        from urllib.parse import urlparse
        if urlparse(target_url).scheme != "https":
            return []
        try:
            resp = client.get("/")
        except Exception:
            return []

        hsts = resp.headers.get("Strict-Transport-Security", "")
        if not hsts:
            return [self._result(
                passed=False, url=target_url,
                evidence="Strict-Transport-Security: absent",
                detail=(
                    "HTTP Strict-Transport-Security (HSTS) is not set. Without HSTS, users who "
                    "type the site URL without 'https://' may be silently downgraded to HTTP by "
                    "a network attacker (SSL stripping). HSTS instructs browsers to always connect "
                    "over HTTPS after the first visit."
                ),
                recommendation=(
                    "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' to all "
                    "HTTPS responses. Consider adding 'preload' after confirming all subdomains "
                    "support HTTPS, and submit to the HSTS preload list."
                ),
                severity="medium", asvs_ref="ASVS 5.0 V14.4.5",
            )]

        # Check max-age is meaningful (at least 1 year)
        m = re.search(r"max-age\s*=\s*(\d+)", hsts, re.I)
        if m:
            max_age = int(m.group(1))
            if max_age < 31536000:
                return [self._result(
                    passed=False, url=target_url,
                    evidence=f"Strict-Transport-Security: {hsts}",
                    detail=f"HSTS max-age is {max_age}s (< 1 year). Short max-age values reduce protection.",
                    recommendation="Set max-age to at least 31536000 (1 year).",
                    severity="low", asvs_ref="ASVS 5.0 V14.4.5",
                )]
        return []


@registry.register(CheckCategory.HEADERS, "V14.4.6", "Referrer-Policy not set")
class ReferrerPolicyCheck(Check):
    def run(self, client, target_url, session=None, discovery=None):
        try:
            resp = client.get("/")
        except Exception:
            return []

        policy = resp.headers.get("Referrer-Policy", "")
        safe_policies = {
            "no-referrer", "no-referrer-when-downgrade",
            "same-origin", "strict-origin",
            "strict-origin-when-cross-origin",
        }
        if policy.lower().strip() in safe_policies:
            return []

        evidence = f"Referrer-Policy: {policy!r}" if policy else "Referrer-Policy: absent"
        return [self._result(
            passed=False, url=target_url, evidence=evidence,
            detail=(
                "Referrer-Policy is absent or set to an unsafe value. Without a restrictive policy, "
                "the browser sends the full URL in the Referer header to third-party sites, potentially "
                "leaking authentication tokens, session IDs, or sensitive path parameters."
            ),
            recommendation=(
                "Set 'Referrer-Policy: strict-origin-when-cross-origin' or 'no-referrer'. "
                "Avoid 'unsafe-url' and 'no-referrer-when-downgrade' for apps handling sensitive data."
            ),
            severity="low", asvs_ref="ASVS 5.0 V14.4.6",
        )]


@registry.register(CheckCategory.HEADERS, "V14.4.7", "Server header discloses version")
class ServerVersionCheck(Check):
    def run(self, client, target_url, session=None, discovery=None):
        try:
            resp = client.get("/")
        except Exception:
            return []

        server = resp.headers.get("Server", "")
        powered = resp.headers.get("X-Powered-By", "")

        findings = []
        version_re = re.compile(r"\d+\.\d+")

        if server and version_re.search(server):
            findings.append(self._result(
                passed=False, url=target_url,
                evidence=f"Server: {server}",
                detail=(
                    f"The Server header discloses version information: '{server}'. "
                    "This helps attackers identify known CVEs for the specific version."
                ),
                recommendation=(
                    "Configure the web server to suppress or genericise the Server header. "
                    "For nginx: 'server_tokens off;'. For Apache: 'ServerTokens Prod; ServerSignature Off'."
                ),
                severity="informational", asvs_ref="ASVS 5.0 V14.4.7",
            ))

        if powered:
            findings.append(self._result(
                passed=False, url=target_url,
                evidence=f"X-Powered-By: {powered}",
                detail=(
                    f"X-Powered-By header discloses the application framework: '{powered}'. "
                    "This aids technology fingerprinting and targeted attacks."
                ),
                recommendation="Remove the X-Powered-By header at the framework or web server level.",
                severity="informational", asvs_ref="ASVS 5.0 V14.4.7",
            ))

        return findings


@registry.register(CheckCategory.HEADERS, "V14.4.8", "Permissions-Policy not configured")
class PermissionsPolicyCheck(Check):
    def run(self, client, target_url, session=None, discovery=None):
        try:
            resp = client.get("/")
        except Exception:
            return []

        policy = resp.headers.get("Permissions-Policy", "")
        if policy:
            return []

        return [self._result(
            passed=False, url=target_url,
            evidence="Permissions-Policy: absent",
            detail=(
                "Permissions-Policy (formerly Feature-Policy) is not set. Without it, embedded "
                "third-party content and iframes may access powerful browser APIs "
                "(camera, microphone, geolocation, payment) without explicit opt-in."
            ),
            recommendation=(
                "Add a Permissions-Policy header restricting APIs your application does not use. "
                "Example: 'Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()'"
            ),
            severity="informational", asvs_ref="ASVS 5.0 V14.4.8",
        )]
