"""OAuth 2.0 / OpenID Connect security checks -- ASVS V3.7."""

from __future__ import annotations

import re
from typing import List, TYPE_CHECKING
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from packages.web.checks.base import Check, CheckCategory, CheckResult, registry

if TYPE_CHECKING:
    from packages.web.client import WebClient
    from packages.web.auth import AuthSession

_OAUTH_PATHS = [
    "/oauth/authorize", "/oauth2/authorize", "/auth/oauth",
    "/connect/authorize", "/.well-known/openid-configuration",
    "/oauth/token", "/auth",
]


@registry.register(CheckCategory.AUTHN, "V3.7.1", "OAuth redirect_uri allows open redirect")
class OAuthOpenRedirectCheck(Check):
    def run(self, client, target_url, session=None, discovery=None):
        # Find OAuth authorization endpoints
        auth_endpoints = []
        if discovery:
            openapi = discovery.get("openapi_spec") or {}
            for path in (openapi.get("paths") or {}).keys():
                if "auth" in path.lower() or "oauth" in path.lower():
                    auth_endpoints.append(path)
            for url in discovery.get("urls", []):
                parsed = urlparse(url)
                if any(k in parsed.path.lower() for k in ("oauth", "authorize", "connect")):
                    auth_endpoints.append(parsed.path)

        auth_endpoints.extend(_OAUTH_PATHS)

        for path in auth_endpoints[:5]:
            try:
                # Probe with an external redirect_uri
                resp = client.get(
                    path,
                    params={
                        "response_type": "code",
                        "client_id": "test",
                        "redirect_uri": "https://evil-raptor-probe.example.com/callback",
                        "scope": "openid",
                        "state": "raptor_probe",
                    },
                )

                body = resp.text if isinstance(resp.text, str) else ""
                location = resp.headers.get("Location", "")

                if resp.status_code in (301, 302, 307, 308):
                    if "evil-raptor-probe.example.com" in location:
                        return [self._result(
                            passed=False, url=target_url.rstrip("/") + path,
                            evidence=f"redirect_uri=evil-raptor-probe.example.com -> Location: {location}",
                            detail=(
                                "The OAuth authorization endpoint accepted an external redirect_uri "
                                "pointing to an attacker-controlled domain. An attacker can craft "
                                "an authorization URL that, when visited by a victim, sends the "
                                "authorization code to the attacker, enabling account takeover."
                            ),
                            recommendation=(
                                "Enforce strict redirect_uri validation against a pre-registered "
                                "allowlist. Do not use prefix matching or wildcard matching. "
                                "The redirect_uri must match exactly (scheme, host, path, query)."
                            ),
                            severity="critical", asvs_ref="ASVS 5.0 V3.7.1",
                        )]
            except Exception:
                continue
        return []


@registry.register(CheckCategory.AUTHN, "V3.7.2", "OAuth authorization missing state parameter")
class OAuthMissingStateCheck(Check):
    def run(self, client, target_url, session=None, discovery=None):
        # Look for OAuth initiation flows in the HTML
        try:
            resp = client.get("/")
            body = resp.text if isinstance(resp.text, str) else ""
        except Exception:
            return []

        # Find OAuth authorize URLs in the page
        oauth_links = re.findall(
            r'href=["\']([^"\']*(?:oauth|authorize|connect)[^"\']*)["\']',
            body, re.I
        )

        for link in oauth_links[:3]:
            parsed = urlparse(link)
            params = parse_qs(parsed.query)

            if "state" not in params:
                return [self._result(
                    passed=False, url=target_url,
                    evidence=f"OAuth link without state parameter: {link[:200]}",
                    detail=(
                        "An OAuth authorization link in the page does not include a 'state' "
                        "parameter. The state parameter is the CSRF defence for OAuth flows. "
                        "Without it, an attacker can initiate an OAuth flow and trick a victim "
                        "into completing it, linking the victim's account to the attacker's "
                        "OAuth identity (account takeover via CSRF on the OAuth callback)."
                    ),
                    recommendation=(
                        "Generate a cryptographically random state value per authorization request "
                        "and validate it exactly on the callback. The state must be tied to the "
                        "user's session and unguessable."
                    ),
                    severity="high", asvs_ref="ASVS 5.0 V3.7.2",
                )]
        return []
