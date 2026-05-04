"""ASVS V3 -- Session management checks."""

from __future__ import annotations

from typing import List, TYPE_CHECKING

from packages.web.checks.base import Check, CheckCategory, CheckResult, registry

if TYPE_CHECKING:
    from packages.web.client import WebClient
    from packages.web.auth import AuthSession


@registry.register(CheckCategory.SESSION, "V3.4.1", "Session cookie missing Secure flag")
class SecureCookieFlagCheck(Check):
    def run(self, client, target_url, session=None, discovery=None):
        from urllib.parse import urlparse
        try:
            resp = client.get("/")
        except Exception:
            return []

        findings = []
        for header_value in resp.headers.get_all("Set-Cookie") if hasattr(resp.headers, "get_all") else [resp.headers.get("Set-Cookie", "")]:
            if not header_value:
                continue
            name = header_value.split("=")[0].strip()
            if urlparse(target_url).scheme == "https" and "secure" not in header_value.lower():
                findings.append(self._result(
                    passed=False, url=target_url,
                    evidence=f"Set-Cookie: {header_value[:200]}",
                    detail=(
                        f"Cookie '{name}' is served over HTTPS but does not have the Secure flag set. "
                        "The cookie may be transmitted over HTTP if the user ever visits the HTTP version "
                        "of the site, or if an attacker forces a downgrade."
                    ),
                    recommendation=f"Add the 'Secure' attribute to the '{name}' cookie.",
                    severity="medium", asvs_ref="ASVS 5.0 V3.4.1",
                ))
        return findings


@registry.register(CheckCategory.SESSION, "V3.4.2", "Session cookie missing HttpOnly flag")
class HttpOnlyCookieFlagCheck(Check):
    def run(self, client, target_url, session=None, discovery=None):
        try:
            resp = client.get("/")
        except Exception:
            return []

        findings = []
        raw_cookies = resp.headers.get("Set-Cookie", "")
        for header_value in ([raw_cookies] if raw_cookies else []):
            name = header_value.split("=")[0].strip()
            if "httponly" not in header_value.lower():
                findings.append(self._result(
                    passed=False, url=target_url,
                    evidence=f"Set-Cookie: {header_value[:200]}",
                    detail=(
                        f"Cookie '{name}' does not have the HttpOnly flag set. "
                        "JavaScript running in the page context (e.g. via XSS) can read this cookie "
                        "and exfiltrate it to an attacker-controlled server."
                    ),
                    recommendation=f"Add the 'HttpOnly' attribute to the '{name}' cookie.",
                    severity="medium", asvs_ref="ASVS 5.0 V3.4.2",
                ))
        return findings


@registry.register(CheckCategory.SESSION, "V3.4.3", "Session cookie missing SameSite attribute")
class SameSiteCookieCheck(Check):
    def run(self, client, target_url, session=None, discovery=None):
        try:
            resp = client.get("/")
        except Exception:
            return []

        raw = resp.headers.get("Set-Cookie", "")
        if not raw:
            return []

        name = raw.split("=")[0].strip()
        has_samesite = "samesite" in raw.lower()
        none_without_secure = (
            "samesite=none" in raw.lower() and "secure" not in raw.lower()
        )

        if not has_samesite:
            return [self._result(
                passed=False, url=target_url,
                evidence=f"Set-Cookie: {raw[:200]}",
                detail=(
                    f"Cookie '{name}' has no SameSite attribute. Without SameSite, the cookie is "
                    "sent on cross-site requests, making CSRF attacks easier even on modern browsers."
                ),
                recommendation=(
                    f"Add 'SameSite=Lax' (or 'Strict' where cross-site navigation is not needed) "
                    f"to the '{name}' cookie."
                ),
                severity="medium", asvs_ref="ASVS 5.0 V3.4.3",
            )]

        if none_without_secure:
            return [self._result(
                passed=False, url=target_url,
                evidence=f"Set-Cookie: {raw[:200]}",
                detail=(
                    f"Cookie '{name}' has SameSite=None but is missing the Secure flag. "
                    "Browsers reject SameSite=None cookies without Secure in modern browsers, "
                    "and serving them over HTTP is a misconfiguration."
                ),
                recommendation="SameSite=None requires the Secure flag. Add 'Secure' to this cookie.",
                severity="medium", asvs_ref="ASVS 5.0 V3.4.3",
            )]
        return []


@registry.register(CheckCategory.SESSION, "V3.3.1", "Session fixation possible",
                   requires_auth=True)
class SessionFixationCheck(Check):
    def run(self, client, target_url, session=None, discovery=None):
        if not session or not session.session_cookie_name:
            return []

        pre = session.pre_login_cookies.get(session.session_cookie_name)
        post = session.cookies.get(session.session_cookie_name)

        if pre and post and pre == post:
            return [self._result(
                passed=False, url=target_url,
                evidence=(
                    f"Session cookie '{session.session_cookie_name}' value unchanged "
                    f"before and after authentication: {pre[:32]}..."
                ),
                detail=(
                    "The session token is not rotated upon successful authentication. An attacker "
                    "who can set a known session cookie value (e.g. via a sub-domain cookie injection "
                    "or XSS) can wait for the victim to log in and then hijack the authenticated session."
                ),
                recommendation=(
                    "Invalidate and regenerate the session token on every successful login. "
                    "Most frameworks provide session.regenerate() or equivalent."
                ),
                severity="high", asvs_ref="ASVS 5.0 V3.3.1",
            )]
        return []


@registry.register(CheckCategory.SESSION, "V3.1.1", "Session token exposed in URL")
class SessionInUrlCheck(Check):
    def run(self, client, target_url, session=None, discovery=None):
        try:
            resp = client.get("/")
        except Exception:
            return []

        from urllib.parse import urlparse, parse_qs
        url = resp.url or target_url
        query = parse_qs(urlparse(url).query)
        token_params = {"sessionid", "session_id", "sid", "token", "jsessionid",
                        "phpsessid", "asp.net_sessionid"}
        found = token_params & {k.lower() for k in query}
        if found:
            return [self._result(
                passed=False, url=url,
                evidence=f"Session token parameter(s) in URL: {', '.join(found)}",
                detail=(
                    "Session tokens appear in the URL query string. URLs are logged by proxies, "
                    "CDNs, web servers, and browser history, and sent to third parties via the "
                    "Referer header, exposing the session token to unintended parties."
                ),
                recommendation=(
                    "Store session tokens exclusively in cookies with Secure, HttpOnly, and "
                    "SameSite attributes. Never transmit them in URLs."
                ),
                severity="high", asvs_ref="ASVS 5.0 V3.1.1",
            )]
        return []
