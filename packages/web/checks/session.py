"""ASVS V3 -- Session management checks."""

from __future__ import annotations

from typing import TYPE_CHECKING

import re

from packages.web.checks.base import Check, CheckCategory, registry

if TYPE_CHECKING:
    pass

# A folded Set-Cookie header joins cookies with ", " — but Expires
# attributes also contain ", " ("Expires=Wed, 21 Oct ..."). Split only
# at commas followed by a cookie-name token and '=': the day-name/date
# fragments after an Expires comma never look like "name=".
_FOLDED_COOKIE_SPLIT_RE = re.compile(r",\s*(?=[^;,\s=]+=)")


def _set_cookie_headers(response) -> list[str]:
    """Every Set-Cookie header of *response*, one entry per cookie.

    requests' CaseInsensitiveDict folds repeated Set-Cookie headers into
    one comma-joined string and has no get_all, so evaluating the folded
    string as a single cookie lets one well-flagged cookie mask every
    unflagged sibling. Prefer the underlying urllib3 header multidict
    (which preserves the individual headers), then fall back to
    unfolding the joined string.
    """
    raw = getattr(response, "raw", None)
    raw_headers = getattr(raw, "headers", None)
    if raw_headers is not None:
        for attr in ("get_all", "getlist"):
            getter = getattr(raw_headers, attr, None)
            if callable(getter):
                try:
                    values = getter("Set-Cookie")
                except TypeError:
                    continue
                return [str(v) for v in (values or []) if v]
    folded = ""
    headers = getattr(response, "headers", None)
    if headers is not None:
        folded = headers.get("Set-Cookie", "") or ""
    if not folded:
        return []
    return [part for part in _FOLDED_COOKIE_SPLIT_RE.split(folded) if part]


def _cookie_name(header_value: str) -> str:
    return header_value.split("=", 1)[0].strip()


def _cookie_attributes(header_value: str) -> list[str]:
    """Lowercased attribute tokens AFTER the name=value pair.

    Flag checks must inspect attributes only: substring tests over the
    whole header let a cookie NAME or value containing "secure" satisfy
    the Secure-flag check.
    """
    return [
        part.strip().lower()
        for part in header_value.split(";")[1:]
        if part.strip()
    ]


@registry.register(CheckCategory.SESSION, "V3.4.1", "Session cookie missing Secure flag")
class SecureCookieFlagCheck(Check):
    def run(self, client, target_url, session=None, discovery=None):
        from urllib.parse import urlparse
        try:
            resp = client.get("/")
        except Exception:
            return []

        findings = []
        for header_value in _set_cookie_headers(resp):
            if not header_value:
                continue
            name = _cookie_name(header_value)
            attributes = _cookie_attributes(header_value)
            if urlparse(target_url).scheme == "https" and "secure" not in attributes:
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
        for header_value in _set_cookie_headers(resp):
            name = _cookie_name(header_value)
            if "httponly" not in _cookie_attributes(header_value):
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

        findings = []
        for raw in _set_cookie_headers(resp):
            name = _cookie_name(raw)
            attributes = _cookie_attributes(raw)
            has_samesite = any(a.startswith("samesite") for a in attributes)
            none_without_secure = (
                "samesite=none" in attributes and "secure" not in attributes
            )

            if not has_samesite:
                findings.append(self._result(
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
                ))
            elif none_without_secure:
                findings.append(self._result(
                    passed=False, url=target_url,
                    evidence=f"Set-Cookie: {raw[:200]}",
                    detail=(
                        f"Cookie '{name}' has SameSite=None but is missing the Secure flag. "
                        "Browsers reject SameSite=None cookies without Secure in modern browsers, "
                        "and serving them over HTTP is a misconfiguration."
                    ),
                    recommendation="SameSite=None requires the Secure flag. Add 'Secure' to this cookie.",
                    severity="medium", asvs_ref="ASVS 5.0 V3.4.3",
                ))
        return findings


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
