"""Authentication managers for web scanning.

MFA note: automated MFA solving is intentionally not supported. For apps
protected by MFA, SSO, or any other interactive auth flow, use one of:
  - cookie mode: log in manually in a browser, export session cookies,
    pass via --cookies "name=value; name2=value2"
  - bearer mode: complete the auth flow yourself, pass the resulting
    JWT or opaque token via --token
"""

from __future__ import annotations

import abc
import logging
from dataclasses import dataclass, field
from typing import Dict, Optional, TYPE_CHECKING
from urllib.parse import urljoin, urlparse

if TYPE_CHECKING:
    from packages.web.client import WebClient

logger = logging.getLogger(__name__)


class AuthenticationError(Exception):
    """Raised when authentication fails."""


@dataclass
class AuthSession:
    """Snapshot of authentication state after a successful auth attempt.

    WebClient.session is mutated in-place by AuthManager.authenticate().
    This dataclass is a read-only metadata record passed to checks so they
    can inspect session behaviour (cookie flags, fixation, logout, etc.)
    without needing to know which AuthManager is active.
    """

    mode: str                               # form | bearer | cookie | basic
    username: Optional[str] = None
    token: Optional[str] = None
    cookies: Dict[str, str] = field(default_factory=dict)
    session_cookie_name: Optional[str] = None
    pre_login_cookies: Dict[str, str] = field(default_factory=dict)
    login_url: Optional[str] = None
    logout_url: Optional[str] = None
    authenticated: bool = False


class AuthManager(abc.ABC):
    @abc.abstractmethod
    def authenticate(self, client: "WebClient") -> AuthSession:
        """Mutate client.session and return populated AuthSession.

        Raises AuthenticationError on failure.
        """
        ...

    @abc.abstractmethod
    def verify(self, client: "WebClient", session: AuthSession) -> bool:
        """Return True if the session is still valid."""
        ...


class FormAuthManager(AuthManager):
    """Log in via an HTML form POST.

    Discovers the login form on login_url, submits credentials, then
    confirms authentication either by checking for a redirect away from
    the login page or by verifying a configurable success indicator.

    Does not support MFA. For MFA-protected apps, use CookieAuthManager.
    """

    def __init__(
        self,
        login_url: str,
        username: str,
        password: str,
        username_field: str = "username",
        password_field: str = "password",
        success_indicator: Optional[str] = None,
        logout_url: Optional[str] = None,
    ) -> None:
        self.login_url = login_url
        self.username = username
        self.password = password
        self.username_field = username_field
        self.password_field = password_field
        self.success_indicator = success_indicator
        self.logout_url = logout_url

    def authenticate(self, client: "WebClient") -> AuthSession:
        from bs4 import BeautifulSoup

        pre_login_cookies = dict(client.session.cookies)
        parsed = urlparse(self.login_url)
        path = parsed.path + (f"?{parsed.query}" if parsed.query else "")

        try:
            get_resp = client.get(path)
        except Exception as e:
            raise AuthenticationError(f"Could not fetch login page: {e}") from e

        soup = BeautifulSoup(get_resp.content, "html.parser")
        form = self._find_login_form(soup)
        if not form:
            raise AuthenticationError(
                f"No login form containing '{self.username_field}' found at {self.login_url}"
            )

        form_data = self._build_form_data(form)
        form_data[self.username_field] = self.username
        form_data[self.password_field] = self.password

        action = form.get("action", "") or path
        post_url = urljoin(self.login_url, action)
        post_parsed = urlparse(post_url)
        post_path = post_parsed.path + (f"?{post_parsed.query}" if post_parsed.query else "")

        try:
            post_resp = client.post(post_path, data=form_data)
        except Exception as e:
            raise AuthenticationError(f"Login POST failed: {e}") from e

        if not self._verify_success(get_resp, post_resp):
            raise AuthenticationError(
                f"Login appeared to fail for '{self.username}' -- "
                "check credentials and ensure no MFA is required"
            )

        post_cookies = dict(client.session.cookies)
        session_cookie = self._detect_session_cookie(post_cookies)

        logger.info("Form authentication succeeded for %s", self.username)
        return AuthSession(
            mode="form",
            username=self.username,
            cookies=post_cookies,
            pre_login_cookies=pre_login_cookies,
            session_cookie_name=session_cookie,
            login_url=self.login_url,
            logout_url=self.logout_url,
            authenticated=True,
        )

    def verify(self, client: "WebClient", session: AuthSession) -> bool:
        if not session.login_url:
            return True
        try:
            parsed = urlparse(session.login_url)
            path = parsed.path + (f"?{parsed.query}" if parsed.query else "")
            resp = client.get(path)
            # If we're redirected back to the login page, session has expired
            final_url = resp.url or session.login_url
            return urlparse(final_url).path != urlparse(session.login_url).path
        except Exception:
            return False

    def _find_login_form(self, soup):
        for form in soup.find_all("form"):
            fields = [
                inp.get("name", "")
                for inp in form.find_all(["input", "textarea"])
            ]
            if self.username_field in fields or self.password_field in fields:
                return form
        return None

    def _build_form_data(self, form) -> dict:
        data = {}
        for inp in form.find_all(["input", "select", "textarea"]):
            name = inp.get("name")
            if not name:
                continue
            inp_type = inp.get("type", "text").lower()
            if inp_type in ("submit", "button", "image", "reset"):
                continue
            if inp_type == "checkbox" and not inp.get("checked"):
                continue
            data[name] = inp.get("value", "")
        return data

    def _verify_success(self, get_resp, post_resp) -> bool:
        if self.success_indicator:
            return self.success_indicator in post_resp.text
        # Heuristic: redirected away from login page, or response no longer
        # contains a password input field
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(post_resp.content, "html.parser")
        has_password_field = bool(
            soup.find("input", {"type": "password"})
        )
        return not has_password_field

    def _detect_session_cookie(self, cookies: dict) -> Optional[str]:
        known = ("session", "sessionid", "jsessionid", "phpsessid",
                 "asp.net_sessionid", "connect.sid", "sid", "auth",
                 "token", "jwt")
        for name in cookies:
            if name.lower() in known:
                return name
        # Fall back to the longest cookie value (heuristic for session tokens)
        if cookies:
            return max(cookies, key=lambda n: len(cookies[n]))
        return None


class BearerAuthManager(AuthManager):
    """Inject a pre-obtained JWT or opaque bearer token.

    No network call is needed -- the token is simply set as the
    Authorization header. Use this after manually completing an OAuth /
    OIDC / MFA flow to obtain a token.
    """

    def __init__(self, token: str, verify_url: str = "/") -> None:
        self.token = token
        self.verify_url = verify_url

    def authenticate(self, client: "WebClient") -> AuthSession:
        client.set_bearer_token(self.token)
        logger.info("Bearer token authentication configured")
        return AuthSession(
            mode="bearer",
            token=self.token,
            authenticated=True,
        )

    def verify(self, client: "WebClient", session: AuthSession) -> bool:
        try:
            resp = client.get(self.verify_url)
            return resp.status_code not in (401, 403)
        except Exception:
            return False


class CookieAuthManager(AuthManager):
    """Import raw session cookies from a browser or proxy export.

    This is the recommended approach for apps protected by MFA, SSO,
    CAPTCHA, or any interactive auth flow. The operator logs in manually
    in their browser, exports the session cookies (via browser devtools,
    Cookie-Editor extension, Burp Suite, or similar), and passes them here.

    Cookie string format: "name=value; name2=value2"
    """

    def __init__(
        self,
        cookies: Dict[str, str],
        verify_url: str = "/",
    ) -> None:
        self.cookies = cookies
        self.verify_url = verify_url

    def authenticate(self, client: "WebClient") -> AuthSession:
        client.set_cookies(self.cookies)
        session_cookie = next(iter(self.cookies), None)
        logger.info(
            "Cookie authentication configured (%d cookies)", len(self.cookies)
        )
        return AuthSession(
            mode="cookie",
            cookies=dict(self.cookies),
            session_cookie_name=session_cookie,
            authenticated=True,
        )

    def verify(self, client: "WebClient", session: AuthSession) -> bool:
        try:
            resp = client.get(self.verify_url)
            return resp.status_code not in (401, 403)
        except Exception:
            return False


class BasicAuthManager(AuthManager):
    """HTTP Basic authentication."""

    def __init__(
        self,
        username: str,
        password: str,
        verify_url: str = "/",
    ) -> None:
        self.username = username
        self.password = password
        self.verify_url = verify_url

    def authenticate(self, client: "WebClient") -> AuthSession:
        client.set_auth(self.username, self.password)
        try:
            resp = client.get(self.verify_url)
            if resp.status_code in (401, 403):
                raise AuthenticationError(
                    f"Basic auth failed for '{self.username}' -- check credentials"
                )
        except AuthenticationError:
            raise
        except Exception as e:
            raise AuthenticationError(f"Basic auth verification failed: {e}") from e

        logger.info("Basic auth succeeded for %s", self.username)
        return AuthSession(
            mode="basic",
            username=self.username,
            authenticated=True,
        )

    def verify(self, client: "WebClient", session: AuthSession) -> bool:
        try:
            resp = client.get(self.verify_url)
            return resp.status_code not in (401, 403)
        except Exception:
            return False


def parse_cookie_string(cookie_str: str) -> Dict[str, str]:
    """Parse a browser-style cookie string into a dict.

    Accepts the format produced by browser devtools' 'Copy as cURL':
      "session=abc123; csrf=xyz; other=value"
    """
    cookies = {}
    for part in cookie_str.split(";"):
        part = part.strip()
        if "=" in part:
            name, _, value = part.partition("=")
            cookies[name.strip()] = value.strip()
    return cookies


def make_auth_manager(
    mode: str,
    *,
    username: Optional[str] = None,
    password: Optional[str] = None,
    token: Optional[str] = None,
    cookies: Optional[str] = None,
    login_url: Optional[str] = None,
    logout_url: Optional[str] = None,
    username_field: str = "username",
    password_field: str = "password",
    verify_url: str = "/",
) -> Optional[AuthManager]:
    """Factory: instantiate the right AuthManager from CLI arguments.

    Returns None for mode='none' (unauthenticated scan).
    """
    if mode == "none" or not mode:
        return None
    if mode == "form":
        if not login_url or not username or not password:
            raise ValueError(
                "--auth-mode form requires --login-url, --username, and --password"
            )
        return FormAuthManager(
            login_url=login_url,
            username=username,
            password=password,
            username_field=username_field,
            password_field=password_field,
            logout_url=logout_url,
        )
    if mode == "bearer":
        if not token:
            raise ValueError("--auth-mode bearer requires --token")
        return BearerAuthManager(token=token, verify_url=verify_url)
    if mode == "cookie":
        if not cookies:
            raise ValueError(
                "--auth-mode cookie requires --cookies 'name=value; name2=value2'"
            )
        return CookieAuthManager(
            cookies=parse_cookie_string(cookies),
            verify_url=verify_url,
        )
    if mode == "basic":
        if not username or not password:
            raise ValueError("--auth-mode basic requires --username and --password")
        return BasicAuthManager(
            username=username, password=password, verify_url=verify_url
        )
    raise ValueError(
        f"Unknown auth mode '{mode}'. Choose: none, form, bearer, cookie, basic"
    )
