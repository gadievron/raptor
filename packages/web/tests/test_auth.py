"""Unit tests for the web auth managers (no network)."""

from __future__ import annotations

import pytest

from packages.web.auth import (
    AuthenticationError,
    BearerAuthManager,
    CookieAuthManager,
    make_auth_manager,
    parse_cookie_string,
)


class _StubResponse:
    def __init__(self, status_code: int = 200, text: str = "ok"):
        self.status_code = status_code
        self.text = text


class _StubClient:
    """Just enough of WebClient for the non-form managers."""

    def __init__(self):
        self.headers: dict[str, str] = {}
        self.cookies: dict[str, str] = {}
        self.reveal_secrets = False

    class _Session:
        def __init__(self, outer):
            self._outer = outer

        @property
        def headers(self):
            return self._outer.headers

    @property
    def session(self):
        return self._Session(self)

    def set_bearer_token(self, token: str) -> None:
        self.headers["Authorization"] = f"Bearer {token}"

    def set_cookies(self, cookies: dict[str, str]) -> None:
        self.cookies.update(cookies)

    def get_cookies(self) -> dict[str, str]:
        return dict(self.cookies)

    def get(self, path: str, **_kwargs):
        return _StubResponse(200)


def test_parse_cookie_string_handles_values_with_equals():
    parsed = parse_cookie_string("session=abc=def; pref=dark;  empty")

    assert parsed["session"] == "abc=def"
    assert parsed["pref"] == "dark"
    assert "empty" not in parsed


def test_cookie_auth_manager_imports_cookies_and_reports_session():
    manager = CookieAuthManager(cookies={"sid": "s3cret", "pref": "dark"})
    client = _StubClient()

    session = manager.authenticate(client)

    assert session.authenticated is True
    assert session.mode == "cookie"
    assert client.get_cookies()["sid"] == "s3cret"


def test_bearer_auth_manager_sets_authorization_header():
    manager = BearerAuthManager(token="tok-123")
    client = _StubClient()

    session = manager.authenticate(client)

    assert session.authenticated is True
    assert client.headers["Authorization"] == "Bearer tok-123"


@pytest.mark.parametrize(
    ("mode", "kwargs", "message"),
    [
        ("form", {}, "username"),
        ("bearer", {}, "token"),
        ("cookie", {}, "cookie"),
        ("basic", {"username": "u"}, "password"),
    ],
)
def test_make_auth_manager_requires_per_mode_arguments(mode, kwargs, message):
    with pytest.raises(ValueError, match=message):
        make_auth_manager(mode, **kwargs)


def test_make_auth_manager_none_mode_returns_none():
    assert make_auth_manager("none") is None


def test_bearer_verify_never_raises_on_transport_failure():
    """authenticate() is offline for bearer mode; verify() probes the
    target and must degrade to False, not raise."""

    class _FailingClient(_StubClient):
        def get(self, path: str, **_kwargs):
            raise AuthenticationError("boom")

    manager = BearerAuthManager(token="tok")
    client = _FailingClient()
    session = manager.authenticate(client)

    assert session.authenticated is True
    assert manager.verify(client, session) is False


def test_cross_origin_login_url_is_refused_loudly():
    pytest.importorskip("bs4")
    from packages.web.auth import AuthenticationError, FormAuthManager
    from packages.web.origin import origin_of

    class _ScopedClient(_StubClient):
        base_url = "https://target.example"

        def _is_in_scope(self, url: str) -> bool:
            # Same origin-equality predicate as WebClient._is_in_scope
            # — a prefix check here would accept crafted hosts like
            # https://target.example.evil.test and no longer model the
            # scope gate the production client actually applies.
            return origin_of(url) == origin_of(self.base_url)

        def get_cookies(self):
            return {}

    manager = FormAuthManager(
        login_url="https://sso.other.example/login",
        username="u", password="p",
    )
    # Stripping the URL to path+query silently re-anchored the login
    # POST onto the target origin — credentials to the wrong host's
    # path with no error.
    with pytest.raises(AuthenticationError, match="not on the target"):
        manager.authenticate(_ScopedClient())


def test_verify_success_requires_a_logout_affordance_not_body_text():
    pytest.importorskip("bs4")
    from packages.web.auth import FormAuthManager

    manager = FormAuthManager(
        login_url="https://t.example/login", username="u", password="p",
    )

    class _Resp:
        status_code = 200
        history: list = []
        url = "https://t.example/login"

        def __init__(self, html: str):
            self.text = html
            self.content = html.encode()

    # Nav furniture / marketing copy mentioning "logout" is not a
    # session: no affordance, no success.
    furniture = _Resp(
        "<p>You can logout any time from the menu. Sign out policies "
        "apply.</p>"
    )
    assert manager._verify_success(_Resp("<form></form>"), furniture) is False

    # A real logout link IS the affordance.
    affordance = _Resp('<a href="/account/logout">Log out</a>')
    assert manager._verify_success(_Resp("<form></form>"), affordance) is True
