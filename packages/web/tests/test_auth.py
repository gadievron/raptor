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
