"""Two-direction oracle tests for the ASVS check classes: each check
must still detect its true positive AND no longer fire on the weak
signal that produced false positives. Mocked clients only — no network."""

from __future__ import annotations

import json
from types import SimpleNamespace


class FakeResponse:
    def __init__(self, status: int = 200, text: str = "", headers: dict | None = None,
                 url: str = "", history: list | None = None, raw=None) -> None:
        self.status_code = status
        self.text = text
        self.content = text.encode()
        self.headers = headers or {}
        self.url = url
        self.history = history or []
        if raw is not None:
            self.raw = raw

    def json(self):
        return json.loads(self.text)


class FakeClient:
    """Route requests to a handler(method, path_or_url, **kwargs)."""

    def __init__(self, handler, cookies: dict | None = None) -> None:
        self._handler = handler
        self._cookies = dict(cookies or {})
        self.calls: list[tuple] = []
        self.verify_ssl = True
        self.reveal_secrets = False

    def get(self, path, params=None, headers=None, allow_redirects=True):
        self.calls.append(("GET", path, params, headers))
        return self._handler("GET", path, params=params, headers=headers,
                             allow_redirects=allow_redirects, client=self)

    def post(self, path, data=None, json_data=None, headers=None,
             allow_redirects=True):
        self.calls.append(("POST", path, data, json_data))
        return self._handler("POST", path, data=data, json_data=json_data,
                             headers=headers, allow_redirects=allow_redirects,
                             client=self)

    def get_cookies(self):
        return dict(self._cookies)


# -- access-control forbidden-bypass header primitive -------------------------


def _bypass(homepage_body: str, override_body: str):
    from packages.web.access_control import (
        AccessControlResult,
        Principal,
        _try_forbidden_bypass,
    )

    def handler(method, path, headers=None, **_kw):
        if headers:  # override-header probe of '/'
            return FakeResponse(200, override_body)
        if path == "/":
            return FakeResponse(200, homepage_body)
        return FakeResponse(403, "forbidden")  # path-primitive probes

    principal = Principal("anonymous", FakeClient(handler))
    return _try_forbidden_bypass(
        principal, "https://t.example/admin/users",
        AccessControlResult(), original_status=403,
    )


def test_forbidden_bypass_needs_content_absent_from_plain_homepage():
    # Homepage nav contains 'users' with and without the override
    # header: the server ignored the header, no bypass happened.
    assert _bypass(
        homepage_body="<nav>Home | Users | About</nav>",
        override_body="<nav>Home | Users | About</nav>",
    ) is None


def test_forbidden_bypass_detects_real_override_routing():
    hit = _bypass(
        homepage_body="<nav>Home | About</nav>",
        override_body="<h1>Users administration</h1><table>users</table>",
    )
    assert hit is not None
    assert hit["kind"] == "forbidden_bypass"
    # Actual observed status, never a hardcoded placeholder.
    assert hit["evidence"]["original_status"] == 403


# -- form-auth success verification -------------------------------------------


def _verify(post_resp) -> bool:
    from packages.web.auth import FormAuthManager

    manager = FormAuthManager(
        login_url="https://t.example/login", username="u", password="p",
    )
    get_resp = FakeResponse(200, '<form><input type="password"></form>')
    return manager._verify_success(get_resp, post_resp)


def test_login_json_error_without_password_field_is_not_success():
    assert _verify(FakeResponse(
        200, '{"error": "invalid credentials"}',
        url="https://t.example/login",
    )) is False


def test_login_redirect_away_from_login_page_is_success():
    assert _verify(FakeResponse(
        200, "<h1>Dashboard</h1>",
        url="https://t.example/home",
        history=[SimpleNamespace(status_code=302)],
    )) is True


def test_login_page_re_rendering_the_form_is_failure():
    assert _verify(FakeResponse(
        200, '<form><input type="password"></form>',
        url="https://t.example/login",
    )) is False


# -- mass assignment persistence oracle ---------------------------------------


def _mass_assignment(persisted_json: str):
    from packages.web.checks.api import MassAssignmentCheck

    def handler(method, path, **_kw):
        if method == "POST":
            # Endpoint echoes the submitted document back.
            return FakeResponse(200, '{"is_admin": true, "role": "admin"}')
        return FakeResponse(200, persisted_json)

    return MassAssignmentCheck().run(
        FakeClient(handler), "https://t.example",
        session=SimpleNamespace(authenticated=True),
    )


def test_mass_assignment_echo_without_persistence_is_not_a_finding():
    assert _mass_assignment('{"is_admin": false, "role": "user"}') == []


def test_mass_assignment_persisted_attribute_is_a_finding():
    findings = _mass_assignment('{"is_admin": true, "role": "admin"}')
    assert len(findings) == 1
    assert findings[0].severity == "critical"
    assert "persisted" in findings[0].evidence


# -- brute-force protection status semantics ----------------------------------


def _brute_force(status_sequence: list[int], final_text: str = "Invalid credentials"):
    from packages.web.checks.authentication import BruteForceProtectionCheck

    statuses = iter(status_sequence)

    def handler(method, path, **_kw):
        if method == "POST":
            return FakeResponse(next(statuses, status_sequence[-1]), final_text)
        return FakeResponse(200, '<input type="password">')

    discovery = {"forms": [{"action": "https://t.example/login"}]}
    return BruteForceProtectionCheck().run(
        FakeClient(handler), "https://t.example", discovery=discovery,
    )


def test_constant_401_login_is_flagged_as_unprotected():
    # 401 is the NORMAL invalid-credentials answer — it must not read
    # as lockout evidence.
    findings = _brute_force([401] * 6)
    assert len(findings) == 1
    assert findings[0].severity == "high"


def test_429_after_failures_counts_as_protection():
    assert _brute_force([401, 401, 429, 429, 429, 429]) == []


def test_403_escalation_counts_but_constant_403_is_inconclusive():
    # 403 appearing only after repeated attempts = throttle escalation.
    assert _brute_force([401, 401, 403, 403, 403, 403]) == []
    # Constant 403 (CSRF/WAF): probes never reached credential checks.
    assert _brute_force([403] * 6) == []


# -- default credentials session evidence --------------------------------------


def _default_creds(grants_session: bool):
    from packages.web.checks.authentication import DefaultCredentialsCheck

    state = {"logged_in": False}

    def handler(method, path, client=None, **_kw):
        if method == "POST":
            if grants_session:
                state["logged_in"] = True
                client._cookies["sessionid"] = "granted-token"
            # Failed login 302s to a page whose form is a JS modal:
            # no raw password input either way.
            return FakeResponse(200, "<h1>Welcome</h1>", url="https://t.example/")
        if state["logged_in"]:
            return FakeResponse(200, "<h1>Dashboard</h1>")
        return FakeResponse(200, '<form><input type="password"></form>')

    discovery = {"forms": [{"action": "https://t.example/login"}]}
    return DefaultCredentialsCheck().run(
        FakeClient(handler), "https://t.example", discovery=discovery,
    )


def test_rejected_default_credentials_without_session_are_not_a_finding():
    assert _default_creds(grants_session=False) == []


def test_accepted_default_credentials_with_session_are_critical():
    findings = _default_creds(grants_session=True)
    assert len(findings) == 1
    assert findings[0].severity == "critical"


# -- cache deception calibration ----------------------------------------------


def _cache_deception(catch_all: bool, cache_headers: dict):
    from packages.web.checks.cache import CacheDeceptionCheck

    shell = "<html>Your account profile email address</html>"

    def handler(method, path, **_kw):
        if "raptor-" in path:  # known-nonexistent control
            if catch_all:
                return FakeResponse(200, shell, headers=cache_headers)
            return FakeResponse(404, "not found")
        return FakeResponse(200, shell, headers=cache_headers)

    return CacheDeceptionCheck().run(
        FakeClient(handler), "https://t.example",
        session=SimpleNamespace(authenticated=True),
    )


def test_spa_catch_all_shell_is_not_cache_deception():
    assert _cache_deception(
        catch_all=True, cache_headers={"X-Cache": "HIT"},
    ) == []


def test_via_header_alone_is_not_cache_evidence():
    # Via marks a proxy hop (RFC 9110), not a cache.
    assert _cache_deception(
        catch_all=False, cache_headers={"Via": "1.1 nginx"},
    ) == []


def test_real_cache_deception_is_still_detected():
    findings = _cache_deception(
        catch_all=False, cache_headers={"X-Cache": "HIT"},
    )
    assert len(findings) == 1
    assert findings[0].severity == "high"


# -- CSP directive scoping -----------------------------------------------------


def _csp(policy: str):
    from packages.web.checks.headers import CspCheck

    def handler(method, path, **_kw):
        return FakeResponse(200, "", headers={"Content-Security-Policy": policy})

    return CspCheck().run(FakeClient(handler), "https://t.example")


def test_style_src_unsafe_inline_is_not_a_script_src_finding():
    assert _csp(
        "default-src 'self'; script-src 'self'; style-src 'unsafe-inline'",
    ) == []


def test_script_src_unsafe_inline_still_flags_and_foreign_nonce_never_exempts():
    findings = _csp("script-src 'unsafe-inline'; style-src 'nonce-abc123'")
    assert len(findings) == 1
    assert "'unsafe-inline' in script-src" in findings[0].detail


def test_script_src_nonce_exempts_unsafe_inline():
    assert _csp("script-src 'unsafe-inline' 'nonce-abc123'") == []


# -- sensitive file calibration --------------------------------------------------


def _sensitive_files(control_status: int, env_body: str | None):
    from packages.web.checks.information import SensitiveFileCheck

    shell = "<html>app shell</html>"

    def handler(method, path, **_kw):
        if "does-not-exist" in path:
            return FakeResponse(control_status, shell if control_status == 200 else "nope")
        if path == "/.env" and env_body is not None:
            return FakeResponse(200, env_body)
        if control_status == 200:
            return FakeResponse(200, shell)  # catch-all serves everything
        return FakeResponse(404, "nope")

    return SensitiveFileCheck().run(FakeClient(handler), "https://t.example")


def test_spa_catch_all_does_not_mass_produce_sensitive_file_findings():
    assert _sensitive_files(control_status=200, env_body=None) == []


def test_distinct_sensitive_file_response_is_still_flagged():
    findings = _sensitive_files(
        control_status=404, env_body="DB_PASSWORD=hunter2-swordfish",
    )
    assert len(findings) == 1
    assert findings[0].severity == "critical"
    assert "/.env" in findings[0].url


# -- OAuth missing-state scoping -------------------------------------------------


def _oauth_state(homepage: str):
    from packages.web.checks.oauth import OAuthMissingStateCheck

    def handler(method, path, **_kw):
        return FakeResponse(200, homepage)

    return OAuthMissingStateCheck().run(FakeClient(handler), "https://t.example")


def test_server_side_initiation_links_are_not_missing_state():
    assert _oauth_state(
        '<a href="/auth/google/connect">Google</a>'
        '<a href="/how-to-connect">Docs</a>'
    ) == []


def test_authorization_url_without_state_is_flagged():
    findings = _oauth_state(
        '<a href="/oauth/authorize?response_type=code&client_id=app1">x</a>',
    )
    assert len(findings) == 1


def test_authorization_url_with_state_passes():
    assert _oauth_state(
        '<a href="/oauth/authorize?response_type=code&client_id=app1&state=r4nd">x</a>',
    ) == []


# -- prototype pollution behavioral oracle ----------------------------------------


def _prototype_pollution(pollutable: bool, echo: bool):
    from packages.web.checks.prototype_pollution import (
        _SENTINEL,
        ServerSidePrototypePollutionCheck,
    )

    state = {"polluted": False}

    def handler(method, path, params=None, json_data=None, **_kw):
        probe_carries_sentinel = _SENTINEL in str(json_data or "") or _SENTINEL in str(params or "")
        if probe_carries_sentinel and pollutable:
            state["polluted"] = True
        if probe_carries_sentinel and echo:
            return FakeResponse(200, f"rejected fields: {_SENTINEL} polluted")
        if state["polluted"]:
            return FakeResponse(200, f"<footer>{_SENTINEL}</footer>")
        return FakeResponse(200, "<html>plain</html>")

    return ServerSidePrototypePollutionCheck().run(
        FakeClient(handler), "https://t.example",
    )


def test_payload_echo_is_not_prototype_pollution():
    assert _prototype_pollution(pollutable=False, echo=True) == []


def test_pollution_visible_on_clean_request_is_a_finding():
    findings = _prototype_pollution(pollutable=True, echo=True)
    assert len(findings) == 1


# -- cookie flag checks on multiple Set-Cookie headers -----------------------------


class _MultiHeaderRaw:
    def __init__(self, values: list[str]) -> None:
        self._values = values

    def get_all(self, name):
        return list(self._values) if name.lower() == "set-cookie" else []


def _cookie_response(cookies: list[str], folded_only: bool = False):
    if folded_only:
        return FakeResponse(200, "", headers={"Set-Cookie": ", ".join(cookies)})
    return FakeResponse(
        200, "", headers={"Set-Cookie": ", ".join(cookies)},
        raw=_MultiHeaderRaw(cookies),
    )


def _run_cookie_checks(response):
    from packages.web.checks.session import (
        HttpOnlyCookieFlagCheck,
        SameSiteCookieCheck,
        SecureCookieFlagCheck,
    )

    def handler(method, path, **_kw):
        return response

    client = FakeClient(handler)
    return (
        SecureCookieFlagCheck().run(client, "https://t.example"),
        HttpOnlyCookieFlagCheck().run(client, "https://t.example"),
        SameSiteCookieCheck().run(client, "https://t.example"),
    )


def test_one_well_flagged_cookie_does_not_mask_unflagged_siblings():
    secure, httponly, samesite = _run_cookie_checks(_cookie_response([
        "sessionid=SECRET123; Path=/",
        "csrftoken=x; Secure; HttpOnly; SameSite=Lax",
    ]))
    assert [f for f in secure if "sessionid" in f.detail]
    assert [f for f in httponly if "sessionid" in f.detail]
    assert [f for f in samesite if "sessionid" in f.detail]
    # The properly-flagged sibling is NOT reported.
    assert not [f for f in secure if "csrftoken" in f.detail]


def test_folded_set_cookie_header_is_unfolded_even_with_expires_commas():
    secure, httponly, samesite = _run_cookie_checks(_cookie_response(
        [
            "sessionid=SECRET123; Path=/; Expires=Wed, 21 Oct 2026 07:28:00 GMT",
            "csrftoken=x; Secure; HttpOnly; SameSite=Lax",
        ],
        folded_only=True,
    ))
    assert [f for f in secure if "sessionid" in f.detail]
    assert not [f for f in secure if "csrftoken" in f.detail]
    assert [f for f in httponly if "sessionid" in f.detail]
    assert [f for f in samesite if "sessionid" in f.detail]


def test_cookie_name_containing_secure_does_not_satisfy_the_flag():
    secure, _httponly, _samesite = _run_cookie_checks(_cookie_response([
        "securetoken=abc; Path=/",
    ]))
    assert len(secure) == 1
    assert "securetoken" in secure[0].detail


def test_fully_flagged_cookie_produces_no_findings():
    secure, httponly, samesite = _run_cookie_checks(_cookie_response([
        "sessionid=x; Secure; HttpOnly; SameSite=Lax",
    ]))
    assert secure == [] and httponly == [] and samesite == []


# -- SSRF baseline subtraction and probe location -----------------------------------


def _ssrf_param_check(handler, discovery):
    from packages.web.checks.ssrf import SsrfParameterCheck

    client = FakeClient(handler)
    return SsrfParameterCheck().run(
        client, "https://t.example", discovery=discovery,
    ), client


def test_always_present_error_text_is_not_ssrf_evidence():
    def handler(method, path, **_kw):
        # Diagnostics page: every response mentions a backend failure.
        return FakeResponse(200, "backend status: Connection refused (db-01)")

    findings, _ = _ssrf_param_check(
        handler, {"parameters": ["url"], "urls": []},
    )
    assert findings == []


def test_ssrf_probes_the_url_where_the_parameter_was_discovered():
    def handler(method, path, **_kw):
        if "/proxy" in str(path):
            return FakeResponse(200, "Failed to connect to 127.0.0.1 port 80")
        return FakeResponse(200, "<html>home</html>")

    findings, client = _ssrf_param_check(
        handler,
        {"parameters": [], "urls": ["https://t.example/proxy?url=https://a"]},
    )
    assert len(findings) >= 1
    assert findings[0].severity == "critical"
    probed = [call[1] for call in client.calls if "/proxy" in str(call[1])]
    assert probed, "the probe must hit the discovered /proxy endpoint"


# -- redirect legs are observable (client no longer eats the 3xx) --------------


def test_host_header_poisoned_location_is_detected():
    from packages.web.checks.base import PROBE_HOST
    from packages.web.checks.host_header import HostHeaderInjectionCheck

    observed = []

    def handler(method, path, headers=None, allow_redirects=True, **_kw):
        observed.append(allow_redirects)
        if headers and PROBE_HOST in str(headers.values()):
            return FakeResponse(
                302, "", headers={"Location": f"https://{PROBE_HOST}/reset"},
            )
        return FakeResponse(200, "<html>ok</html>")

    findings = HostHeaderInjectionCheck().run(FakeClient(handler), "https://t.example")
    assert len(findings) == 1
    assert "Location" in findings[0].evidence
    # The probe must observe redirects, never follow them: following
    # raises on the out-of-scope Location before the check sees it.
    assert False in observed


def test_host_header_clean_redirect_is_not_flagged():
    from packages.web.checks.host_header import HostHeaderInjectionCheck

    def handler(method, path, **_kw):
        return FakeResponse(302, "", headers={"Location": "/home"})

    assert HostHeaderInjectionCheck().run(
        FakeClient(handler), "https://t.example",
    ) == []


def test_oauth_open_redirect_to_probe_host_is_detected():
    from packages.web.checks.base import PROBE_HOST
    from packages.web.checks.oauth import OAuthOpenRedirectCheck

    def handler(method, path, params=None, allow_redirects=True, **_kw):
        assert allow_redirects is False
        if "authorize" in str(path) and params:
            return FakeResponse(
                302, "",
                headers={"Location": f"https://{PROBE_HOST}/callback?code=x"},
            )
        return FakeResponse(404, "")

    findings = OAuthOpenRedirectCheck().run(FakeClient(handler), "https://t.example")
    assert len(findings) == 1
    assert findings[0].severity == "critical"


def test_oauth_probe_host_reflected_in_query_is_not_a_redirect():
    from packages.web.checks.base import PROBE_HOST
    from packages.web.checks.oauth import OAuthOpenRedirectCheck

    def handler(method, path, params=None, **_kw):
        if params:
            return FakeResponse(
                302, "",
                headers={
                    "Location": f"https://t.example/login?back=https://{PROBE_HOST}/",
                },
            )
        return FakeResponse(404, "")

    assert OAuthOpenRedirectCheck().run(FakeClient(handler), "https://t.example") == []


# -- transport accounting on probes that bypass WebClient ----------------------


class _CountingClient(FakeClient):
    """Client double carrying the integer transport counter."""

    def __init__(self, handler, **kwargs):
        super().__init__(handler, **kwargs)
        self.transport_errors = 0
        self.verify_ssl = True


def test_raw_socket_smuggling_probe_failures_count_as_degradation():
    from packages.web.checks.cache import RequestSmugglingCheck

    check = RequestSmugglingCheck()
    check._raw_exchange = lambda *args: (None, 0.0)  # target unreachable
    client = _CountingClient(lambda *a, **k: FakeResponse(200, "ok"))
    assert check.run(client, "https://t.example") == []
    assert client.transport_errors == 3  # one per probe variant


def test_https_downgrade_probe_failure_counts_as_degradation(monkeypatch):
    import requests

    from packages.web.checks.tls import HttpsRedirectCheck

    def _refuse(*args, **kwargs):
        raise requests.ConnectionError("refused")

    monkeypatch.setattr(requests, "get", _refuse)
    client = _CountingClient(lambda *a, **k: FakeResponse(200, "ok"))
    assert HttpsRedirectCheck().run(client, "https://t.example") == []
    assert client.transport_errors == 1


def test_options_probe_failure_counts_as_degradation(monkeypatch):
    import requests

    from packages.web.checks.information import VerbosHttpMethodsCheck

    def _refuse(*args, **kwargs):
        raise requests.ConnectionError("refused")

    monkeypatch.setattr(requests, "options", _refuse)
    client = _CountingClient(lambda *a, **k: FakeResponse(200, "ok"))
    assert VerbosHttpMethodsCheck().run(client, "https://t.example") == []
    assert client.transport_errors == 1


def test_successful_bypass_probes_do_not_count(monkeypatch):
    import requests

    from packages.web.checks.tls import HttpsRedirectCheck

    monkeypatch.setattr(
        requests, "get",
        lambda *a, **k: FakeResponse(301, "", headers={"Location": "https://t.example/"}),
    )
    client = _CountingClient(lambda *a, **k: FakeResponse(200, "ok"))
    HttpsRedirectCheck().run(client, "https://t.example")
    assert client.transport_errors == 0
