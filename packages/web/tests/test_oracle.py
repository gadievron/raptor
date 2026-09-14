"""Verification-oracle semantics: replay, control differentials,
canary attribution, transport degradation, request accounting."""

from __future__ import annotations

import pytest

pytest.importorskip("requests")

from packages.web.markers import marker_present  # noqa: E402
from packages.web.oracle import (  # noqa: E402
    INCONCLUSIVE,
    REFUTED,
    VERIFIED,
    VerificationOracle,
    mint_canary,
)

SQL_ERROR = "You have an error in your SQL syntax near line 1"
PASSWD = "root:x:0:0:root:/root:/bin/bash"
CLEAN = "<html><body>results: none</body></html>"


class _Resp:
    def __init__(self, text: str, status_code: int = 200):
        self.text = text
        self.status_code = status_code
        self.content = text.encode()


class _ScriptedClient:
    """Returns responses per param value; records requests.

    ``script`` maps a sent value to response text; unmatched values
    get ``default``. A value mapped to an Exception instance raises.
    Callables produce per-call texts (for flaky pages).
    """

    reveal_secrets = False

    def __init__(self, script=None, default=CLEAN):
        self.script = dict(script or {})
        self.default = default
        self.calls = []

    def _respond(self, value):
        outcome = self.script.get(value, self.default)
        if isinstance(outcome, Exception):
            raise outcome
        if callable(outcome):
            outcome = outcome()
        return _Resp(outcome)

    def get(self, url, params=None, **kw):
        (value,) = list(params.values())
        self.calls.append(("GET", url, value))
        return self._respond(value)

    def post(self, url, data=None, **kw):
        (value,) = list(data.values())
        self.calls.append(("POST", url, value))
        return self._respond(value)


class TestMarkers:
    def test_class_markers_match(self):
        assert marker_present("sqli", SQL_ERROR)
        assert marker_present("path_traversal", PASSWD)
        assert marker_present("command_injection", "uid=33(www-data)")

    def test_clean_text_no_marker(self):
        for vt in ("sqli", "path_traversal", "command_injection"):
            assert not marker_present(vt, CLEAN)

    def test_xss_and_unknown_have_no_marker(self):
        assert not marker_present("xss", "<script>alert(1)</script>")
        assert not marker_present("nosuch", SQL_ERROR)


class TestMintCanary:
    def test_unique_and_benign_shape(self):
        a, b = mint_canary(), mint_canary()
        assert a != b
        assert a.startswith("raptorcanary")
        assert a.isalnum()


class TestMarkerDifferential:
    PAYLOAD = "' OR 1=1--"

    def test_verified_when_replay_reproduces_and_controls_clean(self):
        client = _ScriptedClient({self.PAYLOAD: SQL_ERROR})
        result = VerificationOracle(client).verify(
            "http://t/search", "q", self.PAYLOAD, "sqli")
        assert result.status == VERIFIED
        assert result.refuted_by_control is False
        assert result.requests_used == 3  # replay + 2 control legs

    def test_refuted_when_controls_show_marker(self):
        client = _ScriptedClient({}, default=SQL_ERROR)
        result = VerificationOracle(client).verify(
            "http://t/search", "q", self.PAYLOAD, "sqli")
        assert result.status == REFUTED
        assert result.refuted_by_control is True

    def test_flaky_replay_is_inconclusive(self):
        client = _ScriptedClient({self.PAYLOAD: CLEAN})
        result = VerificationOracle(client).verify(
            "http://t/search", "q", self.PAYLOAD, "sqli")
        assert result.status == INCONCLUSIVE
        assert result.refuted_by_control is False

    def test_mixed_controls_are_inconclusive(self):
        texts = iter([SQL_ERROR, SQL_ERROR, CLEAN])
        client = _ScriptedClient(default=lambda: next(texts))
        result = VerificationOracle(client).verify(
            "http://t/search", "q", self.PAYLOAD, "sqli")
        assert result.status == INCONCLUSIVE

    def test_transport_error_is_inconclusive_and_counted(self):
        client = _ScriptedClient({self.PAYLOAD: ConnectionError("down")})
        oracle = VerificationOracle(client)
        result = oracle.verify("http://t/search", "q", self.PAYLOAD, "sqli")
        assert result.status == INCONCLUSIVE
        assert oracle.errors == 1

    def test_post_method_used(self):
        client = _ScriptedClient({self.PAYLOAD: SQL_ERROR})
        VerificationOracle(client).verify(
            "http://t/login", "user", self.PAYLOAD, "sqli", method="POST")
        assert all(m == "POST" for m, _, _ in client.calls)


class TestReflection:
    PAYLOAD = "<script>alert(1)</script>"

    def test_verified_when_canary_attributes_and_payload_replays(self):
        client = _ScriptedClient(
            default=CLEAN,
            script={self.PAYLOAD: f"you searched {self.PAYLOAD}"},
        )
        # canary value is dynamic — echo any canary back
        client.script = dict(client.script)
        orig = client._respond

        def echo(value):
            if value.startswith("raptorcanary"):
                return _Resp(f"you searched {value}")
            return orig(value)

        client._respond = echo
        result = VerificationOracle(client).verify(
            "http://t/", "q", self.PAYLOAD, "xss")
        assert result.status == VERIFIED
        assert result.requests_used == 2

    def test_refuted_when_payload_is_page_furniture(self):
        client = _ScriptedClient(default=f"docs: {self.PAYLOAD}")
        result = VerificationOracle(client).verify(
            "http://t/", "q", self.PAYLOAD, "xss")
        assert result.status == REFUTED
        assert result.refuted_by_control is True
        assert result.requests_used == 1  # refuted on the canary probe

    def test_non_reflecting_param_inconclusive(self):
        client = _ScriptedClient(
            default=CLEAN,
            script={self.PAYLOAD: f"echo {self.PAYLOAD}"},
        )
        result = VerificationOracle(client).verify(
            "http://t/", "q", self.PAYLOAD, "xss")
        assert result.status == INCONCLUSIVE


class TestUnknownClass:
    def test_unknown_vuln_type_inconclusive_no_requests(self):
        client = _ScriptedClient()
        oracle = VerificationOracle(client)
        result = oracle.verify("http://t/", "q", "x", "nosuchclass")
        assert result.status == INCONCLUSIVE
        assert oracle.requests_used == 0


class _FormServerClient:
    """Simulates a CSRF-protected multi-field form endpoint.

    Server-side validation rejects any request missing the csrf token
    or the required sibling field BEFORE the fuzzed value reaches the
    injectable sink — the shape that demoted every multi-field form
    hit to inconclusive when replay sent the fuzzed field alone.
    """

    reveal_secrets = False

    def __init__(self):
        self.requests: list[dict] = []

    def _respond(self, values):
        self.requests.append(dict(values))
        if values.get("csrf") != "tok123" or "email" not in values:
            return _Resp("<html>form validation failed</html>", 400)
        if "OR 1=1" in values.get("q", ""):
            return _Resp(SQL_ERROR, 500)
        return _Resp(CLEAN)

    def post(self, url, data=None, **kw):
        return self._respond(data or {})

    def get(self, url, params=None, **kw):
        return self._respond(params or {})


class TestSiblingFormFields:
    PAYLOAD = "' OR 1=1--"
    BASE = {"csrf": "tok123", "email": "a@example.invalid", "q": "hello"}

    def test_replay_carries_siblings_and_confirms(self):
        client = _FormServerClient()
        result = VerificationOracle(client).verify(
            "http://t/search", "q", self.PAYLOAD, "sqli",
            method="POST", base_data=self.BASE)
        assert result.status == VERIFIED
        # Every leg (replay + both controls) rode the full field set.
        assert len(client.requests) == 3
        for sent in client.requests:
            assert sent["csrf"] == "tok123"
            assert sent["email"] == "a@example.invalid"
        # The fuzzed field is REPLACED in the payload leg, and the
        # control legs substitute the control value into that field.
        assert client.requests[0]["q"] == self.PAYLOAD
        assert client.requests[1]["q"] == client.requests[2]["q"]
        assert client.requests[1]["q"].startswith("raptorcanary")

    def test_siblings_ride_get_replays_too(self):
        client = _FormServerClient()
        result = VerificationOracle(client).verify(
            "http://t/search", "q", self.PAYLOAD, "sqli",
            method="GET", base_data=self.BASE)
        assert result.status == VERIFIED
        assert all(r["csrf"] == "tok123" for r in client.requests)

    def test_without_siblings_form_hit_stays_inconclusive(self):
        # The pre-carry failure mode: bare {param: value} replays fail
        # server-side validation on every leg — no marker anywhere, so
        # the verdict degrades instead of confirming.
        client = _FormServerClient()
        result = VerificationOracle(client).verify(
            "http://t/search", "q", self.PAYLOAD, "sqli", method="POST")
        assert result.status == INCONCLUSIVE


class _UrlRecordingClient:
    """Records the exact URL + params/data of every request."""

    reveal_secrets = False

    def __init__(self):
        self.calls = []

    def get(self, url, params=None, **kw):
        self.calls.append(("GET", url, dict(params or {})))
        return _Resp(CLEAN)

    def post(self, url, data=None, **kw):
        self.calls.append(("POST", url, dict(data or {})))
        return _Resp(CLEAN)


class TestProbeQueryDeduplication:
    """The recorded hit URL is the PRE-injection URL and commonly
    already carries the fuzzed parameter; requests appends ``params=``
    to the existing query, so pre-fix every replay/control leg sent
    ``?id=1&id=<probe>`` and first-occurrence-wins frameworks never
    saw the probed value — real query-vector hits demoted to
    inconclusive."""

    def test_fuzzed_param_stripped_from_recorded_url(self):
        client = _UrlRecordingClient()
        VerificationOracle(client)._probe(
            "http://t/page.php?id=1&keep=x", "id", "PROBE", "GET")
        _, url, params = client.calls[0]
        assert "id=" not in url
        assert "keep=x" in url
        assert params == {"id": "PROBE"}

    def test_base_data_keys_stripped_from_recorded_url(self):
        client = _UrlRecordingClient()
        VerificationOracle(client)._probe(
            "http://t/f?q=a&csrf=old&other=1", "q", "PROBE", "GET",
            base_data={"csrf": "tok"})
        _, url, params = client.calls[0]
        assert "q=" not in url and "csrf=old" not in url
        assert "other=1" in url
        assert params == {"q": "PROBE", "csrf": "tok"}

    def test_url_without_query_passes_through(self):
        client = _UrlRecordingClient()
        VerificationOracle(client)._probe(
            "http://t/search", "q", "PROBE", "GET")
        _, url, _ = client.calls[0]
        assert url == "http://t/search"

    def test_post_body_never_rewrites_the_url(self):
        # POST data cannot duplicate into the query string; the form
        # action URL is replayed exactly as detected.
        client = _UrlRecordingClient()
        VerificationOracle(client)._probe(
            "http://t/f?stage=2", "q", "PROBE", "POST")
        _, url, data = client.calls[0]
        assert url == "http://t/f?stage=2"
        assert data == {"q": "PROBE"}
