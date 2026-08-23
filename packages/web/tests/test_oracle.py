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
