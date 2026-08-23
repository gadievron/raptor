"""Upstream proxy URL parsing (`_parse_proxy_url`).

The load-bearing case: https:// upstream URLs must be REJECTED at
parse time. Pre-fix the scheme was validated and then discarded — the
upstream leg is opened with plain asyncio.open_connection (no ssl=),
so an operator who pointed HTTPS_PROXY at a TLS proxy had their
CONNECT metadata sent in plaintext to it (silent downgrade of
operator intent). No TLS wrapping is attempted; refusal is fail-fast
and actionable, mirroring the existing userinfo rejection.
"""

from __future__ import annotations

import pytest

from core.sandbox.proxy import _parse_proxy_url


class TestHttpsUpstreamRejected:

    def test_https_url_raises_actionable_valueerror(self):
        with pytest.raises(ValueError, match="plaintext"):
            _parse_proxy_url("https://corp-proxy.example:3128")

    def test_https_url_without_port_raises_too(self):
        # Pre-fix this silently became ("corp-proxy.example", 443)
        # over a plaintext leg.
        with pytest.raises(ValueError, match="https://"):
            _parse_proxy_url("https://corp-proxy.example")

    def test_error_message_names_the_remedy(self):
        with pytest.raises(ValueError, match="http://"):
            _parse_proxy_url("https://corp-proxy.example:3128")

    def test_construction_fails_fast_with_https_upstream(self):
        """The refusal must surface at EgressProxy construction, not
        mid-CONNECT."""
        from core.sandbox import proxy as proxy_mod
        with pytest.raises(ValueError, match="plaintext"):
            proxy_mod.EgressProxy(
                allowed_hosts={"x"},
                upstream_proxy="https://corp-proxy.example:3128",
            )


class TestHttpUpstreamStillAccepted:

    def test_http_url_parses(self):
        assert _parse_proxy_url("http://corp-proxy.example:3128") == \
            ("corp-proxy.example", 3128)

    def test_http_default_port_is_80(self):
        assert _parse_proxy_url("http://corp-proxy.example") == \
            ("corp-proxy.example", 80)

    def test_empty_and_none_return_none(self):
        assert _parse_proxy_url(None) is None
        assert _parse_proxy_url("") is None

    def test_other_schemes_still_rejected(self):
        with pytest.raises(ValueError, match="scheme"):
            _parse_proxy_url("socks5://corp-proxy.example:1080")

    def test_userinfo_still_rejected(self):
        with pytest.raises(ValueError, match="auth"):
            _parse_proxy_url("http://user:pw@corp-proxy.example:3128")
