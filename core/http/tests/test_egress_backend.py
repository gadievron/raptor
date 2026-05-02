"""Tests for core.http.egress_backend.EgressClient (urllib3-backed).

End-to-end testing through the real proxy lives in ``core/sandbox/tests/`` —
the proxy has its own coverage there, and CONNECT-tunnel integration
tests need an HTTPS stub server with a self-signed cert which is heavy
infrastructure for limited additional confidence.
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

import urllib3

# core/http/tests/test_egress_backend.py -> repo root
sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from core.http import HttpError, default_client
from core.http.egress_backend import EgressClient
from core.http.urllib_backend import UrllibClient


# ---------------------------------------------------------------------------
# Wiring — host registration + ProxyManager construction
# ---------------------------------------------------------------------------

class TestEgressClientWiring:
    """Verifies EgressClient registers hosts with the proxy and constructs
    a urllib3.ProxyManager pointing at the in-process proxy."""

    def _stub_proxy(self, port: int = 12345):
        proxy = MagicMock()
        proxy.port = port
        return proxy

    @patch("core.sandbox.proxy.get_proxy")
    def test_registers_hosts_with_proxy(self, mock_get_proxy):
        mock_get_proxy.return_value = self._stub_proxy()
        EgressClient(["api.osv.dev", "services.nvd.nist.gov"])
        called_hosts = set(mock_get_proxy.call_args.args[0])
        assert {"api.osv.dev", "services.nvd.nist.gov"} <= called_hosts

    @patch("core.sandbox.proxy.get_proxy")
    def test_uses_proxy_manager(self, mock_get_proxy):
        """The injected pool must be a urllib3.ProxyManager (not a plain
        PoolManager) — that's what enforces routing through the proxy
        for every request, with no no_proxy bypass."""
        mock_get_proxy.return_value = self._stub_proxy(port=54321)
        client = EgressClient(["api.osv.dev"])
        assert isinstance(client._http, urllib3.ProxyManager)

    @patch("core.sandbox.proxy.get_proxy")
    def test_inherits_urllib_retry_logic(self, mock_get_proxy):
        """EgressClient extends UrllibClient — retry/parse/size-cap all
        inherited. Smoke-test: isinstance + public API present."""
        mock_get_proxy.return_value = self._stub_proxy()
        client = EgressClient(["api.osv.dev"])
        assert isinstance(client, UrllibClient)
        assert callable(client.get_json)
        assert callable(client.post_json)
        assert callable(client.get_bytes)

    @patch("core.sandbox.proxy.get_proxy")
    def test_iterable_hosts_accepted(self, mock_get_proxy):
        """allowed_hosts can be any iterable, not just a list."""
        mock_get_proxy.return_value = self._stub_proxy()
        EgressClient(("a.com", "b.com"))
        EgressClient(h for h in ["c.com"])

    @patch("core.sandbox.proxy.get_proxy")
    def test_get_request_routes_through_proxy(self, mock_get_proxy):
        """A GET request must go through the injected ProxyManager —
        urllib3.ProxyManager forwards every CONNECT to the proxy URL,
        no no_proxy bypass."""
        mock_get_proxy.return_value = self._stub_proxy()
        client = EgressClient(["example.com"])
        # Replace the pool with a stub.
        fake_resp = MagicMock()
        fake_resp.status = 200
        fake_resp.headers = {}
        fake_resp.stream = lambda cs, decode_content=True: iter(
            [b'{"ok": true}'],
        )
        fake_resp.release_conn = MagicMock()
        client._http = MagicMock()
        client._http.request.return_value = fake_resp

        result = client.get_json("https://example.com/api")
        assert result == {"ok": True}
        client._http.request.assert_called_once()


class TestProxyManagerHasNoBypass:
    """The whole reason for the urllib3 swap (besides pooling) was that
    stdlib urllib's ProxyHandler silently honoured no_proxy env vars,
    bypassing our chokepoint. urllib3's ProxyManager doesn't read
    no_proxy at request time — every request is forwarded.

    These tests verify the property by inspecting the constructed pool.
    """

    @patch("core.sandbox.proxy.get_proxy")
    def test_no_proxy_env_does_not_affect_pool_construction(
        self, mock_get_proxy, monkeypatch,
    ):
        mock_get_proxy.return_value = MagicMock(port=12345)
        # Set no_proxy to its most aggressive form before constructing.
        monkeypatch.setenv("no_proxy", "*")
        monkeypatch.setenv("NO_PROXY", "*")

        client = EgressClient(["api.osv.dev"])

        # Smoke check: ProxyManager constructed; client._http is the
        # ProxyManager. The fact that urllib3.ProxyManager doesn't
        # call proxy_bypass() at request time is intrinsic to urllib3 —
        # we don't need to test urllib3 itself, only that we use it.
        assert isinstance(client._http, urllib3.ProxyManager)


# ---------------------------------------------------------------------------
# https-only validation
# ---------------------------------------------------------------------------

class TestHttpsOnly:

    @patch("core.sandbox.proxy.get_proxy")
    def test_http_url_rejected(self, mock_get_proxy):
        """EgressClient narrows _ALLOWED_SCHEMES to https only — the
        underlying proxy is HTTPS-CONNECT-only and http:// requests
        would forward-proxy and fail. Reject at the validator with a
        clear message instead."""
        mock_get_proxy.return_value = MagicMock(port=12345)
        client = EgressClient(["example.com"])
        with pytest.raises(HttpError, match="scheme 'http'"):
            client.get_json("http://example.com/api")


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

class TestDefaultClientWithHosts:

    @patch("core.sandbox.proxy.get_proxy")
    def test_with_hosts_returns_egress(self, mock_get_proxy):
        mock_get_proxy.return_value = MagicMock(port=1234)
        c = default_client(allowed_hosts=["api.osv.dev"])
        assert isinstance(c, EgressClient)
