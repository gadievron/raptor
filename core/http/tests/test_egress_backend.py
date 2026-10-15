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


# ---------------------------------------------------------------------------
# Seatbelt child behind the parent's egress proxy
# ---------------------------------------------------------------------------

class TestSeatbeltParentProxy:
    """A macOS seatbelt child under (deny network*) cannot bind an
    in-process proxy; EgressClient routes through the parent proxy the
    spawn layer named — only on darwin, only with the marker matching
    HTTPS_PROXY on a loopback URL, only when the kernel reports the
    process as sandboxed."""

    URL = "http://127.0.0.1:43210"

    @pytest.fixture
    def child_env(self, monkeypatch):
        from core.http import egress_backend
        from core.sandbox.seatbelt import PARENT_EGRESS_PROXY_ENV
        monkeypatch.setattr(egress_backend.sys, "platform", "darwin")
        monkeypatch.setattr(egress_backend, "_process_is_sandboxed",
                            lambda: True)
        monkeypatch.setenv(PARENT_EGRESS_PROXY_ENV, self.URL)
        monkeypatch.setenv("HTTPS_PROXY", self.URL)
        return monkeypatch

    @patch("core.sandbox.proxy.get_proxy")
    def test_routes_via_parent_without_starting_a_proxy(
            self, mock_get_proxy, child_env):
        client = EgressClient(["api.osv.dev"])
        mock_get_proxy.assert_not_called()
        assert isinstance(client._http, urllib3.ProxyManager)
        assert client._http.proxy.port == 43210
        assert client._http.proxy.host == "127.0.0.1"

    @pytest.mark.parametrize("mutate", [
        "not_darwin", "not_sandboxed", "no_marker",
        "marker_mismatch", "non_loopback",
    ])
    @patch("core.sandbox.proxy.get_proxy")
    def test_any_failed_condition_keeps_in_process_proxy(
            self, mock_get_proxy, child_env, mutate):
        from core.http import egress_backend
        from core.sandbox.seatbelt import PARENT_EGRESS_PROXY_ENV
        if mutate == "not_darwin":
            child_env.setattr(egress_backend.sys, "platform", "linux")
        elif mutate == "not_sandboxed":
            child_env.setattr(egress_backend, "_process_is_sandboxed",
                              lambda: False)
        elif mutate == "no_marker":
            child_env.delenv(PARENT_EGRESS_PROXY_ENV)
        elif mutate == "marker_mismatch":
            child_env.setenv("HTTPS_PROXY", "http://127.0.0.1:1")
        elif mutate == "non_loopback":
            child_env.setenv(PARENT_EGRESS_PROXY_ENV, "http://evil:43210")
            child_env.setenv("HTTPS_PROXY", "http://evil:43210")
        mock_get_proxy.return_value = MagicMock(port=1234)
        client = EgressClient(["api.osv.dev"])
        mock_get_proxy.assert_called_once()
        assert client._http.proxy.port == 1234
