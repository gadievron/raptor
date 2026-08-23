"""Tests for the pooled SDK HTTP transport (``core.llm.http_pool``).

httpx's default pool expires idle keepalive connections after 5
seconds — shorter than RAPTOR's typical inter-call gap, so every LLM
call re-established its connection (and, behind chained proxies, paid
CONNECT negotiation per hop). The factory pins a keepalive window
that outlives the gap and gives every SDK the same tunable pool.
"""

from __future__ import annotations

import sys
import types

import httpx
import pytest

from core.llm import http_pool

_KNOB_VARS = (
    "RAPTOR_HTTP_KEEPALIVE_S",
    "RAPTOR_HTTP_MAX_KEEPALIVE",
    "RAPTOR_HTTP_MAX_CONNECTIONS",
    "RAPTOR_HTTP2",
)


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for var in _KNOB_VARS:
        monkeypatch.delenv(var, raising=False)


class TestPoolLimits:

    def test_defaults_outlive_inter_call_gap(self):
        limits = http_pool.pool_limits()
        # The whole point: idle keepalive must comfortably exceed
        # httpx's 5s default, which is shorter than the think-time
        # gap between RAPTOR LLM calls.
        assert limits.keepalive_expiry == 60.0
        assert limits.max_keepalive_connections == 20
        assert limits.max_connections == 100

    def test_env_overrides(self, monkeypatch):
        monkeypatch.setenv("RAPTOR_HTTP_KEEPALIVE_S", "120")
        monkeypatch.setenv("RAPTOR_HTTP_MAX_KEEPALIVE", "8")
        monkeypatch.setenv("RAPTOR_HTTP_MAX_CONNECTIONS", "16")
        limits = http_pool.pool_limits()
        assert limits.keepalive_expiry == 120.0
        assert limits.max_keepalive_connections == 8
        assert limits.max_connections == 16

    @pytest.mark.parametrize("bad", ["", "abc", "0", "-5"])
    def test_invalid_env_falls_back(self, monkeypatch, bad):
        monkeypatch.setenv("RAPTOR_HTTP_KEEPALIVE_S", bad)
        limits = http_pool.pool_limits()
        assert limits.keepalive_expiry == 60.0


class TestSdkHttpClient:

    def test_returns_httpx_client_with_pool_limits(self):
        client = http_pool.sdk_http_client(30)
        try:
            assert isinstance(client, httpx.Client)
            assert client.timeout.read == 30.0
        finally:
            client.close()

    def test_trust_env_passthrough(self):
        trusted = http_pool.sdk_http_client(10)
        pinned = http_pool.sdk_http_client(10, trust_env=False)
        try:
            assert trusted.trust_env is True
            assert pinned.trust_env is False
        finally:
            trusted.close()
            pinned.close()


class TestHttp2Gate:
    """HTTP/2 is opt-in AND conditional on the h2 stack being
    installed — httpx raises at client construction otherwise."""

    @pytest.fixture(autouse=True)
    def _reset_warn_flag(self, monkeypatch):
        monkeypatch.setattr(http_pool, "_http2_missing_warned", False)

    def test_off_by_default(self):
        assert http_pool.http2_enabled() is False

    @pytest.mark.parametrize("value", ["0", "false", "no", "off", ""])
    def test_non_truthy_values_stay_off(self, monkeypatch, value):
        monkeypatch.setenv("RAPTOR_HTTP2", value)
        assert http_pool.http2_enabled() is False

    def test_opted_in_with_h2_installed(self, monkeypatch):
        monkeypatch.setenv("RAPTOR_HTTP2", "1")
        monkeypatch.setattr(
            http_pool.importlib.util, "find_spec",
            lambda name: object() if name == "h2" else None,
        )
        assert http_pool.http2_enabled() is True

    def test_opted_in_without_h2_warns_once_and_stays_http1(
        self, monkeypatch, caplog,
    ):
        monkeypatch.setenv("RAPTOR_HTTP2", "1")
        monkeypatch.setattr(
            http_pool.importlib.util, "find_spec", lambda name: None,
        )
        with caplog.at_level("WARNING", logger="core.llm.http_pool"):
            assert http_pool.http2_enabled() is False
            assert http_pool.http2_enabled() is False
        warnings = [r for r in caplog.records if "h2" in r.getMessage()]
        assert len(warnings) == 1

    def test_client_construction_honours_gate(self, monkeypatch):
        """With the gate closed the client must be constructible even
        when h2 is absent — the whole point of gating."""
        monkeypatch.setenv("RAPTOR_HTTP2", "1")
        monkeypatch.setattr(
            http_pool.importlib.util, "find_spec", lambda name: None,
        )
        client = http_pool.sdk_http_client(10)
        client.close()


class TestProviderWiring:
    """The provider constructors must hand the SDK the pooled client
    on their env-direct (non-dispatcher) paths."""

    @pytest.fixture(autouse=True)
    def _no_dispatcher(self, monkeypatch):
        monkeypatch.delenv("RAPTOR_LLM_SOCKET", raising=False)

    def _spy_factory(self, monkeypatch):
        built = []
        real = http_pool.sdk_http_client

        def spy(timeout, **kwargs):
            client = real(timeout, **kwargs)
            built.append((timeout, kwargs, client))
            return client

        monkeypatch.setattr(http_pool, "sdk_http_client", spy)
        return built

    def test_anthropic_direct_uses_pooled_client(self, monkeypatch):
        anthropic_mod = pytest.importorskip("anthropic")
        del anthropic_mod
        from core.llm.config import ModelConfig
        from core.llm.providers import AnthropicProvider

        built = self._spy_factory(monkeypatch)
        provider = AnthropicProvider(ModelConfig(
            provider="anthropic", model_name="claude-test",
            api_key="k", timeout=33,
        ))
        assert len(built) == 1
        timeout, _, client = built[0]
        assert timeout == 33
        assert provider.client._client is client

    def test_openai_remote_keeps_trust_env(self, monkeypatch):
        pytest.importorskip("openai")
        from core.llm.config import ModelConfig
        from core.llm.providers import OpenAICompatibleProvider

        built = self._spy_factory(monkeypatch)
        OpenAICompatibleProvider(ModelConfig(
            provider="openai", model_name="gpt-test",
            api_key="k", timeout=20,
        ))
        assert len(built) == 1
        _, kwargs, client = built[0]
        assert kwargs == {"trust_env": True}
        assert client.trust_env is True

    def test_openai_loopback_pins_trust_env_false(self, monkeypatch):
        pytest.importorskip("openai")
        from core.llm.config import ModelConfig
        from core.llm.providers import OpenAICompatibleProvider

        built = self._spy_factory(monkeypatch)
        OpenAICompatibleProvider(ModelConfig(
            provider="ollama", model_name="llama-test",
            api_base="http://localhost:11434/v1", timeout=20,
        ))
        assert len(built) == 1
        _, kwargs, client = built[0]
        assert kwargs == {"trust_env": False}
        assert client.trust_env is False


class TestGeminiHttpOptions:
    """Feature detection for google-genai's httpx_client injection
    point — pooled when the field exists, SDK-default otherwise."""

    def test_none_when_sdk_absent(self, monkeypatch):
        monkeypatch.setitem(sys.modules, "google", None)
        from core.llm.providers import _pooled_gemini_http_options
        assert _pooled_gemini_http_options(30) is None

    def _stub_genai_types(self, monkeypatch, fields):
        class HttpOptions:
            model_fields = dict.fromkeys(fields)

            def __init__(self, **kwargs):
                self.kwargs = kwargs

        genai_types = types.ModuleType("google.genai.types")
        genai_types.HttpOptions = HttpOptions
        genai = types.ModuleType("google.genai")
        genai.types = genai_types
        google = types.ModuleType("google")
        google.genai = genai
        monkeypatch.setitem(sys.modules, "google", google)
        monkeypatch.setitem(sys.modules, "google.genai", genai)
        monkeypatch.setitem(sys.modules, "google.genai.types", genai_types)
        return HttpOptions

    def test_none_when_field_missing(self, monkeypatch):
        self._stub_genai_types(monkeypatch, fields=("base_url",))
        from core.llm.providers import _pooled_gemini_http_options
        assert _pooled_gemini_http_options(30) is None

    def test_pooled_client_when_field_present(self, monkeypatch):
        HttpOptions = self._stub_genai_types(
            monkeypatch, fields=("base_url", "httpx_client"),
        )
        from core.llm.providers import _pooled_gemini_http_options
        opts = _pooled_gemini_http_options(30)
        assert isinstance(opts, HttpOptions)
        client = opts.kwargs["httpx_client"]
        try:
            assert isinstance(client, httpx.Client)
        finally:
            client.close()


class TestNegotiatedProtocolTelemetry:
    """RAPTOR_HTTP2 requested HTTP/2, but nothing recorded what ALPN
    actually negotiated — h2 service could not be proven from run
    artifacts. Every pooled client installs a response hook that
    feeds a process-wide protocol registry the telemetry reads."""

    @pytest.fixture(autouse=True)
    def _fresh_registry(self, monkeypatch):
        monkeypatch.setattr(http_pool, "_last_http_version", None)
        monkeypatch.setattr(http_pool, "_protocol_counts", {})

    def test_note_normalizes_h1_h2(self):
        assert http_pool.last_http_version() is None
        http_pool.note_http_version("HTTP/2")
        assert http_pool.last_http_version() == "h2"
        http_pool.note_http_version("HTTP/1.1")
        assert http_pool.last_http_version() == "h1"
        assert http_pool.protocol_counts() == {"h2": 1, "h1": 1}

    def test_unknown_version_kept_lowercased(self):
        http_pool.note_http_version("HTTP/3")
        assert http_pool.last_http_version() == "http/3"
        http_pool.note_http_version("")
        assert http_pool.last_http_version() == "unknown"

    def test_sdk_client_installs_response_hook(self):
        client = http_pool.sdk_http_client(timeout=5.0)
        try:
            assert http_pool._response_hook in client.event_hooks["response"]
        finally:
            client.close()

    def test_response_feeds_registry(self):
        transport = httpx.MockTransport(
            lambda request: httpx.Response(
                200, extensions={"http_version": b"HTTP/1.1"},
            ),
        )
        with httpx.Client(
            transport=transport,
            event_hooks=http_pool.response_event_hooks(),
        ) as client:
            client.get("http://unit.test/x")
        assert http_pool.last_http_version() == "h1"
        assert http_pool.protocol_counts() == {"h1": 1}

    def test_client_emit_sites_carry_http_version(self):
        """Every per-attempt telemetry emit in the LLM client attaches
        the negotiated protocol (source-level wiring check: 2 ok sites
        + 2 attempt_failed sites)."""
        from pathlib import Path

        import core.llm.client as client_mod

        src = Path(client_mod.__file__).read_text()
        assert src.count("http_version=_transport_http_version()") == 4

    def test_transport_http_version_helper(self):
        from core.llm.client import _transport_http_version

        assert _transport_http_version() is None
        http_pool.note_http_version("HTTP/2")
        assert _transport_http_version() == "h2"
