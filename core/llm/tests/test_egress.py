"""Tests for ``core.llm.egress`` — LLM SDK egress via in-process proxy.

Two layers:
  * ``derive_allowlist`` — pure function over LLMConfig shape. Easy to
    test in isolation.
  * ``enable_llm_egress`` — mutates env + spawns proxy singleton.
    Tested with a stub proxy (avoids actually opening a port) plus
    explicit env reset between tests so the global state doesn't
    leak across the suite.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

try:
    sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
except IndexError:                                      # pragma: no cover
    pass

from core.llm import egress
from core.llm.config import LLMConfig, ModelConfig


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_egress_state(monkeypatch):
    """Reset module-level ``_enabled`` flag and any env vars we mutate
    between tests so each test sees a deterministic starting state."""
    egress._reset_for_tests()
    monkeypatch.delenv("HTTPS_PROXY", raising=False)
    monkeypatch.delenv("https_proxy", raising=False)
    monkeypatch.delenv("NO_PROXY", raising=False)
    monkeypatch.delenv("no_proxy", raising=False)
    yield
    egress._reset_for_tests()


@pytest.fixture
def stub_proxy(monkeypatch):
    """Replace ``core.sandbox.proxy.get_proxy`` with a stub that
    records the allowlist passed in and returns an object with a
    fixed ``.port``. Avoids spinning up a real TCP listener for tests
    that don't need it."""
    seen_calls = []

    class _StubProxy:
        port = 51234

    def stub_get_proxy(allowed_hosts):
        seen_calls.append(list(allowed_hosts))
        return _StubProxy()

    import core.sandbox.proxy as proxy_mod
    monkeypatch.setattr(proxy_mod, "get_proxy", stub_get_proxy)
    yield seen_calls


def _model(provider: str = "anthropic", model_name: str = "x",
           api_base: str = None) -> ModelConfig:
    return ModelConfig(
        provider=provider,
        model_name=model_name,
        max_context=200000,
        api_key="k",
        api_base=api_base,
    )


def _config(primary=None, fallbacks=None, specialized=None) -> LLMConfig:
    """Bypass autodetect — we craft the config explicitly."""
    cfg = LLMConfig.__new__(LLMConfig)
    cfg.primary_model = primary
    cfg.fallback_models = fallbacks or []
    cfg.specialized_models = specialized or {}
    return cfg


# ---------------------------------------------------------------------------
# derive_allowlist — pure function tests
# ---------------------------------------------------------------------------


class TestDeriveAllowlist:
    def test_empty_config_returns_empty(self):
        cfg = _config()
        assert egress.derive_allowlist(cfg) == set()

    def test_anthropic_default_uses_known_default(self):
        cfg = _config(primary=_model(provider="anthropic"))
        assert egress.derive_allowlist(cfg) == {"api.anthropic.com"}

    def test_openai_default_uses_provider_endpoints(self):
        cfg = _config(primary=_model(provider="openai"))
        assert "api.openai.com" in egress.derive_allowlist(cfg)

    def test_operator_api_base_overrides_default(self):
        """Operator routes Anthropic via internal gateway: the
        operator's hostname lands in the allowlist; the
        ``api.anthropic.com`` default does NOT (because the operator
        explicitly didn't go there)."""
        cfg = _config(primary=_model(
            provider="anthropic",
            api_base="https://gateway.internal.corp/anthropic/v1",
        ))
        hosts = egress.derive_allowlist(cfg)
        assert "gateway.internal.corp" in hosts
        assert "api.anthropic.com" not in hosts

    def test_multi_provider_panel(self):
        """A multi-model dispatch with primary + fallback + specialized
        across providers contributes every distinct hostname."""
        cfg = _config(
            primary=_model(provider="anthropic"),
            fallbacks=[_model(provider="openai", model_name="gpt-x")],
            specialized={
                "verdict_binary": _model(
                    provider="mistral", model_name="mistral-fast",
                ),
            },
        )
        hosts = egress.derive_allowlist(cfg)
        assert "api.anthropic.com" in hosts
        assert "api.openai.com" in hosts
        assert "api.mistral.ai" in hosts

    def test_ollama_only_localhost(self):
        cfg = _config(primary=_model(
            provider="ollama",
            model_name="llama3",
            api_base="http://localhost:11434/v1",
        ))
        # localhost SHOULD show up here — derive_allowlist is pure
        # discovery; the loopback bypass happens in enable_llm_egress.
        hosts = egress.derive_allowlist(cfg)
        assert "localhost" in hosts

    def test_unknown_provider_no_endpoint(self):
        """A provider with no ``api_base`` and no entry in
        PROVIDER_ENDPOINTS / KNOWN_DEFAULTS contributes nothing —
        rather than crashing the egress wiring."""
        cfg = _config(primary=_model(
            provider="totally-made-up", model_name="x",
        ))
        assert egress.derive_allowlist(cfg) == set()

    def test_malformed_api_base_skipped(self):
        cfg = _config(primary=_model(
            provider="anthropic",
            api_base="not a url",
        ))
        # Should not crash; falls back to the configured provider's
        # default if api_base parses to no host.
        hosts = egress.derive_allowlist(cfg)
        # urlparse on "not a url" yields no hostname; we silently skip
        # this entry rather than substituting the default.
        assert "api.anthropic.com" not in hosts

    def test_api_base_with_port_extracts_host_only(self):
        cfg = _config(primary=_model(
            provider="openai",
            api_base="https://gateway.corp:8443/v1",
        ))
        # Hostname only, no port
        assert egress.derive_allowlist(cfg) == {"gateway.corp"}


# ---------------------------------------------------------------------------
# enable_llm_egress — env mutation + idempotency tests
# ---------------------------------------------------------------------------


class TestEnableLLMEgress:
    def test_sets_https_proxy_env_var(self, stub_proxy):
        cfg = _config(primary=_model(provider="anthropic"))
        egress.enable_llm_egress(cfg)
        assert os.environ["HTTPS_PROXY"] == "http://127.0.0.1:51234"
        assert os.environ["https_proxy"] == "http://127.0.0.1:51234"

    def test_appends_loopback_to_no_proxy(self, stub_proxy):
        cfg = _config(primary=_model(provider="anthropic"))
        egress.enable_llm_egress(cfg)
        np = os.environ["NO_PROXY"]
        assert "localhost" in np
        assert "127.0.0.1" in np

    def test_preserves_operator_no_proxy_entries(self, stub_proxy, monkeypatch):
        monkeypatch.setenv("NO_PROXY", "internal.corp,*.test")
        cfg = _config(primary=_model(provider="anthropic"))
        egress.enable_llm_egress(cfg)
        np = os.environ["NO_PROXY"]
        assert "internal.corp" in np
        assert "*.test" in np
        assert "localhost" in np
        # Order: operator entries first
        parts = np.split(",")
        assert parts.index("internal.corp") < parts.index("localhost")

    def test_no_double_localhost_when_already_present(self, stub_proxy, monkeypatch):
        monkeypatch.setenv("NO_PROXY", "localhost,internal.corp")
        cfg = _config(primary=_model(provider="anthropic"))
        egress.enable_llm_egress(cfg)
        np = os.environ["NO_PROXY"]
        # Each entry exactly once
        assert np.count("localhost") == 1

    def test_empty_allowlist_no_op(self, stub_proxy, monkeypatch):
        """No models configured (autodetect-empty) → no env mutation,
        no proxy bring-up. Operator who runs in CC-only or no-LLM
        modes shouldn't see HTTPS_PROXY appear in their environment."""
        cfg = _config()  # nothing configured
        egress.enable_llm_egress(cfg)
        assert "HTTPS_PROXY" not in os.environ
        assert stub_proxy == []  # get_proxy not invoked

    def test_ollama_only_no_op(self, stub_proxy):
        """Ollama-only setups have a single localhost host — no remote
        endpoints, so the chokepoint is meaningless. Skip the env
        mutation entirely so the SDK talks direct to localhost."""
        cfg = _config(primary=_model(
            provider="ollama",
            model_name="llama3",
            api_base="http://localhost:11434/v1",
        ))
        egress.enable_llm_egress(cfg)
        assert "HTTPS_PROXY" not in os.environ
        assert stub_proxy == []

    def test_idempotent_env_not_re_overwritten(self, stub_proxy):
        """Two LLMClient constructions in the same process must not
        re-overwrite HTTPS_PROXY (which by now points at our proxy).
        Subsequent calls only union the allowlist."""
        cfg = _config(primary=_model(provider="anthropic"))
        egress.enable_llm_egress(cfg)
        first_value = os.environ["HTTPS_PROXY"]

        # Mutate the env to detect a second overwrite if it happens.
        os.environ["HTTPS_PROXY"] = "http://sentinel:99"
        egress.enable_llm_egress(cfg)
        assert os.environ["HTTPS_PROXY"] == "http://sentinel:99", (
            "second call should not overwrite HTTPS_PROXY"
        )

    def test_idempotent_unions_allowlist(self, stub_proxy):
        """Second call with a wider config adds new hosts to the
        existing in-process proxy via ``get_proxy``'s union semantics."""
        cfg1 = _config(primary=_model(provider="anthropic"))
        cfg2 = _config(primary=_model(provider="openai"))
        egress.enable_llm_egress(cfg1)
        egress.enable_llm_egress(cfg2)
        assert len(stub_proxy) == 2
        assert "api.anthropic.com" in stub_proxy[0]
        assert "api.openai.com" in stub_proxy[1]

    def test_proxy_brought_up_before_env_overwrite(self, monkeypatch):
        """Critical ordering: ``get_proxy`` must be called BEFORE we
        overwrite HTTPS_PROXY, so the proxy reads the operator's
        upstream chain (corporate proxy autodetect) rather than its
        own self-pointer.

        Asserted by recording the value HTTPS_PROXY had at the moment
        ``get_proxy`` was invoked."""
        monkeypatch.setenv("HTTPS_PROXY", "http://corp:8080")

        captured = {}

        class _StubProxy:
            port = 51234

        def stub_get_proxy(allowed_hosts):
            captured["env_at_call"] = os.environ.get("HTTPS_PROXY")
            return _StubProxy()

        import core.sandbox.proxy as proxy_mod
        monkeypatch.setattr(proxy_mod, "get_proxy", stub_get_proxy)

        cfg = _config(primary=_model(provider="anthropic"))
        egress.enable_llm_egress(cfg)

        assert captured["env_at_call"] == "http://corp:8080", (
            "get_proxy must see the operator's HTTPS_PROXY for "
            "upstream chain autodetect; saw "
            f"{captured.get('env_at_call')!r} instead"
        )
        # And after the call, env is overwritten.
        assert os.environ["HTTPS_PROXY"] == "http://127.0.0.1:51234"

    def test_loopback_excluded_from_proxy_allowlist(self, stub_proxy):
        """A multi-provider config that includes both remote hosts
        AND localhost (e.g. Ollama fallback) must NOT register
        localhost on the chokepoint allowlist — that would let an
        attacker register a localhost service and reach it via the
        chokepoint, defeating the isolation."""
        cfg = _config(
            primary=_model(provider="anthropic"),
            fallbacks=[_model(
                provider="ollama",
                model_name="llama",
                api_base="http://localhost:11434/v1",
            )],
        )
        egress.enable_llm_egress(cfg)
        assert stub_proxy, "get_proxy should have been called"
        registered = set(stub_proxy[0])
        assert "api.anthropic.com" in registered
        assert "localhost" not in registered
        assert "127.0.0.1" not in registered


# ---------------------------------------------------------------------------
# Subprocess-strip layer separation
# ---------------------------------------------------------------------------


class TestSubprocessStripStillWorks:
    """The subprocess-env strip in get_safe_env() must continue to
    remove HTTPS_PROXY even when we set it in the parent process —
    they're at different layers and must not interfere."""

    def test_get_safe_env_strips_https_proxy(self, stub_proxy):
        from core.config import RaptorConfig

        cfg = _config(primary=_model(provider="anthropic"))
        egress.enable_llm_egress(cfg)
        assert "HTTPS_PROXY" in os.environ  # Sanity: parent has it

        env = RaptorConfig.get_safe_env()
        assert "HTTPS_PROXY" not in env
        assert "https_proxy" not in env
