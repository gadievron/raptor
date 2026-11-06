"""Dollar forecasts require a metered route, not API-equivalent token costs."""


import pytest

from core.llm import billing, config
from core.llm.client import _pinned_llm_config
from core.llm.config import LLMConfig, ModelConfig


@pytest.fixture(autouse=True)
def private_auth(tmp_path, monkeypatch):
    for name in ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN",
                 "AWS_BEARER_TOKEN_BEDROCK", "RAPTOR_LLM_SOCKET", "CLAUDE_CODE_USE_BEDROCK",
                 "CLAUDE_CODE_USE_VERTEX", "CLAUDE_CODE_USE_FOUNDRY", "CLAUDE_CODE_USE_MANTLE"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("RAPTOR_DIR", str(tmp_path))
    monkeypatch.setenv("RAPTOR_REGISTRY_HOME", str(tmp_path / "state"))
    monkeypatch.setattr(config, "bedrock_sigv4_intent", lambda: False)
    monkeypatch.setattr(config, "model_broker", lambda provider: None)
    monkeypatch.setattr(config, "_get_configured_models", lambda: [])


@pytest.mark.parametrize("provider", ["claudecode", "claudecode-resumable", "ollama"])
def test_subscription_and_local_routes_do_not_have_dollar_estimates(provider):
    assert not billing.model_uses_metered_api(ModelConfig(provider, "owned-model"))


@pytest.mark.parametrize("provider", ["anthropic", "openai", "gemini", "mistral"])
@pytest.mark.parametrize("key", [None, "test-api-key"])
def test_api_estimate_requires_configured_authentication(provider, key):
    assert billing.model_uses_metered_api(ModelConfig(provider, "owned-model", api_key=key)) == bool(key)


def test_unknown_route_does_not_claim_zero_or_estimated_dollars():
    assert not billing.model_uses_metered_api(None)


@pytest.mark.parametrize("signal", ["profile", "bearer", "sigv4"])
def test_bedrock_can_be_metered_without_a_local_api_key(monkeypatch, signal):
    model = ModelConfig("bedrock", "owned-model", aws_profile="owned-profile" if signal == "profile" else None)
    if signal == "bearer":
        monkeypatch.setenv("AWS_BEARER_TOKEN_BEDROCK", "test-bearer")
    elif signal == "sigv4":
        monkeypatch.setattr(config, "bedrock_sigv4_intent", lambda: True)
    assert billing.model_uses_metered_api(model)


def test_broker_held_credentials_keep_metered_estimates(monkeypatch, tmp_path):
    monkeypatch.setattr(config, "model_broker", lambda provider: "owned-broker")
    monkeypatch.setenv("RAPTOR_LLM_SOCKET", str(tmp_path / "never-connected.sock"))
    assert billing.model_uses_metered_api(ModelConfig("openai", "owned-model"))


@pytest.mark.parametrize("signal", ["ANTHROPIC_API_KEY", "CLAUDE_CODE_USE_BEDROCK", "CLAUDE_CODE_USE_VERTEX", "CLAUDE_CODE_USE_FOUNDRY", "CLAUDE_CODE_USE_MANTLE"])
def test_cloud_or_api_backed_cli_remains_metered(monkeypatch, signal):
    monkeypatch.setenv(signal, "test-value")
    assert billing.model_uses_metered_api(ModelConfig("claudecode", "owned-model"))


def test_subscription_oauth_is_not_mistaken_for_an_api_key(monkeypatch):
    monkeypatch.setenv("CLAUDE_CODE_OAUTH_TOKEN", "test-subscription-token")
    monkeypatch.setenv("ANTHROPIC_AUTH_TOKEN", "test-opaque-token")
    assert not billing.model_uses_metered_api(ModelConfig("claudecode", "owned-model"))


@pytest.mark.parametrize("routes,expected", [
    ([], True), (["default"], True), (["paid"], True), (["subscription"], False),
    (["paid", "subscription"], False), (["paid", "paid"], True),
])
def test_estimate_uses_requested_routes_and_offline_resolution(monkeypatch, routes, expected):
    calls = []
    def primary(**kwargs):
        calls.append(("default", kwargs))
        return ModelConfig("anthropic", "owned-api", api_key="test-key")
    def pinned(name, **kwargs):
        calls.append((name, kwargs))
        model = (ModelConfig("claudecode", "owned-cli") if name == "subscription"
                 else ModelConfig("anthropic", "owned-api", api_key="test-key"))
        return LLMConfig(primary_model=model, fallback_models=[])
    monkeypatch.setattr(billing, "_get_default_primary_model", primary)
    monkeypatch.setattr(billing, "_pinned_llm_config", pinned)
    assert billing.can_estimate_api_spend(routes) is expected
    assert calls
    assert all(kwargs == {"offline": True} for _, kwargs in calls)


def test_resolution_failure_suppresses_estimate_instead_of_blocking_run(monkeypatch):
    def fail(**kwargs):
        raise OSError("owned config unavailable")
    monkeypatch.setattr(billing, "_get_default_primary_model", fail)
    assert not billing.can_estimate_api_spend()


@pytest.mark.parametrize("name", ["ollama", "ollama/owned-model"])
def test_offline_pin_never_probes_local_model_server(monkeypatch, name):
    calls = []
    def probe():
        calls.append(None)
        raise AssertionError("availability probe reached")
    monkeypatch.setattr(config, "_PROVIDER_BUILDERS", {"ollama": probe})
    if name == "ollama":
        with pytest.raises(ValueError, match="not available"):
            _pinned_llm_config(name, offline=True)
    else:
        result = _pinned_llm_config(name, offline=True)
        assert result.primary_model.provider == "ollama"
    assert not calls
    with pytest.raises(AssertionError, match="availability probe reached"):
        _pinned_llm_config(name)
    assert calls == [None]
