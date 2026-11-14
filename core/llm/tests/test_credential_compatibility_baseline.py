"""Characterize current auth/transport boundaries before catalog migration.

These assertions capture current account and transport selection, including
known differences between direct SDK calls and dispatcher authentication.
No provider requests, credential discovery or real operator config are used.
"""

from __future__ import annotations

import json
import os

import pytest

from core.llm.config import ModelConfig, _model_config_from_entry
from core.llm.dispatcher.auth import CredentialStore, seed_from_config
from core.llm.model_brokers import MODEL_BROKERS


@pytest.fixture
def isolated_credentials(monkeypatch, tmp_path):
    from core.config import RaptorConfig

    for name in RaptorConfig.LLM_API_KEY_VARS:
        monkeypatch.delenv(name, raising=False)
    for name in RaptorConfig.LLM_ROUTING_ENV_VARS:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("RAPTOR_CONFIG", str(tmp_path / "models.json"))
    monkeypatch.delenv("RAPTOR_LLM_TOKEN_FD", raising=False)
    return tmp_path / "models.json"


def _write_models(path, entries):
    path.write_text(json.dumps({"models": entries}))
    path.chmod(0o600)


@pytest.mark.parametrize("provider,env_name", [
    ("anthropic", "ANTHROPIC_API_KEY"),
    ("openai", "OPENAI_API_KEY"),
    ("gemini", "GEMINI_API_KEY"),
])
def test_inline_and_environment_choose_different_accounts_on_existing_paths(
    isolated_credentials, monkeypatch, provider, env_name,
):
    entry = {"provider": provider, "model": "fixture-model", "api_key": "inline-account"}
    _write_models(isolated_credentials, [entry])
    monkeypatch.setenv(env_name, "environment-account")

    direct = _model_config_from_entry(entry)
    store = CredentialStore()
    seed_from_config(store)

    assert direct.api_key == "inline-account"
    assert store.get(provider) == "environment-account"
    # A later fallback cannot reconstruct the original environment from getenv.
    assert env_name not in os.environ


@pytest.mark.parametrize("provider", ["anthropic", "openai", "gemini"])
def test_duplicate_entries_keep_direct_accounts_but_proxy_seeds_only_first(
    isolated_credentials, provider,
):
    entries = [
        {"provider": provider, "model": "fixture-model", "role": role, "api_key": key}
        for role, key in [("analysis", "first-account"), ("fallback", "second-account")]
    ]
    _write_models(isolated_credentials, entries)

    direct = [_model_config_from_entry(entry) for entry in entries]
    store = CredentialStore()
    seed_from_config(store)

    assert [config.api_key for config in direct] == ["first-account", "second-account"]
    assert store.get(provider) == "first-account"


@pytest.fixture
def sdk_routes(monkeypatch, isolated_credentials):
    pytest.importorskip("openai")
    from core.llm import config as config_module
    from core.llm import providers
    from core.llm.dispatcher import client

    # Construct real SDK clients/transports, without opening a socket or token FD.
    monkeypatch.setenv("RAPTOR_LLM_SOCKET", "/unused-compatibility-baseline.sock")
    monkeypatch.setattr(
        client, "_resolve_socket_and_token",
        lambda socket_path, token: ("/unused-compatibility-baseline.sock", "fixture-token"),
    )
    monkeypatch.setattr(providers, "OPENAI_SDK_AVAILABLE", True)
    monkeypatch.setattr(config_module, "_sdk_available", lambda name: name == "OPENAI_SDK_AVAILABLE")
    return providers


@pytest.mark.parametrize("api_base,expected_base,expected_key", [
    (None, "http://_/openai/v1", "dummy-not-used"),
    ("https://api.openai.com/v1", "https://api.openai.com/v1", "worker-account"),
    ("https://gateway.example.test/v1", "https://gateway.example.test/v1", "worker-account"),
])
def test_openai_proxy_depends_on_absent_base_not_standard_endpoint(
    sdk_routes, api_base, expected_base, expected_key,
):
    config = ModelConfig(
        provider="openai", model_name="fixture-model",
        api_key="worker-account", api_base=api_base,
    )
    provider = sdk_routes.create_provider(config)
    try:
        assert str(provider.client.base_url).rstrip("/") == expected_base
        assert provider.client.api_key == expected_key
    finally:
        provider.client.close()


@pytest.mark.parametrize("source", ["file-entry", "environment-builder"])
def test_normal_openai_resolution_materializes_base_and_bypasses_proxy(
    sdk_routes, monkeypatch, source,
):
    if source == "file-entry":
        config = _model_config_from_entry({
            "provider": "openai", "model": "fixture-model", "api_key": "worker-account",
        })
    else:
        from core.llm.config import _build_openai_compat_config
        monkeypatch.setenv("OPENAI_API_KEY", "worker-account")
        config = _build_openai_compat_config("openai")
    assert config is not None
    provider = sdk_routes.create_provider(config)
    try:
        assert str(provider.client.base_url).rstrip("/") == "https://api.openai.com/v1"
        assert provider.client.api_key == "worker-account"
    finally:
        provider.client.close()


@pytest.mark.parametrize("name,base", [
    ("anthropic", "https://api.anthropic.com/v1"),
    ("gemini", "https://generativelanguage.googleapis.com/v1beta/openai"),
    ("mistral", "https://api.mistral.ai/v1"),
    ("cohere", "https://cohere.example.test/v1"),
    ("azure_openai", "https://azure.example.test/v1"),
    ("ollama", "http://localhost:11434/v1"),
])
def test_compatibility_sdk_paths_remain_direct_with_proxy_present(
    sdk_routes, monkeypatch, name, base,
):
    monkeypatch.setattr(sdk_routes, "ANTHROPIC_SDK_AVAILABLE", False)
    monkeypatch.setattr(sdk_routes, "GENAI_SDK_AVAILABLE", False)
    config = _model_config_from_entry({
        "provider": name, "model": "fixture-model",
        "api_base": base, "api_key": "worker-account",
    })
    provider = sdk_routes.create_provider(config)
    try:
        assert str(provider.client.base_url).rstrip("/") == base
        assert provider.client.api_key == "worker-account"
    finally:
        provider.client.close()


@pytest.mark.parametrize(
    "broker", [broker for broker in MODEL_BROKERS if broker.protocol == "openai"],
    ids=lambda broker: broker.name,
)
def test_registered_sdk_broker_uses_parent_route_not_entry_key(sdk_routes, broker):
    config = _model_config_from_entry({
        "provider": broker.name, "model": "fixture-model", "api_key": "unused-worker-key",
    })
    provider = sdk_routes.create_provider(config)
    try:
        assert str(provider.client.base_url).rstrip("/") == (
            f"http://_/{broker.name}{broker.api_path}"
        )
        assert provider.client.api_key == "dummy-not-used"
    finally:
        provider.client.close()


def test_raw_http_broker_is_not_an_sdk_route(sdk_routes):
    raw = next(broker for broker in MODEL_BROKERS if broker.protocol == "http")
    config = _model_config_from_entry({"provider": raw.name, "model": "fixture-model"})
    with pytest.raises(ValueError, match="native HTTP API"):
        sdk_routes.create_provider(config)
