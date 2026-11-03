"""Registry validation and wiring across credential/routing boundaries."""

import json
import os
import runpy
import subprocess
import sys
from dataclasses import asdict, replace
from pathlib import Path
from unittest.mock import Mock

import pytest

import core.llm.model_brokers as broker_registry
from core.config import RaptorConfig
from core.llm.model_brokers import MODEL_BROKERS, ModelBroker, load_model_brokers, read_broker_key

_EXAMPLE_BROKER = ModelBroker(
    name="examplebroker", upstream_base_url="https://example.invalid", api_path="/v1",
)
_OPENROUTER = next(b for b in MODEL_BROKERS if b.name == "openrouter")


@pytest.mark.parametrize("first_import", ["core.config", "core.security.llm_family",
                                        "core.llm.model_brokers"])
def test_registry_imports_without_sdk_initialisation_or_cycles(first_import):
    program = f'''
import importlib
import sys
importlib.import_module({first_import!r})
import core.config
import core.llm.model_brokers
assert "core.llm.providers" not in sys.modules
assert "core.llm.client" not in sys.modules
from core.llm import LLMClient, ModelConfig, create_provider
assert callable(create_provider)
assert LLMClient.__name__ == "LLMClient"
assert ModelConfig.__name__ == "ModelConfig"
'''
    result = subprocess.run(
        [sys.executable, "-c", program],
        cwd=Path(__file__).resolve().parents[4],
        env=RaptorConfig.get_safe_env(),
        capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0, result.stderr


def test_mistral_is_a_direct_provider(monkeypatch):
    from core.llm.dispatcher.auth import CredentialStore, build_rules
    from core.llm.dispatcher.server import _DIRECT_PATH_PREFIXES, _AGGREGATOR_PATH_PREFIXES
    from core.security.llm_family import family_of

    assert "mistral" not in {broker.name for broker in MODEL_BROKERS}
    assert _DIRECT_PATH_PREFIXES["/mistral/"] == "mistral"
    assert "/mistral/" not in _AGGREGATOR_PATH_PREFIXES
    assert "MISTRAL_API_KEY" in RaptorConfig.LLM_API_KEY_VARS
    monkeypatch.setenv("MISTRAL_API_KEY", "mistral-test-key")
    rule = build_rules(CredentialStore())["mistral"]
    assert rule.upstream_base_url == "https://api.mistral.ai"
    assert rule.inject_headers() == {"Authorization": "Bearer mistral-test-key"}
    assert family_of("mistral/mistral-large-latest") == "mistral"


def test_bundled_catalog_is_valid():
    path = Path(broker_registry.__file__).with_name("registry.json")
    assert load_model_brokers(path) == MODEL_BROKERS


def test_registry_accepts_config_comments_and_preserves_urls(tmp_path):
    path = tmp_path / "registry.json"
    path.write_text('''// Broker catalog
{
  "version": 1, # config dialect
  "brokers": [{
    "name": "example", // EXAMPLE_API_KEY
    "upstream_base_url": "https://example.invalid", # URL must survive
    "api_path": "/v1"
  }]
}
''')
    broker, = load_model_brokers(path)
    assert broker.api_base == "https://example.invalid/v1"


def test_api_token_credential_name():
    broker = replace(_EXAMPLE_BROKER, credential_suffix="API_TOKEN")
    assert broker.api_key_env == "EXAMPLEBROKER_API_TOKEN"
    assert broker.auth_scheme == "Bearer"


@pytest.mark.parametrize("suffix", ["API_KEY", "API_TOKEN"])
@pytest.mark.parametrize("scheme", ["Bearer", "Token"])
def test_credential_suffix_and_auth_are_independent(tmp_path, monkeypatch, suffix, scheme):
    from core.llm.dispatcher import auth

    entry = asdict(replace(_EXAMPLE_BROKER, credential_suffix=suffix, auth_scheme=scheme))
    path = tmp_path / "registry.json"
    path.write_text(json.dumps({"version": 1, "brokers": [entry]}))
    broker, = load_model_brokers(path)
    assert broker.api_key_env == f"EXAMPLEBROKER_{suffix}"
    monkeypatch.setattr(auth, "MODEL_BROKERS", (broker,))
    monkeypatch.setenv(f"EXAMPLEBROKER_{suffix}", "test-secret")
    rule = auth.build_rules(auth.CredentialStore())[broker.name]
    assert rule.inject_headers() == {"Authorization": f"{scheme} test-secret"}


def test_credential_policy_overrides_safe_env_prefix(monkeypatch):
    name = "LC_BROKER_API_KEY"
    monkeypatch.setenv(name, "secret")
    monkeypatch.setattr(RaptorConfig, "LLM_API_KEY_VARS", (*RaptorConfig.LLM_API_KEY_VARS, name))
    assert name not in RaptorConfig.get_safe_env()


@pytest.mark.parametrize("broker", MODEL_BROKERS, ids=lambda b: b.name)
def test_broker_consumers(broker, monkeypatch):
    from core.llm.dispatcher.auth import CredentialStore, build_rules
    from core.llm.dispatcher.server import _AGGREGATOR_PATH_PREFIXES
    from core.security.llm_family import _AGGREGATOR_PREFIXES, family_of

    monkeypatch.setenv(broker.api_key_env, "registry-test-key")
    creds = CredentialStore()
    assert creds.get(broker.name) == "registry-test-key"
    # Secrets are consumed by the parent, never inherited by workers.
    assert broker.api_key_env not in os.environ
    assert broker.api_key_env in RaptorConfig.LLM_API_KEY_VARS
    assert broker.api_key_env not in RaptorConfig.get_safe_env()
    rule = build_rules(creds)[broker.name]
    assert rule.upstream_base_url == broker.upstream_base_url
    assert rule.inject_headers() == {"Authorization": f"{broker.auth_scheme} registry-test-key"}
    assert _AGGREGATOR_PATH_PREFIXES[f"/{broker.name}/"] == broker.name
    assert f"{broker.name}/" in _AGGREGATOR_PREFIXES
    assert family_of(f"{broker.name}/anthropic/claude-opus-4-6") == "anthropic"


def test_new_broker_builds_rule_from_json(tmp_path, monkeypatch):
    from core.llm.dispatcher import auth

    entry = replace(_EXAMPLE_BROKER, name="examplebroker",
                    upstream_base_url="https://example.invalid")
    path = tmp_path / "brokers.json"
    path.write_text(json.dumps({"version": 1, "brokers": [asdict(entry)]}))
    monkeypatch.setattr(auth, "MODEL_BROKERS", load_model_brokers(path))
    monkeypatch.setenv(entry.api_key_env, "example-key")
    rule = auth.build_rules(auth.CredentialStore())[entry.name]
    assert rule.upstream_base_url == entry.upstream_base_url
    assert rule.inject_headers() == {"Authorization": "Bearer example-key"}


def test_json_cannot_claim_a_python_environment_variable(tmp_path, monkeypatch):
    name = "PYTHON_FEATURE_API_KEY"
    monkeypatch.setenv(name, "python-owned")
    entry = asdict(_EXAMPLE_BROKER)
    entry["api_key_env"] = name
    path = tmp_path / "registry.json"
    path.write_text(json.dumps({"version": 1, "brokers": [entry]}))
    with pytest.raises(ValueError, match="allowed fields"):
        load_model_brokers(path)
    assert os.environ[name] == "python-owned"


def test_runtime_rejects_claiming_nvd_credential(tmp_path, monkeypatch):
    monkeypatch.setenv("NVD_API_KEY", "python-owned-review-key")
    entry = asdict(replace(_EXAMPLE_BROKER, name="nvd"))
    path = tmp_path / "registry.json"
    path.write_text(json.dumps({"version": 1, "brokers": [entry]}))
    with pytest.raises(ValueError, match="Python-owned.*NVD_API_KEY"):
        load_model_brokers(path)
    # Defence in depth: construction without loading JSON cannot consume it.
    with pytest.raises(ValueError, match="Python-owned.*NVD_API_KEY"):
        read_broker_key(ModelBroker(**entry), consume=True)
    assert os.environ["NVD_API_KEY"] == "python-owned-review-key"


def test_runtime_reserves_new_python_declarations_without_importing_them(tmp_path, monkeypatch):
    from core.llm.model_brokers._env_ownership import python_credential_names

    source_root = tmp_path / "application"
    source_root.joinpath("core").mkdir(parents=True)
    source_root.joinpath("core/service.py").write_text(
        'raise AssertionError("must never execute")\n'
        'KEY_NAME = "FUTURE_SERVICE_API_KEY"\n'
    )
    source_root.joinpath("core/tests").mkdir()
    source_root.joinpath("core/tests/test_fixture.py").write_text(
        'KEY_NAME = "EXAMPLEBROKER_API_KEY"\n'
    )
    reserved = python_credential_names(source_root)
    assert reserved == {"FUTURE_SERVICE_API_KEY"}
    monkeypatch.setattr(broker_registry, "python_credential_names", lambda: reserved)
    path = tmp_path / "registry.json"
    path.write_text(json.dumps({"version": 1, "brokers": [
        asdict(replace(_EXAMPLE_BROKER, name="future_service")),
    ]}))
    with pytest.raises(ValueError, match="Python-owned.*FUTURE_SERVICE_API_KEY"):
        load_model_brokers(path)


def test_broker_consumes_only_its_derived_credential(monkeypatch):
    broker = _EXAMPLE_BROKER
    monkeypatch.setenv(broker.api_key_env, "broker-secret")
    for name in ("MISTRAL_API_KEY", "PYTHON_FEATURE_API_KEY", "OTHERBROKER_API_KEY"):
        monkeypatch.setenv(name, "unrelated")
    assert read_broker_key(broker, consume=True) == "broker-secret"
    assert broker.api_key_env not in os.environ
    for name in ("MISTRAL_API_KEY", "PYTHON_FEATURE_API_KEY", "OTHERBROKER_API_KEY"):
        assert os.environ[name] == "unrelated"


@pytest.mark.parametrize("field,value", [
    ("name", "openai"), ("name", "mistral"), ("name", "../broker"),
    ("api_key_env", "PATH"), ("auth_scheme", "Bearer\r\nx-test: injected"),
    ("api_key_env", "MISTRAL_API_KEY"),
    ("api_key_env", "OPENAI_API_KEY"), ("name", "cohere"),
    ("protocol", "python.module:function"),
    ("auth_scheme", "Basic"),
    ("credential_suffix", "MISTRAL_API_KEY"),
    ("credential_suffix", "PATH"),
    ("api_path", "/v1/../admin"), ("api_path", "//evil.com"),
    ("api_path", "/v1?key=secret"),
    ("upstream_base_url", "http://example.com"),
    ("upstream_base_url", "https://user:secret@example.com"),
    ("upstream_base_url", "https://example.com/v1"),
    ("upstream_base_url", "https://example.com?key=secret"),
    ("upstream_base_url", "https://example.com#fragment"),
])
def test_invalid_entry_rejected(tmp_path, field, value):
    entry = asdict(_EXAMPLE_BROKER)
    entry[field] = value
    path = tmp_path / "brokers.json"
    path.write_text(json.dumps({"version": 1, "brokers": [entry]}))
    with pytest.raises(ValueError):
        load_model_brokers(path)


def test_duplicate_broker_rejected(tmp_path):
    entry = asdict(_EXAMPLE_BROKER)
    path = tmp_path / "brokers.json"
    path.write_text(json.dumps({"version": 1, "brokers": [entry, entry]}))
    with pytest.raises(ValueError, match="duplicate broker name"):
        load_model_brokers(path)


@pytest.mark.parametrize("text", [
    '{"version":1,"version":1,"brokers":[]}',
    '{"version":2,"brokers":[]}',
    '{"version":true,"brokers":[]}',
    '{"version":1,"brokers":[{}]}',
])
def test_invalid_registry_rejected(tmp_path, text):
    path = tmp_path / "brokers.json"
    path.write_text(text)
    with pytest.raises(ValueError):
        load_model_brokers(path)


@pytest.mark.parametrize("broker", MODEL_BROKERS, ids=lambda b: b.name)
def test_config_resolves_broker_without_worker_key(broker, monkeypatch):
    from core.llm.config import model_config_from_entry, _entry_auth_resolvable

    monkeypatch.setenv("RAPTOR_LLM_SOCKET", "/unused-test-socket")
    config = model_config_from_entry({"provider": broker.name, "model": "example-model"})
    assert config.api_base == broker.api_base
    assert config.api_key is None
    assert _entry_auth_resolvable(config)


def test_no_dispatcher_means_no_direct_fallback(monkeypatch):
    from core.llm.dispatcher.client import make_broker_client

    monkeypatch.delenv("RAPTOR_LLM_SOCKET", raising=False)
    with pytest.raises(RuntimeError, match="requires the RAPTOR LLM dispatcher"):
        make_broker_client(_OPENROUTER.name)


def test_broker_endpoint_cannot_be_overridden():
    from core.llm.config import ModelConfig
    from core.llm.providers import OpenAICompatibleProvider

    with pytest.raises(ValueError, match="conflicts with its registered endpoint"):
        OpenAICompatibleProvider(ModelConfig(
            provider=_OPENROUTER.name, model_name="example-model",
            api_base="https://unregistered.invalid/v1",
        ))


def test_broken_catalog_leaves_native_providers_available(tmp_path):
    module_path = tmp_path / "model_brokers.py"
    module_path.write_text(Path(broker_registry.__file__).read_text())
    module_path.with_name("registry.json").write_text('{"invalid":true}')
    module = runpy.run_path(str(module_path))
    assert module["MODEL_BROKERS"] == ()
    assert module["model_broker"]("mistral") is None
    assert module["model_broker"]("openai") is None
    assert module["model_broker"]("") is None
    with pytest.raises(RuntimeError, match="registry is unavailable"):
        module["model_broker"]("examplebroker")


@pytest.mark.parametrize("entry", [{"model": "claude-opus-4-6"},
                                  {"provider": None}, {"provider": 1}])
def test_broken_catalog_does_not_block_native_default_selection(monkeypatch, entry):
    from core.llm import config

    native = config.ModelConfig(provider="anthropic", model_name="claude-opus-4-6")
    monkeypatch.setattr(broker_registry, "BROKER_REGISTRY_ERROR", "malformed catalog")
    monkeypatch.setattr(broker_registry, "MODEL_BROKERS", ())
    monkeypatch.setattr(config, "_operator_primary_override", None)
    monkeypatch.setattr(config, "_get_best_thinking_model", lambda: None)
    monkeypatch.setattr(config, "_get_configured_models", lambda: [entry])
    monkeypatch.setattr(config, "_config_bedrock_primary", lambda: None)
    monkeypatch.setattr(config, "_config_ollama_primary", lambda: None)
    monkeypatch.setattr(config, "_DEFAULT_PROVIDER_ORDER", ("anthropic",))
    monkeypatch.setattr(config, "_PROVIDER_BUILDERS", {"anthropic": lambda: native})
    assert config._get_default_primary_model(offline=True) is native
    if entry.get("model"):
        assert config.model_config_from_entry(entry).provider == "anthropic"


def test_python_rules_win_even_if_catalog_validation_is_bypassed(monkeypatch):
    from core.llm.dispatcher import auth

    conflicting = replace(_EXAMPLE_BROKER, name="openai",
                          upstream_base_url="https://wrong.invalid")
    monkeypatch.setattr(auth, "MODEL_BROKERS", (conflicting,))
    creds = auth.CredentialStore.__new__(auth.CredentialStore)
    creds._keys = {"openai": "native-test-key"}
    assert auth.build_rules(creds)["openai"].upstream_base_url == "https://api.openai.com"


def test_spawn_strips_broker_keys_even_from_explicit_env(monkeypatch):
    from core.llm.dispatcher.spawn import spawn_worker

    read_fd, write_fd = os.pipe()
    os.close(write_fd)
    dispatcher = Mock()
    dispatcher.allocate_worker.return_value = ("/test-socket", read_fd)
    popen = Mock()
    monkeypatch.setattr("subprocess.Popen", popen)
    env = {broker.api_key_env: "parent-secret" for broker in MODEL_BROKERS}
    env["PATH"] = "/usr/bin"
    spawn_worker(dispatcher, ["example-worker"], label="test", env=env)
    child_env = popen.call_args.kwargs["env"]
    assert not ({b.api_key_env for b in MODEL_BROKERS} & child_env.keys())
    assert child_env["RAPTOR_LLM_SOCKET"] == "/test-socket"
    assert child_env["PATH"] == "/usr/bin"
    assert all(env[b.api_key_env] == "parent-secret" for b in MODEL_BROKERS)
