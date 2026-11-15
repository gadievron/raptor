"""Catalog construction and generation must never rediscover operator setup."""

from dataclasses import replace
import json

import pytest

from core.llm.catalog import llm_config_from_catalog, prepare_catalog
from core.llm.client import LLMClient
from core.llm.config import ModelConfig
from core.llm.providers import LLMProvider, LLMResponse


class _Provider(LLMProvider):
    def generate(self, prompt, system_prompt=None, **kwargs):
        assert self.config.api_key is None
        assert self.config.api_base is None
        return LLMResponse("worker-ok", self.config.model_name, self.config.provider, 1, 0, "stop")

    def generate_structured(self, *args, **kwargs):
        pytest.fail("free-form catalog request must not take the structured path")


@pytest.fixture
def catalog_client(monkeypatch):
    from core.llm import client, config, detection, egress

    def no_discovery(*args, **kwargs):
        pytest.fail("catalog worker attempted setup discovery")

    monkeypatch.setenv("RAPTOR_LLM_SOCKET", "/owned-test-proxy")
    monkeypatch.setenv("RAPTOR_LLM_TOKEN_FD", "12345")
    monkeypatch.setattr(detection, "_sdk_available", lambda name: True)
    monkeypatch.setattr(detection, "detect_llm_availability", no_discovery)
    monkeypatch.setattr(detection, "_read_config_models", no_discovery)
    monkeypatch.setattr(config, "_get_configured_models", no_discovery)
    monkeypatch.setattr(egress, "enable_llm_egress", no_discovery)
    monkeypatch.setattr(client, "create_provider", _Provider)

    def build(provider="anthropic"):
        public = prepare_catalog([ModelConfig(
            provider=provider, model_name="fixture-model", api_key="parent-only",
        )]).public
        config = llm_config_from_catalog(public, public.routes[0].route_id)
        return LLMClient(config, catalog=public), public

    return build


@pytest.mark.parametrize("provider", ["anthropic", "gemini"])
def test_catalog_generation_without_any_setup_reads(catalog_client, provider):
    client, _ = catalog_client(provider)
    assert client.config.fallback_models == []
    assert client.config.specialized_models == {}
    response = client.generate("test prompt", model_config=client.config.primary_model)
    assert response.content == "worker-ok"


def test_catalog_refuses_undeclared_models_and_private_config(catalog_client):
    client, _ = catalog_client()
    for model in [replace(client.config.primary_model, model_name="other-model"),
                  replace(client.config.primary_model, api_key="unexpected-key")]:
        with pytest.raises(ValueError, match="outside"):
            client._get_provider(model)


def test_disappearing_proxy_cannot_select_direct_sdk(catalog_client, monkeypatch):
    client, _ = catalog_client()
    monkeypatch.delenv("RAPTOR_LLM_SOCKET")
    with pytest.raises(ValueError, match="disappeared"):
        client.primary_provider


def test_catalog_requires_explicit_configuration_and_native_sdk(monkeypatch):
    from core.llm import detection

    public = prepare_catalog([ModelConfig(provider="anthropic", model_name="fixture-model")]).public
    with pytest.raises(ValueError, match="explicit"):
        LLMClient(catalog=public)
    monkeypatch.setenv("RAPTOR_LLM_SOCKET", "/owned-test-proxy")
    config = llm_config_from_catalog(public, public.routes[0].route_id)
    monkeypatch.setattr(detection, "_sdk_available", lambda name: False)
    with pytest.raises(ValueError, match="native"):
        LLMClient(config, catalog=public)


def test_ask_worker_records_and_replays_without_provider_dispatch(catalog_client, monkeypatch, tmp_path):
    from core.llm import client, transcript
    from core.llm.ask_worker import execute_request
    from core.testing.module_state import isolated_module_state

    _, public = catalog_client()
    raw = json.dumps({"prompt": "test prompt", "system_prompt": None,
                      "max_tokens": 32, "temperature": None}).encode()
    path = tmp_path / "worker.jsonl"
    monkeypatch.setenv("RAPTOR_LLM_TRANSCRIPT", f"record:{path}")
    with isolated_module_state(transcript, {"_active": None, "_active_resolved": False},
                               lock=transcript._active_lock):
        recorded = execute_request(public, raw)
    assert recorded.content == "worker-ok"
    assert recorded.tokens_used == 1
    assert path.is_file()
    assert "parent-only" not in path.read_text()

    def no_provider(*args, **kwargs):
        pytest.fail("replaying the keyless worker dispatched a provider")

    monkeypatch.setattr(client, "create_provider", no_provider)
    monkeypatch.setenv("RAPTOR_LLM_TRANSCRIPT", f"replay:{path}")
    with isolated_module_state(transcript, {"_active": None, "_active_resolved": False},
                               lock=transcript._active_lock):
        replayed = execute_request(public, raw)
    assert replayed.content == recorded.content
    assert replayed.model == recorded.model
    assert replayed.provider == recorded.provider
    # Replay preserves the answer but reports no new provider usage or cost.
    assert replayed.tokens_used == 0
    assert replayed.cost == 0
