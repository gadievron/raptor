"""Public snapshots preserve model selection metadata without authentication."""

from __future__ import annotations

import json
from dataclasses import FrozenInstanceError, replace

import pytest

from core.llm.catalog import (
    MAX_CATALOG_BYTES,
    MAX_CATALOG_ROUTES,
    CatalogError,
    PublicCatalog,
    prepare_catalog,
)
from core.llm.config import ModelConfig


def _config(**overrides):
    fields = {
        "provider": "openai", "model_name": "fixture-model",
        "api_key": "canary-private-key",
        "api_base": "https://user:canary-password@gateway.example.test/v1?key=canary-query",
        "aws_profile": "canary-private-profile", "aws_region": "canary-private-region",
        "role": "analysis", "max_tokens": 8192, "max_context": 128000,
        "temperature": 0.4, "timeout": 180, "cost_per_1k_tokens": 0.03,
    }
    fields.update(overrides)
    return ModelConfig(**fields)


def test_snapshot_has_explicit_public_fields_and_round_trips():
    config = _config()
    prepared = prepare_catalog([config])
    raw = prepared.public.to_bytes()
    payload = json.loads(raw)
    assert set(payload) == {"schema_version", "generation", "routes"}
    route = prepared.public.routes[0]
    assert payload["routes"] == [{
        "route_id": route.route_id, "provider": config.provider,
        "model_name": config.model_name, "max_tokens": 8192,
        "max_context": 128000, "temperature": 0.4, "timeout": 180,
        "cost_per_1k_tokens": 0.03, "enabled": True, "role": "analysis",
    }]
    assert PublicCatalog.from_bytes(raw) == prepared.public
    for value in [config.api_key, config.api_base, config.aws_profile, config.aws_region]:
        assert value not in raw.decode()
        assert value not in repr(prepared)
        assert value not in repr(prepared.public)


def test_duplicate_model_routes_keep_distinct_accounts_and_detached_configs():
    first = _config()
    second = replace(first, api_key="second-account", role="fallback")
    prepared = prepare_catalog([first, second])
    public = prepared.public
    first_id, second_id = [route.route_id for route in public.routes]
    assert first_id != second_id
    first.api_key = "changed-input"
    assert prepared.private_config(public.generation, first_id).api_key == "canary-private-key"
    assert prepared.private_config(public.generation, second_id).api_key == "second-account"
    borrowed = prepared.private_config(public.generation, first_id)
    borrowed.api_key = "changed-return"
    assert prepared.private_config(public.generation, first_id).api_key == "canary-private-key"
    with pytest.raises(FrozenInstanceError):
        public.routes[0].model_name = "changed"
    with pytest.raises(AttributeError):
        prepared.public = prepare_catalog([]).public


def test_ids_do_not_survive_a_new_generation():
    first = prepare_catalog([_config()])
    second = prepare_catalog([_config()])
    assert first.public.generation != second.public.generation
    assert first.public.routes[0].route_id != second.public.routes[0].route_id
    with pytest.raises(CatalogError, match="Unknown"):
        first.private_config(second.public.generation, first.public.routes[0].route_id)
    with pytest.raises(CatalogError, match="Unknown"):
        first.private_config(first.public.generation, second.public.routes[0].route_id)


@pytest.mark.parametrize("field,value", [
    ("max_tokens", True), ("max_context", 0), ("timeout", 0),
    ("temperature", float("nan")), ("temperature", float("inf")),
    ("cost_per_1k_tokens", -1), ("enabled", "yes"),
    ("role", "bad\nrole"), ("model_name", ""),
    ("timeout", 10**1000), ("model_name", "bad\ud800name"),
], ids=["bool-token", "zero-context", "zero-timeout", "nan", "infinity",
        "negative-cost", "non-bool-enabled", "control-role", "empty-model",
        "huge-integer", "unpaired-surrogate"])
def test_invalid_public_settings_fail_without_echoing_values(field, value):
    with pytest.raises(CatalogError, match="Invalid catalog"):
        prepare_catalog([_config(**{field: value})])


@pytest.mark.parametrize("mutate", [
    lambda p: p.update(schema_version=True),
    lambda p: p.update(schema_version=2),
    lambda p: p.update(api_key="canary-private-key"),
    lambda p: p["routes"][0].update(api_key="canary-private-key"),
    lambda p: p["routes"].append(p["routes"][0]),
    lambda p: p.update(routes={}),
    lambda p: p["routes"][0].update(timeout=float("nan")),
], ids=["bool-version", "new-version", "private-envelope", "private-route",
        "duplicate-id", "wrong-routes", "nonfinite-timeout"])
def test_invalid_snapshots_are_rejected_without_input_disclosure(mutate):
    payload = json.loads(prepare_catalog([_config()]).public.to_bytes())
    mutate(payload)
    with pytest.raises(CatalogError) as caught:
        PublicCatalog.from_bytes(json.dumps(payload).encode())
    assert "canary-private-key" not in str(caught.value)


def test_byte_limit_duplicate_keys_and_parse_depth_are_bounded():
    for raw in [b" " * (MAX_CATALOG_BYTES + 1), b'{"routes":[],"routes":[]}',
                b"[" * 2000 + b"]" * 2000, b"\xff", b"null"]:
        with pytest.raises(CatalogError):
            PublicCatalog.from_bytes(raw)


def test_route_limit_does_not_exhaust_an_unbounded_source():
    count = 0

    def configs():
        nonlocal count
        while True:
            count += 1
            yield _config()

    with pytest.raises(CatalogError, match="Too many"):
        prepare_catalog(configs())
    assert count == MAX_CATALOG_ROUTES + 1


def test_combined_snapshot_size_is_checked_before_publication():
    with pytest.raises(CatalogError, match="size limit"):
        prepare_catalog([_config(model_name="m" * 1024)] * MAX_CATALOG_ROUTES)


def test_future_private_attributes_are_not_automatically_projected():
    config = _config()
    config.extra_auth = {"Authorization": "canary-future-secret"}
    prepared = prepare_catalog([config])
    assert b"canary-future-secret" not in prepared.public.to_bytes()


def test_generated_id_collision_fails_without_retry_loop(monkeypatch):
    from core.llm import catalog
    from core.testing.module_bindings import patch_module_attribute

    patch_module_attribute(monkeypatch, catalog, "secrets", "token_hex", lambda size: "a" * 32)
    with pytest.raises(CatalogError, match="Duplicate generated"):
        prepare_catalog([_config(), _config()])


def test_empty_catalog_is_valid_and_does_not_discover_models(monkeypatch):
    def refuse_discovery():
        pytest.fail("catalog preparation must not load operator configuration")

    monkeypatch.setattr("core.llm.config._get_configured_models", refuse_discovery)
    prepared = prepare_catalog([])
    assert PublicCatalog.from_bytes(prepared.public.to_bytes()).routes == ()
