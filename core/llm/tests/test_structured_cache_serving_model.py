"""Serving-model provenance on structured cache replays.

The structured cache is keyed to the REQUESTED (first-choice) model,
so a fallback-served response is filed under the primary's cache slot.
The replay must report the model that actually produced the entry —
rebuilding with the requested model's name fabricates provenance for
every fallback-served hit. Entries written before the reader consumed
the stored field must still replay (with the requested model's name).
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from core.llm import cache_integrity
from core.llm import telemetry
from core.llm.providers import StructuredResponse
from core.testing import (
    FakeStructuredProvider,
    install_provider,
    make_test_client,
)

_SCHEMA = {"type": "object", "properties": {"verdict": {"type": "string"}}}


@pytest.fixture(autouse=True)
def _isolated_mac_key(tmp_path_factory, monkeypatch):
    """Fresh per-test key dir: never touch the developer's real key."""
    monkeypatch.setenv(
        "XDG_DATA_HOME", str(tmp_path_factory.mktemp("xdg-data")),
    )


@pytest.mark.parametrize("serving_provider", [
    pytest.param("anthropic", id="same-provider"),
    pytest.param("openai", id="cross-provider"),
    pytest.param("OpenAI", id="mixed-case"),
])
def test_fresh_entry_roundtrips_serving_model(tmp_path: Path, monkeypatch,
                                            serving_provider: str) -> None:
    """An entry written by a fallback model replays with the fallback's
    name, not the requested primary's."""
    client = make_test_client(tmp_path)
    telemetry_path = tmp_path / "telemetry.jsonl"
    monkeypatch.setattr(telemetry, "_sink", telemetry.TelemetrySink(telemetry_path))
    fake = FakeStructuredProvider({"verdict": "safe"})
    install_provider(client, fake)

    cache_key = client._get_structured_cache_key(
        "p", None, "test-primary", _SCHEMA, None,
    )
    client._save_structured_to_cache(cache_key, StructuredResponse(
        result={"verdict": "safe"},
        raw='{"verdict": "safe"}',
        cost=0.01,
        tokens_used=5,
        model="fallback-model",
        provider=serving_provider,
        duration=0.1,
    ))

    replay = client.generate_structured("p", _SCHEMA)
    assert fake.calls == 0, "expected a cache hit, not a provider call"
    assert replay.cached is True
    assert replay.model == "fallback-model"
    assert replay.provider == serving_provider.lower()
    assert replay.result == {"verdict": "safe"}
    record = json.loads(telemetry_path.read_text())
    assert record["disposition"] == "cache_hit"
    assert record["model"] == replay.model
    assert record["provider"] == replay.provider


def test_legacy_entry_without_model_key_still_replays(
        tmp_path: Path) -> None:
    """Entries missing the serving-model field load fine and keep the
    requested model's name (the pre-existing replay identity)."""
    client = make_test_client(tmp_path)
    fake = FakeStructuredProvider({"verdict": "safe"})
    install_provider(client, fake)

    cache_key = client._get_structured_cache_key(
        "p", None, "test-primary", _SCHEMA, None,
    )
    name = f"structured-{cache_key}"
    entry = cache_integrity.stamp(name, {
        "result": {"verdict": "safe"},
        "raw": '{"verdict": "safe"}',
        "provider": "anthropic",
        "tokens_used": 5,
        "timestamp": time.time(),
    })
    client.config.cache_dir.mkdir(parents=True, exist_ok=True)
    (client.config.cache_dir / f"{name}.json").write_text(
        json.dumps(entry))

    replay = client.generate_structured("p", _SCHEMA)
    assert fake.calls == 0, "legacy entry must still count as a hit"
    assert replay.cached is True
    assert replay.model == "test-primary"
    assert replay.result == {"verdict": "safe"}


@pytest.mark.parametrize("stored_provider", [
    pytest.param(None, id="missing"),
    pytest.param("", id="empty"),
    pytest.param(7, id="number"),
    pytest.param([], id="list"),
])
def test_legacy_provider_metadata_uses_requested_provider(
        tmp_path: Path, monkeypatch, stored_provider) -> None:
    client = make_test_client(tmp_path, provider="Anthropic")
    fake = FakeStructuredProvider({"verdict": "safe"})
    install_provider(client, fake)
    path = tmp_path / "telemetry.jsonl"
    monkeypatch.setattr(telemetry, "_sink", telemetry.TelemetrySink(path))
    key = client._get_structured_cache_key("p", None, "test-primary", _SCHEMA, None)
    name = f"structured-{key}"
    payload: dict[str, object] = {
        "result": {"verdict": "safe"}, "raw": '{"verdict":"safe"}',
        "model": "legacy-stub", "timestamp": time.time(),
    }
    if stored_provider is not None:
        payload["provider"] = stored_provider
    (client.config.cache_dir / f"{name}.json").write_text(
        json.dumps(cache_integrity.stamp(name, payload)))

    replay = client.generate_structured("p", _SCHEMA)
    assert replay.cached is True and fake.calls == 0
    assert replay.provider == "anthropic"
    assert json.loads(path.read_text())["provider"] == replay.provider


@pytest.mark.parametrize("with_model", [False, True], ids=["pair", "triple"])
def test_legacy_cache_reader_shapes_remain_accepted(tmp_path, monkeypatch, with_model):
    client = make_test_client(tmp_path, provider="Anthropic")
    fake = FakeStructuredProvider({"verdict": "safe"})
    install_provider(client, fake)
    cached: tuple[object, ...] = ({"verdict": "safe"}, '{"verdict":"safe"}')
    if with_model:
        cached = (*cached, "legacy-stub")
    monkeypatch.setattr(client, "_get_cached_structured_response", lambda key: cached)
    replay = client.generate_structured("p", _SCHEMA)
    assert replay.cached is True and fake.calls == 0
    assert replay.provider == "anthropic"
    assert replay.model == ("legacy-stub" if with_model else "test-primary")


def test_provider_metadata_tampering_remains_cache_miss(tmp_path):
    client = make_test_client(tmp_path)
    fake = FakeStructuredProvider({"verdict": "safe"})
    install_provider(client, fake)
    key = client._get_structured_cache_key("p", None, "test-primary", _SCHEMA, None)
    client._save_structured_to_cache(key, StructuredResponse(
        result={"verdict": "safe"}, raw='{"verdict":"safe"}',
        cost=0, tokens_used=0, model="fallback-stub", provider="openai", duration=0,
    ))
    path = client.config.cache_dir / f"structured-{key}.json"
    data = json.loads(path.read_text())
    data["provider"] = "forged-stub"
    path.write_text(json.dumps(data))

    replay = client.generate_structured("p", _SCHEMA)
    assert replay.cached is False
    assert fake.calls == 1
    assert replay.provider == "anthropic"
