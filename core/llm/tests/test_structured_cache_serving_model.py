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


def test_fresh_entry_roundtrips_serving_model(tmp_path: Path) -> None:
    """An entry written by a fallback model replays with the fallback's
    name, not the requested primary's."""
    client = make_test_client(tmp_path)
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
        provider="anthropic",
        duration=0.1,
    ))

    replay = client.generate_structured("p", _SCHEMA)
    assert fake.calls == 0, "expected a cache hit, not a provider call"
    assert replay.cached is True
    assert replay.model == "fallback-model"
    assert replay.result == {"verdict": "safe"}


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
