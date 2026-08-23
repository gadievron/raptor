"""Provider casing on ``StructuredResponse``.

``generate()``'s cached path was already fixed to lowercase the
provider so cached and fresh responses land in the same bucket for
consumers grouping by provider (telemetry summaries, cost rollups).
``generate_structured()`` had reintroduced the same inconsistency on
both its cached and fresh paths — an ``LLMConfig`` with
``provider="Anthropic"`` returned ``"Anthropic"`` from structured
calls and ``"anthropic"`` from everything else.
"""

from __future__ import annotations

from pathlib import Path

from core.llm.client import LLMClient
from core.testing import (
    FakeStructuredProvider,
    install_provider,
    make_test_client,
)

_SCHEMA = {"type": "object", "properties": {"verdict": {"type": "string"}}}


def _client(tmp_path: Path) -> LLMClient:
    """Minimal client with a MIXED-CASE provider name (accepted by the
    constructor — downstream lookups are case-insensitive)."""
    client = make_test_client(tmp_path, provider="Anthropic")
    install_provider(
        client,
        FakeStructuredProvider({"verdict": "safe"}, '{"verdict":"safe"}'),
    )
    return client


def test_fresh_structured_response_provider_is_lowercased(tmp_path: Path):
    client = _client(tmp_path)
    r = client.generate_structured("Is this safe?", _SCHEMA)
    assert r.cached is False
    assert r.provider == "anthropic"


def test_cached_structured_response_provider_is_lowercased(tmp_path: Path):
    client = _client(tmp_path)
    client.generate_structured("Is this safe?", _SCHEMA)
    r2 = client.generate_structured("Is this safe?", _SCHEMA)
    assert r2.cached is True
    assert r2.provider == "anthropic"
