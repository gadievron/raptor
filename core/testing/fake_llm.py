"""Fake LLM provider + minimal client builder for tests.

Consolidates the ``_FakeProvider`` / ``_client(tmp_path)`` scaffolding
that ``core/llm`` test suites (and their copies in packages/) each
re-spelled. The builder intentionally bypasses ``LLMClient.__init__``
(no API keys, no provider autodetection, no egress side effects) —
when the client's private construction changes, THIS is the one place
test scaffolding follows it.
"""

from __future__ import annotations

import threading
from collections import OrderedDict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from core.llm.client import LLMClient
from core.llm.config import LLMConfig, ModelConfig


class FakeStructuredProvider:
    """Provider-level stub whose ``generate_structured`` returns a
    canned ``(result, raw)`` pair, counts invocations, captures the
    last call's kwargs, and bumps the usage counters ``LLMClient``
    diffs (so tests observe non-zero cost/token deltas; cache hits
    bypass the provider entirely and leave the counters alone).

    Signature notes (the drift this fake ends): ``generate_structured``
    accepts positional-or-keyword ``prompt``/``schema`` and MUST take
    ``**kwargs`` — the real client forwards per-call options like
    ``temperature`` and ``task_type``, and copies without ``**kwargs``
    TypeError at runtime.
    """

    def __init__(self, result: Any, raw: str = "raw-stub", *,
                 cost_per_call: float = 0.001,
                 tokens_per_call: int = 100):
        self.result = result
        self.raw = raw
        self.calls = 0
        self.last_kwargs: dict[str, Any] = {}
        self._cost_per_call = cost_per_call
        self._tokens_per_call = tokens_per_call
        # Full usage-counter block the client diffs before/after a
        # call (superset of what the drifted copies carried).
        self.total_cost = 0.0
        self.total_tokens = 0
        self.total_input_tokens = 0
        self.total_output_tokens = 0
        self.call_count = 0
        self.total_duration = 0.0
        self.total_cache_read_tokens = 0
        self.total_cache_write_tokens = 0

    def generate_structured(
        self, prompt: str, schema: dict[str, Any],
        system_prompt: str | None = None,
        **kwargs: Any,
    ) -> tuple[Any, str]:
        self.calls += 1
        self.last_kwargs = dict(kwargs)
        self.total_cost += self._cost_per_call
        self.total_tokens += self._tokens_per_call
        return self.result, self.raw


def make_test_client(
    tmp_path: Path,
    *,
    enable_caching: bool = True,
    cache_ttl_seconds: float | None = None,
    cache_max_entries: int | None = None,
    max_retries: int = 1,
    provider: str = "anthropic",
) -> LLMClient:
    """Build a minimally-configured ``LLMClient`` backed by nothing.

    Skips the real constructor's health-check + provider-creation +
    egress paths so suites run without API keys or network. Pair with
    :func:`install_provider` to wire a fake under the primary-model
    key. ``provider`` lets casing-sensitivity suites configure a
    mixed-case provider name (downstream lookups are
    case-insensitive).
    """
    cfg = LLMConfig.__new__(LLMConfig)
    cfg.primary_model = ModelConfig(
        provider=provider,
        model_name="test-primary",
        max_context=200000,
        api_key="not-used",
    )
    cfg.fallback_models = []
    cfg.specialized_models = {}
    cfg.enable_fallback = False
    cfg.max_retries = max_retries
    cfg.retry_delay = 0.0
    cfg.retry_delay_remote = 0.0
    cfg.enable_caching = enable_caching
    cfg.cache_dir = tmp_path / "llm_cache"
    cfg.cache_ttl_seconds = cache_ttl_seconds
    cfg.cache_max_entries = cache_max_entries
    cfg.enable_cost_tracking = False
    cfg.max_cost_per_scan = 100.0
    # Avoid latent class-default pollution if a future code path
    # consults the scorecard.
    cfg.scorecard_enabled = False

    if enable_caching:
        cfg.cache_dir.mkdir(parents=True, exist_ok=True)

    client = LLMClient.__new__(LLMClient)
    client.config = cfg
    client.providers = {}
    client.total_cost = 0.0
    client.request_count = 0
    client.cache_hits = 0
    client.task_type_costs = {}
    client._daily_quota_exhausted = set()
    client._stats_lock = threading.RLock()
    client._key_locks = OrderedDict()
    client._key_locks_guard = threading.Lock()
    client._key_locks_cap = 4096
    return client


def install_provider(client: LLMClient, provider: Any) -> None:
    """Wire *provider* into ``client.providers`` under the key that
    ``_get_provider`` looks up for the primary model."""
    pm = client.config.primary_model
    client.providers[f"{pm.provider}:{pm.model_name}"] = provider


@dataclass
class FakeModel:
    """One-field stand-in for a multi-model ``ModelHandle`` — the
    ``model_name``-only dataclass four suites re-declared."""

    model_name: str


def make_anthropic_provider(
    client: Any = None,
    *,
    model_name: str = "claude-sonnet-5",
) -> Any:
    """Build an ``AnthropicProvider`` without the anthropic SDK.

    Response-shape and transport-selection suites fake the SDK client
    entirely; going through ``__init__`` would demand the real SDK
    (an optional dependency, absent on bare CI) only to construct a
    client the test immediately replaces. Mirrors
    :func:`make_test_client`'s ``__new__`` pattern: base-provider
    state, instructor wiring pinned off, caching warning silenced.
    """
    from core.llm.config import ModelConfig
    from core.llm.providers import AnthropicProvider, LLMProvider

    provider = AnthropicProvider.__new__(AnthropicProvider)
    LLMProvider.__init__(provider, ModelConfig(
        provider="anthropic", model_name=model_name, api_key="k",
    ))
    provider.instructor_client = None
    provider._instructor_consec_failures = 0
    provider._instructor_lock = threading.Lock()
    provider._caching_warning_emitted = True
    if client is not None:
        provider.client = client
    return provider


def ensure_anthropic_error_types(monkeypatch) -> None:
    """Make ``from anthropic import APIError, ...`` importable.

    The provider's retry taxonomy imports the SDK exception classes
    even when the client is a fake that never raises them. On hosts
    without the optional SDK, install a stub module carrying
    structurally-compatible exception types; where the real SDK is
    installed this is a no-op, so the genuine classes stay in play.
    """
    try:
        import anthropic  # noqa: F401 — availability probe
        return
    except ImportError:
        pass
    import sys
    import types

    stub = types.ModuleType("anthropic")

    class APIError(Exception):
        pass

    class APIConnectionError(APIError):
        pass

    class APIStatusError(APIError):
        status_code: int | None = None

    stub.APIError = APIError
    stub.APIConnectionError = APIConnectionError
    stub.APIStatusError = APIStatusError
    monkeypatch.setitem(sys.modules, "anthropic", stub)


__all__ = [
    "FakeModel",
    "FakeStructuredProvider",
    "ensure_anthropic_error_types",
    "install_provider",
    "make_anthropic_provider",
    "make_test_client",
]
