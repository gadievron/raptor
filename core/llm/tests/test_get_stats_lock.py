"""``get_stats`` must snapshot ``self.providers`` under ``_stats_lock``.

``_get_provider`` inserts new providers into ``self.providers`` under
``_stats_lock`` from concurrent dispatch threads. ``get_stats`` used
to iterate the live dict without the lock, so a first call to a new
model during a progress-reporting stats poll could raise
``RuntimeError: dictionary changed size during iteration``.
"""

from __future__ import annotations

from core.llm.client import LLMClient
from core.llm.config import LLMConfig, ModelConfig


def _client() -> LLMClient:
    config = LLMConfig(
        primary_model=ModelConfig(
            provider="anthropic", model_name="test-model", api_key="test-key",
        ),
        enable_caching=False,
    )
    return LLMClient(config)


class _LockAssertingDict(dict):
    """Dict whose ``items()`` records whether ``_stats_lock`` was held."""

    def __init__(self, lock):
        super().__init__()
        self._lock = lock
        self.items_called_with_lock = []

    def items(self):
        self.items_called_with_lock.append(self._lock._is_owned())
        return super().items()


class _StubProvider:
    call_count = 0
    total_tokens = 0
    total_input_tokens = 0
    total_output_tokens = 0
    total_cost = 0.0
    total_duration = 0.0
    total_cache_read_tokens = 0
    total_cache_write_tokens = 0


def test_provider_iteration_happens_under_stats_lock():
    client = _client()
    guard = _LockAssertingDict(client._stats_lock)
    guard["anthropic/test-model"] = _StubProvider()
    client.providers = guard

    stats = client.get_stats()

    assert guard.items_called_with_lock, "items() was never called"
    assert all(guard.items_called_with_lock), (
        "get_stats read self.providers without holding _stats_lock — "
        "racy against _get_provider's locked insert"
    )
    assert "anthropic/test-model" in stats["providers"]
