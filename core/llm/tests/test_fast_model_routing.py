"""Tests for fast-tier task routing.

Verifies that ``LLMConfig`` populates ``specialized_models`` for
fast-tier task types from a same-provider fast model, and that
``get_model_for_task`` routes correctly.

The fast-tier convention is: if the configured primary's provider has
an entry in :data:`PROVIDER_FAST_MODELS`, every task in
``FAST_TIER_TASKS`` defaults to that fast model unless the operator
has supplied their own entry.
"""

from __future__ import annotations

import pytest

from core.llm.config import LLMConfig, ModelConfig
from core.llm.model_data import (
    PROVIDER_FAST_MODELS,
    MODEL_COSTS,
    MODEL_LIMITS,
)
from core.llm.task_types import FAST_TIER_TASKS, TaskType


def _primary(provider: str, model_name: str = None) -> ModelConfig:
    """Build a primary ModelConfig for tests. ``model_name`` defaults
    to the provider's flagship default when omitted, mirroring real
    auto-config behaviour."""
    from core.llm.model_data import PROVIDER_DEFAULT_MODELS
    name = model_name or PROVIDER_DEFAULT_MODELS[provider]
    return ModelConfig(
        provider=provider,
        model_name=name,
        max_context=200000,
        api_key="sk-test",
    )


# ---------------------------------------------------------------------------
# Default population
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("provider", sorted(PROVIDER_FAST_MODELS.keys()))
def test_fast_tier_populated_for_known_provider(provider: str) -> None:
    """Every provider with a PROVIDER_FAST_MODELS entry must have its
    fast model auto-installed for every fast-tier task. This is the
    payoff: operators get fast-tier routing for free as long as their
    primary is a recognised cloud provider."""
    cfg = LLMConfig(primary_model=_primary(provider), fallback_models=[])
    expected_fast_name = PROVIDER_FAST_MODELS[provider]
    for task in FAST_TIER_TASKS:
        m = cfg.get_model_for_task(task)
        assert m is not None
        assert m.provider == provider
        assert m.model_name == expected_fast_name, (
            f"task {task!r}: expected {expected_fast_name}, got {m.model_name}"
        )


def test_non_fast_tier_task_routes_to_primary() -> None:
    """ANALYSE / GENERATE_CODE / etc. must NOT be silently downgraded
    to the fast model. This guards against accidentally widening the
    fast tier."""
    cfg = LLMConfig(primary_model=_primary("anthropic"), fallback_models=[])
    for task in (TaskType.ANALYSE, TaskType.SUMMARISE,
                 TaskType.GENERATE_CODE, TaskType.AGENT_LOOP, TaskType.AUDIT):
        m = cfg.get_model_for_task(task)
        assert m.model_name == cfg.primary_model.model_name, (
            f"task {task!r} unexpectedly routed away from primary"
        )


def test_unknown_task_type_routes_to_primary() -> None:
    """Unrecognised task_type strings must fall through to primary —
    callers passing typos or new names shouldn't get an exception or
    silent fast-model downgrade."""
    cfg = LLMConfig(primary_model=_primary("anthropic"), fallback_models=[])
    m = cfg.get_model_for_task("totally_made_up_task_name")
    assert m.model_name == cfg.primary_model.model_name


# ---------------------------------------------------------------------------
# Operator overrides
# ---------------------------------------------------------------------------


def test_operator_override_preserved() -> None:
    """If the operator pre-populates ``specialized_models[<fast-task>]``
    we must keep their entry intact — defaults only fill empty slots.
    Without this, an operator setting a custom fast model for one
    task would have it stomped at LLMConfig() construction time."""
    custom = ModelConfig(
        provider="anthropic",
        model_name="claude-sonnet-4-6",
        max_context=200000,
        api_key="sk-custom",
    )
    cfg = LLMConfig(
        primary_model=_primary("anthropic"),
        fallback_models=[],
        specialized_models={TaskType.VERDICT_BINARY: custom},
    )
    # Operator's choice survived for the task they set.
    m = cfg.get_model_for_task(TaskType.VERDICT_BINARY)
    assert m is custom

    # Other fast-tier tasks (CLASSIFY) still got the default fill.
    other = cfg.get_model_for_task(TaskType.CLASSIFY)
    assert other.model_name == PROVIDER_FAST_MODELS["anthropic"]


# ---------------------------------------------------------------------------
# Provider edge cases
# ---------------------------------------------------------------------------


def test_no_primary_model_no_population() -> None:
    """When ``primary_model`` is None (no LLM provider configured)
    population is a no-op rather than an exception. Mirrors how the
    rest of LLMConfig degrades gracefully without a primary."""
    cfg = LLMConfig.__new__(LLMConfig)
    cfg.primary_model = None
    cfg.fallback_models = []
    cfg.specialized_models = {}
    cfg.enable_fallback = False
    cfg.max_retries = 1
    cfg.retry_delay = 0.0
    cfg.retry_delay_remote = 0.0
    cfg.enable_caching = False
    from pathlib import Path
    cfg.cache_dir = Path("/tmp")
    cfg.cache_ttl_seconds = None
    cfg.cache_max_entries = None
    cfg.enable_cost_tracking = False
    cfg.max_cost_per_scan = 10.0
    cfg.__post_init__()                       # should be a no-op

    assert cfg.specialized_models == {}


def test_unknown_provider_no_population() -> None:
    """A provider absent from ``PROVIDER_FAST_MODELS`` (Ollama, Claude
    Code subprocess, anything custom) must leave ``specialized_models``
    untouched. Operators with these setups configure fast routing
    manually."""
    primary = ModelConfig(
        provider="ollama",
        model_name="llama3.2:3b",
        max_context=128000,
        api_key="",
    )
    cfg = LLMConfig(primary_model=primary, fallback_models=[])
    assert cfg.specialized_models == {}


# ---------------------------------------------------------------------------
# Built ModelConfig sanity
# ---------------------------------------------------------------------------


def test_fast_model_inherits_provider_credentials() -> None:
    """The auto-installed fast model uses the primary's API key —
    same provider, same auth. Operators who configured one should
    not need to configure the other."""
    primary = _primary("anthropic")
    primary.api_key = "sk-anthropic-test"
    cfg = LLMConfig(primary_model=primary, fallback_models=[])
    fast = cfg.get_model_for_task(TaskType.VERDICT_BINARY)
    assert fast.api_key == "sk-anthropic-test"


def test_fast_model_pulls_limits_and_costs_from_catalog() -> None:
    """The auto-installed model reads its context window and cost
    figures from the model_data catalog rather than inheriting the
    primary's. Without this the cost-tracking math would credit the
    fast model with the flagship's tariff."""
    cfg = LLMConfig(primary_model=_primary("anthropic"), fallback_models=[])
    fast = cfg.get_model_for_task(TaskType.VERDICT_BINARY)

    expected_limits = MODEL_LIMITS["claude-haiku-4-5"]
    expected_costs = MODEL_COSTS["claude-haiku-4-5"]
    assert fast.max_context == expected_limits["max_context"]
    assert fast.max_tokens == expected_limits["max_output"]

    expected_avg = (expected_costs["input"] + expected_costs["output"]) / 2
    assert fast.cost_per_1k_tokens == pytest.approx(expected_avg)


def test_fast_model_temperature_zero() -> None:
    """Verdict / classification workloads benefit from determinism;
    the fast model is configured with temperature 0 even when the
    primary defaults to 0.7."""
    cfg = LLMConfig(primary_model=_primary("anthropic"), fallback_models=[])
    fast = cfg.get_model_for_task(TaskType.VERDICT_BINARY)
    assert fast.temperature == 0.0
