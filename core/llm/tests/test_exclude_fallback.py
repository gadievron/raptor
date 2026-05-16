"""Tests for ``exclude_fallback_to`` — multi-model duplicate guard.

When a primary model fails and the client silently falls back, the
fallback target may already be one of the OTHER active models in a
multi-model dispatch. That collapses the model panel to duplicates.

These tests verify the kwarg correctly filters fallbacks WITHOUT
breaking the existing fallback path for single-model callers.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from core.llm.client import LLMClient
from core.llm.config import LLMConfig, ModelConfig


def _model(provider: str, name: str, *, key: str = "test-key", role: str = None) -> ModelConfig:
    return ModelConfig(
        provider=provider, model_name=name, api_key=key, role=role,
    )


def _config(primary: ModelConfig, fallbacks: list) -> LLMConfig:
    # Disable disk caching so tests don't hit stale cached responses
    # from prior runs in the worktree's out/llm_cache/ directory.
    return LLMConfig(
        primary_model=primary, fallback_models=fallbacks,
        enable_caching=False,
    )


class _FailingResponse:
    """Stand-in for an LLMResponse the test never reads — provider raises before this matters."""


class _FakeProvider:
    """Provider stub.

    Tracks which model was actually called via ``calls`` list. ``raise_for``
    is a set of model names that should raise (simulating provider failure).
    """

    def __init__(self, calls: list, raise_for: set):
        self.calls = calls
        self.raise_for = raise_for

    def generate(self, prompt, system_prompt=None, **kwargs):
        # The model name is captured via the surrounding LLMClient logic
        # — we record via a closure in the test fixture below.
        raise NotImplementedError  # patched per-test


@pytest.fixture
def calls_log():
    return []


def _patched_get_provider(calls_log: list, fail_for: set, succeed_responses: dict):
    """Build a `_get_provider` replacement that records calls and returns
    a provider whose `generate` either raises (if model in fail_for) or
    returns a canned response (from succeed_responses)."""

    def make_provider(model_config: ModelConfig):
        prov = MagicMock()

        def _generate(prompt, system_prompt=None, **kwargs):
            calls_log.append(model_config.model_name)
            if model_config.model_name in fail_for:
                raise RuntimeError(f"simulated failure for {model_config.model_name}")
            return succeed_responses[model_config.model_name]

        prov.generate.side_effect = _generate
        return prov

    return make_provider


def _response(model_name: str, content: str = "ok"):
    """Minimal LLMResponse-shaped mock."""
    r = MagicMock()
    r.content = content
    r.model = model_name
    r.provider = "anthropic"  # any string
    r.tokens_used = 100
    r.cost = 0.0
    r.duration = 0.1
    r.input_tokens = 50
    r.output_tokens = 50
    r.thinking_tokens = 0
    return r


# ---------------------------------------------------------------------------
# Default behaviour (without exclude_fallback_to) — preserve existing
# ---------------------------------------------------------------------------


class TestDefaultFallback:
    def test_falls_back_when_primary_fails(self, calls_log):
        """Without exclude_fallback_to, primary failure → tries fallbacks."""
        pro = _model("anthropic", "pro")
        flash = _model("anthropic", "flash", role="fallback")
        config = _config(pro, [flash])
        client = LLMClient(config)

        with patch.object(
            client, "_get_provider",
            side_effect=_patched_get_provider(
                calls_log, fail_for={"pro"},
                succeed_responses={"flash": _response("flash")},
            ),
        ):
            result = client.generate("test prompt", model_config=pro)

        assert calls_log == ["pro", "flash"]
        assert result.model == "flash"


# ---------------------------------------------------------------------------
# exclude_fallback_to behaviour
# ---------------------------------------------------------------------------


class TestExcludeFallbackTo:
    def test_blocks_named_fallback(self, calls_log):
        """exclude_fallback_to={"flash"} prevents fallback to flash."""
        pro = _model("anthropic", "pro")
        flash = _model("anthropic", "flash", role="fallback")
        haiku = _model("anthropic", "haiku", role="fallback")
        config = _config(pro, [flash, haiku])
        client = LLMClient(config)

        with patch.object(
            client, "_get_provider",
            side_effect=_patched_get_provider(
                calls_log, fail_for={"pro"},
                succeed_responses={"haiku": _response("haiku")},
            ),
        ):
            result = client.generate(
                "test", model_config=pro, exclude_fallback_to={"flash"},
            )

        # pro tried (and failed), flash skipped, haiku tried (succeeded)
        assert "flash" not in calls_log
        assert calls_log == ["pro", "haiku"]
        assert result.model == "haiku"

    def test_empty_exclude_set_acts_like_default(self, calls_log):
        """exclude_fallback_to=set() doesn't prevent any fallback."""
        pro = _model("anthropic", "pro")
        flash = _model("anthropic", "flash", role="fallback")
        config = _config(pro, [flash])
        client = LLMClient(config)

        with patch.object(
            client, "_get_provider",
            side_effect=_patched_get_provider(
                calls_log, fail_for={"pro"},
                succeed_responses={"flash": _response("flash")},
            ),
        ):
            client.generate("test", model_config=pro, exclude_fallback_to=set())
        assert calls_log == ["pro", "flash"]

    def test_excluding_all_fallbacks_propagates_primary_failure(
        self, calls_log,
    ):
        """If every fallback is excluded and primary fails, error surfaces."""
        pro = _model("anthropic", "pro")
        flash = _model("anthropic", "flash", role="fallback")
        config = _config(pro, [flash])
        client = LLMClient(config)

        with patch.object(
            client, "_get_provider",
            side_effect=_patched_get_provider(
                calls_log, fail_for={"pro"},
                succeed_responses={},
            ),
        ):
            with pytest.raises(RuntimeError):
                client.generate(
                    "test", model_config=pro,
                    exclude_fallback_to={"flash"},
                )
        assert calls_log == ["pro"]

    def test_primary_success_skips_exclude_logic(self, calls_log):
        """When primary succeeds, exclude_fallback_to is never consulted."""
        pro = _model("anthropic", "pro")
        flash = _model("anthropic", "flash", role="fallback")
        config = _config(pro, [flash])
        client = LLMClient(config)

        with patch.object(
            client, "_get_provider",
            side_effect=_patched_get_provider(
                calls_log, fail_for=set(),
                succeed_responses={"pro": _response("pro")},
            ),
        ):
            result = client.generate(
                "test", model_config=pro, exclude_fallback_to={"flash"},
            )
        assert calls_log == ["pro"]
        assert result.model == "pro"

    def test_does_not_propagate_to_provider(self):
        """exclude_fallback_to must be popped from kwargs before reaching
        the provider (which doesn't expect it)."""
        pro = _model("anthropic", "pro")
        config = _config(pro, [])
        client = LLMClient(config)

        captured_kwargs = {}

        def make_provider(model_config):
            prov = MagicMock()

            def _generate(prompt, system_prompt=None, **kwargs):
                captured_kwargs.update(kwargs)
                return _response("pro")

            prov.generate.side_effect = _generate
            return prov

        with patch.object(client, "_get_provider", side_effect=make_provider):
            client.generate(
                "test", model_config=pro,
                exclude_fallback_to={"flash", "haiku"},
            )

        assert "exclude_fallback_to" not in captured_kwargs


# ---------------------------------------------------------------------------
# Same surface on generate_structured
# ---------------------------------------------------------------------------


class TestExcludeFallbackToStructured:
    def test_blocks_named_fallback_in_structured(self, calls_log):
        """generate_structured respects exclude_fallback_to identically."""
        pro = _model("anthropic", "pro")
        flash = _model("anthropic", "flash", role="fallback")
        haiku = _model("anthropic", "haiku", role="fallback")
        config = _config(pro, [flash, haiku])
        client = LLMClient(config)

        def make_provider(model_config):
            prov = MagicMock()
            # Real numbers so cost-delta arithmetic and `:.4f` formatting
            # downstream don't trip on MagicMock attributes.
            prov.total_cost = 0.0
            prov.total_tokens = 0

            def _gs(prompt, schema, system_prompt=None, **kwargs):
                calls_log.append(model_config.model_name)
                if model_config.model_name == "pro":
                    raise RuntimeError("primary fail")
                # client.py:970 unpacks `result_tuple` as 2-tuple
                # (result_dict, raw). Match that shape.
                return ({"verdict": "ok"}, "{}")

            prov.generate_structured.side_effect = _gs
            return prov

        with patch.object(client, "_get_provider", side_effect=make_provider):
            result = client.generate_structured(
                "test", schema={"type": "object"},
                model_config=pro, exclude_fallback_to={"flash"},
            )

        assert "flash" not in calls_log
        assert calls_log == ["pro", "haiku"]
        assert result.model == "haiku"
