"""Tests for ModelHint protocol."""

from __future__ import annotations

import pytest

from core.dispatch.broker.hints import (
    ModelHint,
    SpeedTier,
    defer,
    prefer,
    require,
)


class TestModelHint:
    def test_defer_default(self):
        h = defer()
        assert h.tier == "defer"
        assert h.model == ""
        assert h.speed_tier is SpeedTier.EXPRESS
        assert h.max_cost_usd is None
        assert h.exclude_models == frozenset()

    def test_require_needs_model(self):
        with pytest.raises(ValueError, match="require tier needs a model"):
            ModelHint(tier="require")

    def test_defer_rejects_model(self):
        with pytest.raises(ValueError, match="defer tier should not specify"):
            ModelHint(tier="defer", model="haiku")

    def test_require_happy_path(self):
        h = require("claude-haiku-4-5")
        assert h.tier == "require"
        assert h.model == "claude-haiku-4-5"

    def test_prefer_happy_path(self):
        h = prefer("claude-haiku-4-5", max_cost_usd=0.50)
        assert h.tier == "prefer"
        assert h.model == "claude-haiku-4-5"
        assert h.max_cost_usd == 0.50

    def test_exclude_models(self):
        h = defer(exclude_models={"haiku", "flash"})
        assert h.exclude_models == frozenset({"haiku", "flash"})

    def test_speed_tier_batch(self):
        h = defer(speed_tier=SpeedTier.BATCH)
        assert h.speed_tier is SpeedTier.BATCH

    def test_speed_tier_economy(self):
        h = prefer("opus", speed_tier=SpeedTier.ECONOMY)
        assert h.speed_tier is SpeedTier.ECONOMY

    def test_frozen(self):
        h = defer()
        with pytest.raises(AttributeError):
            h.tier = "require"  # type: ignore[misc]

    def test_decision_class(self):
        h = prefer(
            "claude-haiku-4-5",
            decision_class="agentic:use-after-free",
        )
        assert h.decision_class == "agentic:use-after-free"

    def test_require_with_exclude(self):
        h = require(
            "claude-opus-4-6",
            exclude_models={"claude-haiku-4-5"},
        )
        assert h.tier == "require"
        assert "claude-haiku-4-5" in h.exclude_models
