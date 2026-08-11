"""Tests for context-window routing."""

from __future__ import annotations

import pytest

from core.dispatch.broker.context_routing import (
    ContextRoutingError,
    models_fitting,
    select_by_context,
)
from core.dispatch.broker.hints import defer, prefer, require


class TestSelectByContext:
    CANDIDATES = [
        "claude-haiku-4-5",       # 200k context
        "claude-opus-4-6",        # 1M context
        "gpt-5.4-mini",           # 400k context
    ]

    def test_picks_cheapest_fitting(self):
        model = select_by_context(50_000, self.CANDIDATES)
        assert model in self.CANDIDATES

    def test_small_prompt_picks_cheapest(self):
        model = select_by_context(1_000, self.CANDIDATES)
        assert model in self.CANDIDATES

    def test_large_prompt_excludes_small_context(self):
        model = select_by_context(190_000, self.CANDIDATES)
        assert model != "claude-haiku-4-5"

    def test_require_returns_pinned_model(self):
        model = select_by_context(
            1_000,
            self.CANDIDATES,
            hint=require("claude-opus-4-6"),
        )
        assert model == "claude-opus-4-6"

    def test_require_raises_when_too_large(self):
        with pytest.raises(ContextRoutingError, match="cannot fit"):
            select_by_context(
                999_000,
                self.CANDIDATES,
                hint=require("claude-haiku-4-5"),
            )

    def test_prefer_returns_preferred_when_fits(self):
        model = select_by_context(
            50_000,
            self.CANDIDATES,
            hint=prefer("claude-opus-4-6"),
        )
        assert model == "claude-opus-4-6"

    def test_prefer_falls_through_when_too_large(self):
        model = select_by_context(
            190_000,
            self.CANDIDATES,
            hint=prefer("claude-haiku-4-5"),
        )
        assert model != "claude-haiku-4-5"

    def test_defer_with_exclude(self):
        model = select_by_context(
            1_000,
            self.CANDIDATES,
            hint=defer(exclude_models={"claude-haiku-4-5"}),
        )
        assert model != "claude-haiku-4-5"

    def test_no_candidates_raises(self):
        with pytest.raises(ContextRoutingError, match="no candidate"):
            select_by_context(999_999_999, self.CANDIDATES)

    def test_empty_candidates_raises(self):
        with pytest.raises(ContextRoutingError, match="no candidate"):
            select_by_context(1_000, [])

    def test_require_unknown_model_raises_context_error(self):
        with pytest.raises(ContextRoutingError, match="not in MODEL_LIMITS"):
            select_by_context(
                1_000,
                self.CANDIDATES,
                hint=require("nonexistent-model-xyz"),
            )

    def test_prefer_respects_exclude_on_preferred_model(self):
        model = select_by_context(
            1_000,
            self.CANDIDATES,
            hint=prefer(
                "claude-haiku-4-5",
                exclude_models={"claude-haiku-4-5"},
            ),
        )
        assert model != "claude-haiku-4-5"

    def test_headroom(self):
        from core.llm.model_data import context_window_for

        haiku_ctx = context_window_for("claude-haiku-4-5")
        just_over_90pct = int(haiku_ctx * 0.91)
        model = select_by_context(
            just_over_90pct,
            self.CANDIDATES,
        )
        assert model != "claude-haiku-4-5"

        model_loose = select_by_context(
            just_over_90pct,
            self.CANDIDATES,
            headroom=0.95,
        )
        assert model_loose in self.CANDIDATES


class TestModelsFitting:
    def test_returns_sorted_by_cost(self):
        result = models_fitting(1_000)
        assert len(result) > 0
        assert isinstance(result[0], str)

    def test_large_prompt_filters_small_models(self):
        result = models_fitting(500_000)
        assert "claude-haiku-4-5" not in result

    def test_impossibly_large_returns_empty(self):
        result = models_fitting(999_999_999)
        assert result == []
