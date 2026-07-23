"""Tests for core.llm.prompt_budget."""

from __future__ import annotations

from pathlib import Path
import sys

_RAPTOR_DIR = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(_RAPTOR_DIR))

from core.llm.prompt_budget import (
    PromptSection,
    estimate_tokens,
    fit_to_budget,
    shed_blocks,
    context_budget_for_model,
)


class TestEstimateTokens:

    def test_basic(self):
        assert estimate_tokens("hello world") >= 1

    def test_four_chars_per_token(self):
        assert estimate_tokens("a" * 400) == 100

    def test_minimum_one(self):
        assert estimate_tokens("x") == 1

    def test_empty_string(self):
        assert estimate_tokens("") == 1


class TestFitToBudget:

    def test_within_budget_keeps_all(self):
        sections = [
            PromptSection("a", "x" * 400, 0),
            PromptSection("b", "y" * 200, 1),
        ]
        kept, shed = fit_to_budget(sections, 200)
        assert len(kept) == 2
        assert len(shed) == 0

    def test_over_budget_sheds_highest_priority(self):
        sections = [
            PromptSection("source", "x" * 400, 0),
            PromptSection("callers", "y" * 400, 1),
            PromptSection("exemplars", "z" * 400, 3),
        ]
        kept, shed = fit_to_budget(sections, 200)
        shed_labels = {s.label for s in shed}
        assert "source" not in shed_labels
        assert "exemplars" in shed_labels

    def test_priority_zero_never_shed(self):
        sections = [
            PromptSection("source", "x" * 2000, 0),
            PromptSection("evidence", "y" * 2000, 0),
        ]
        kept, shed = fit_to_budget(sections, 100)
        assert len(shed) == 0
        assert len(kept) == 2

    def test_largest_first_within_priority(self):
        sections = [
            PromptSection("source", "x" * 400, 0),
            PromptSection("small", "a" * 100, 2),
            PromptSection("big", "b" * 800, 2),
        ]
        kept, shed = fit_to_budget(sections, 200)
        if len(shed) == 1:
            assert shed[0].label == "big"

    def test_reserve_tokens(self):
        sections = [
            PromptSection("source", "x" * 400, 0),
            PromptSection("callers", "y" * 400, 1),
        ]
        kept, shed = fit_to_budget(
            sections, 250, reserve_tokens=100,
        )
        assert len(shed) == 1
        assert shed[0].label == "callers"

    def test_preserves_order(self):
        sections = [
            PromptSection("a", "x" * 100, 0),
            PromptSection("b", "y" * 100, 3),
            PromptSection("c", "z" * 100, 0),
            PromptSection("d", "w" * 100, 1),
        ]
        kept, _ = fit_to_budget(sections, 100)
        labels = [s.label for s in kept]
        for i in range(len(labels) - 1):
            orig_i = next(
                j for j, s in enumerate(sections)
                if s.label == labels[i]
            )
            orig_next = next(
                j for j, s in enumerate(sections)
                if s.label == labels[i + 1]
            )
            assert orig_i < orig_next


class TestContextBudgetForModel:

    def test_known_model(self):
        budget = context_budget_for_model("claude-haiku-4-5")
        assert budget > 100_000
        assert budget < 200_000

    def test_unknown_model_fallback(self):
        budget = context_budget_for_model("unknown-model-xyz")
        assert budget > 0

    def test_system_prompt_deducted(self):
        b1 = context_budget_for_model("claude-haiku-4-5")
        b2 = context_budget_for_model(
            "claude-haiku-4-5", system_prompt_tokens=10_000,
        )
        assert b2 == b1 - 10_000


from dataclasses import dataclass


@dataclass(frozen=True)
class _FakeBlock:
    content: str
    kind: str
    origin: str = "test"


class TestShedBlocks:

    def test_within_budget_keeps_all(self):
        blocks = [
            _FakeBlock("x" * 400, "vulnerable-code"),
            _FakeBlock("y" * 200, "ast-view"),
        ]
        pri = {"vulnerable-code": 0, "ast-view": 1}
        kept, shed = shed_blocks(blocks, 200, pri)
        assert len(kept) == 2
        assert len(shed) == 0

    def test_sheds_low_priority_kind(self):
        blocks = [
            _FakeBlock("x" * 400, "vulnerable-code"),
            _FakeBlock("y" * 400, "sage-historical-context"),
        ]
        pri = {"vulnerable-code": 0, "sage-historical-context": 3}
        kept, shed = shed_blocks(blocks, 150, pri)
        assert len(shed) == 1
        assert shed[0].kind == "sage-historical-context"

    def test_priority_zero_never_shed(self):
        blocks = [
            _FakeBlock("x" * 2000, "vulnerable-code"),
            _FakeBlock("y" * 2000, "scanner-message"),
        ]
        pri = {"vulnerable-code": 0, "scanner-message": 0}
        kept, shed = shed_blocks(blocks, 100, pri)
        assert len(shed) == 0
        assert len(kept) == 2

    def test_missing_kind_defaults_to_priority_2(self):
        blocks = [
            _FakeBlock("x" * 400, "vulnerable-code"),
            _FakeBlock("y" * 400, "mystery-block"),
        ]
        pri = {"vulnerable-code": 0}
        kept, shed = shed_blocks(blocks, 150, pri)
        assert len(shed) == 1
        assert shed[0].kind == "mystery-block"

    def test_preserves_original_objects(self):
        b1 = _FakeBlock("x" * 400, "code")
        b2 = _FakeBlock("y" * 400, "context")
        pri = {"code": 0, "context": 3}
        kept, shed = shed_blocks([b1, b2], 150, pri)
        assert kept[0] is b1
        assert shed[0] is b2

    def test_duplicate_kinds(self):
        blocks = [
            _FakeBlock("x" * 100, "step"),
            _FakeBlock("y" * 100, "step"),
            _FakeBlock("z" * 400, "code"),
        ]
        pri = {"step": 2, "code": 0}
        kept, shed = shed_blocks(blocks, 120, pri)
        assert all(b.kind == "step" for b in shed)
        assert any(b.kind == "code" for b in kept)


class TestShedBlocksWithUntrustedBlock:
    """Integration: shed_blocks with the production UntrustedBlock class."""

    def _make_block(self, content, kind, origin="test"):
        from core.security.prompt_envelope import UntrustedBlock
        return UntrustedBlock(
            content=content, kind=kind, origin=origin,
        )

    def test_keeps_all_within_budget(self):
        blocks = [
            self._make_block("x" * 400, "vulnerable-code"),
            self._make_block("y" * 200, "ast-view"),
        ]
        pri = {"vulnerable-code": 0, "ast-view": 1}
        kept, shed = shed_blocks(blocks, 200, pri)
        assert len(kept) == 2
        assert len(shed) == 0

    def test_sheds_low_priority(self):
        blocks = [
            self._make_block("x" * 400, "vulnerable-code"),
            self._make_block("y" * 400, "sage-historical-context"),
        ]
        pri = {"vulnerable-code": 0, "sage-historical-context": 3}
        kept, shed = shed_blocks(blocks, 150, pri)
        assert len(shed) == 1
        assert shed[0].kind == "sage-historical-context"
        assert shed[0].origin == "test"

    def test_returns_original_frozen_dataclass_instances(self):
        b1 = self._make_block("code here", "vulnerable-code")
        b2 = self._make_block("y" * 400, "surrounding-context")
        pri = {"vulnerable-code": 0, "surrounding-context": 2}
        kept, shed = shed_blocks([b1, b2], 100, pri)
        assert kept[0] is b1
        assert shed[0] is b2

    def test_reserve_tokens_deducts_from_budget(self):
        blocks = [
            self._make_block("x" * 400, "vulnerable-code"),
            self._make_block("y" * 200, "function-context"),
        ]
        pri = {"vulnerable-code": 0, "function-context": 1}
        kept, shed = shed_blocks(
            blocks, 200, pri, reserve_tokens=80,
        )
        assert len(shed) == 1
        assert shed[0].kind == "function-context"
