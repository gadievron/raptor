"""Ledger unification: refinement rounds sum, tokens reach outcomes.

Zero LLM calls — fake clients throughout.
"""

from __future__ import annotations

from typing import ClassVar

from core.audit.orchestrator import ReviewOutcome
from core.audit.refinement import merge_outcomes


def _outcome(**over):
    base = {
        "file": "a.c", "function": "f", "status": "suspicious",
        "body": "b", "cost_usd": 1.0, "duration_s": 10.0,
        "tokens_in": 100, "tokens_out": 10,
        "cache_read_tokens": 500, "cache_write_tokens": 5,
    }
    base.update(over)
    return ReviewOutcome(**base)


class TestRefinementLedgerSums:
    def test_refined_wins_but_cost_sums(self):
        original = _outcome(status="suspicious")
        refined = _outcome(status="clean", cost_usd=0.5, duration_s=5.0,
                           tokens_in=50, tokens_out=5,
                           cache_read_tokens=100, cache_write_tokens=1)
        merged = merge_outcomes(original, refined)
        assert merged.status == "clean"
        assert merged.cost_usd == 1.5
        assert merged.duration_s == 15.0
        assert merged.tokens_in == 150
        assert merged.tokens_out == 15
        assert merged.cache_read_tokens == 600
        assert merged.cache_write_tokens == 6

    def test_original_kept_on_demotion_still_sums(self):
        # finding → clean regression is rejected, but the refinement
        # round's spend still happened and must not vanish.
        original = _outcome(status="finding")
        refined = _outcome(status="clean", cost_usd=0.5, duration_s=5.0)
        merged = merge_outcomes(original, refined)
        assert merged.status == "finding"
        assert merged.cost_usd == 1.5
        assert merged.duration_s == 15.0

    def test_tool_evidence_winner_sums(self):
        original = _outcome(status="suspicious")
        refined = _outcome(status="finding", evidence_tool="semgrep:x",
                           cost_usd=0.25)
        merged = merge_outcomes(original, refined)
        assert merged.status == "finding"
        assert merged.cost_usd == 1.25

    def test_rounds_accumulate(self):
        # The refinement loop folds each round into the running
        # outcome — three rounds bill three rounds.
        outcome = _outcome(cost_usd=1.0)
        for _ in range(2):
            outcome = merge_outcomes(outcome, _outcome(cost_usd=1.0))
        assert outcome.cost_usd == 3.0


class TestReviewOutcomeTokenPlumbing:
    def test_review_fn_populates_token_fields(self):
        from core.audit.llm_review import make_review_fn

        class _Resp:
            result: ClassVar[dict] = {"status": "clean", "body": "ok"}
            cost = 0.1
            model = "fake"
            input_tokens = 1234
            output_tokens = 56
            cache_read_tokens = 7000
            cache_write_tokens = 89

        class _Client:
            def supports_prompt_caching_for(self):
                return False

            def generate_structured(self, *a, **k):
                return _Resp()

        review_fn = make_review_fn(_Client())
        outcome = review_fn(
            {"file": "a.c", "function": "f", "source": "int f(){}",
             "line_start": 1, "line_end": 2},
            None,
        )
        assert outcome.tokens_in == 1234
        assert outcome.tokens_out == 56
        assert outcome.cache_read_tokens == 7000
        assert outcome.cache_write_tokens == 89

    def test_missing_usage_defaults_to_zero(self):
        from core.audit.llm_review import make_review_fn

        class _Resp:
            result: ClassVar[dict] = {"status": "clean", "body": "ok"}
            cost = 0.1
            model = "fake"

        class _Client:
            def supports_prompt_caching_for(self):
                return False

            def generate_structured(self, *a, **k):
                return _Resp()

        review_fn = make_review_fn(_Client())
        outcome = review_fn(
            {"file": "a.c", "function": "f", "source": "int f(){}",
             "line_start": 1, "line_end": 2},
            None,
        )
        assert outcome.tokens_in == 0
        assert outcome.cache_read_tokens == 0
