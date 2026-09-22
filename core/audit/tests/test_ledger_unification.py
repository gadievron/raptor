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


class TestRefinementDispatchRecordCarry:
    """The mechanical dispatch record survives the merge whichever
    verdict wins — both rounds describe the same function, and a
    dropped record makes gate resolution read \"no covering channel
    ever ran\" (and erases the did-not-look skips)."""

    def test_refined_winner_inherits_original_records(self):
        original = _outcome(status="suspicious")
        original.tools_dispatched = {"smt", "semgrep"}
        original.tools_errored = {"compiler"}
        original.tools_skipped = {"coccinelle"}
        refined = _outcome(status="suspicious")
        merged = merge_outcomes(original, refined)
        assert merged is refined
        assert merged.tools_dispatched == {"smt", "semgrep"}
        assert merged.tools_errored == {"compiler"}
        assert merged.tools_skipped == {"coccinelle"}

    def test_records_union_across_rounds(self):
        original = _outcome(status="suspicious")
        original.tools_dispatched = {"smt"}
        original.tools_skipped = {"coccinelle"}
        refined = _outcome(status="suspicious")
        refined.tools_dispatched = {"semgrep"}
        merged = merge_outcomes(original, refined)
        assert merged.tools_dispatched == {"smt", "semgrep"}
        assert merged.tools_skipped == {"coccinelle"}

    def test_dispatched_in_any_round_leaves_the_skip_set(self):
        # A channel that looked in either round did look: it must not
        # simultaneously read as did-not-look.
        original = _outcome(status="suspicious")
        original.tools_skipped = {"coccinelle"}
        refined = _outcome(status="suspicious")
        refined.tools_dispatched = {"coccinelle"}
        merged = merge_outcomes(original, refined)
        assert merged.tools_dispatched == {"coccinelle"}
        assert merged.tools_skipped is None or (
            "coccinelle" not in merged.tools_skipped
        )

    def test_original_winner_keeps_its_records(self):
        # finding → clean regression path: original wins.
        original = _outcome(status="finding")
        original.tools_dispatched = {"smt"}
        refined = _outcome(status="clean")
        refined.tools_skipped = {"coccinelle"}
        merged = merge_outcomes(original, refined)
        assert merged is original
        assert merged.tools_dispatched == {"smt"}
        assert merged.tools_skipped == {"coccinelle"}

    def test_no_records_stays_none(self):
        original = _outcome(status="suspicious")
        refined = _outcome(status="suspicious")
        merged = merge_outcomes(original, refined)
        assert merged.tools_dispatched is None
        assert merged.tools_skipped is None

    def test_winner_stale_skip_cleared_when_union_dispatched(self):
        # A channel the merged record shows dispatched must leave the
        # WINNER'S own skip set too — left in both, the journal reads
        # it as looked and did-not-look simultaneously.
        original = _outcome(status="suspicious")
        original.tools_dispatched = {"coccinelle"}
        refined = _outcome(status="suspicious")
        refined.tools_skipped = {"coccinelle"}
        merged = merge_outcomes(original, refined)
        assert merged is refined
        assert merged.tools_dispatched == {"coccinelle"}
        assert not merged.tools_skipped
