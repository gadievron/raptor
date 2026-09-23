"""Tests for ``core.llm.scorecard.judge.record_judge_outcomes``.

Pins the producer's contract:
  * Multi-judge disputes record one event per (model, finding):
    primary's vote vs final, each judge's vote vs final.
  * Single-judge disputes skipped (no panel-majority truth signal).
  * Agreed findings skipped.
  * Decision class shape ``agentic:<rule_id>``.
  * Cheap-tier counters untouched.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from core.llm.scorecard.judge import record_judge_outcomes
from core.llm.scorecard.scorecard import EventType, ModelScorecard


@pytest.fixture
def scorecard(tmp_path: Path) -> ModelScorecard:
    return ModelScorecard(tmp_path / "sc.json", shadow_rate=0.0)


def _stat(sc: ModelScorecard, dc: str, model: str, ev: str):
    s = sc.get_stat(dc, model)
    if s is None:
        return (0, 0)
    return s.events[ev].correct, s.events[ev].incorrect


# ---------------------------------------------------------------------------
# No-op paths
# ---------------------------------------------------------------------------


class TestNoOp:
    def test_none_scorecard(self):
        n = record_judge_outcomes(
            None,
            results_by_id={},
            primary_verdicts_before_judge={},
        )
        assert n == 0

    def test_empty_results(self, scorecard):
        n = record_judge_outcomes(
            scorecard,
            results_by_id={},
            primary_verdicts_before_judge={},
        )
        assert n == 0

    def test_skips_findings_without_judge_field(self, scorecard):
        results = {"f1": {"rule_id": "py/x", "is_exploitable": True}}
        n = record_judge_outcomes(
            scorecard,
            results_by_id=results,
            primary_verdicts_before_judge={"f1": True},
        )
        assert n == 0

    def test_skips_error_results(self, scorecard):
        results = {"f1": {"error": "timeout", "judge": "disputed"}}
        n = record_judge_outcomes(
            scorecard,
            results_by_id=results,
            primary_verdicts_before_judge={"f1": True},
        )
        assert n == 0


# ---------------------------------------------------------------------------
# Multi-judge disputes — events recorded
# ---------------------------------------------------------------------------


class TestMultiJudgeDispute:
    def test_panel_overrules_primary(self, scorecard):
        """Primary said exploitable; 2 judges said not. Final is
        not-exploitable. Primary → incorrect; judges → correct."""
        results = {"f1": {
            "rule_id": "py/sql-injection",
            "judge": "disputed",
            "is_exploitable": False,                    # final
            "analysed_by": "claude-opus",
            "reasoning": "primary thought tainted",
            "judge_analyses": [
                {"model": "gpt-4", "is_exploitable": False,
                 "reasoning": "actually constant"},
                {"model": "gemini", "is_exploitable": False,
                 "reasoning": "validated input"},
            ],
        }}
        n = record_judge_outcomes(
            scorecard,
            results_by_id=results,
            primary_verdicts_before_judge={"f1": True},  # primary said True
        )
        assert n == 3
        dc = "agentic:py/sql-injection"
        assert _stat(scorecard, dc, "claude-opus", EventType.JUDGE_REVIEW) == (0, 1)
        assert _stat(scorecard, dc, "gpt-4",       EventType.JUDGE_REVIEW) == (1, 0)
        assert _stat(scorecard, dc, "gemini",      EventType.JUDGE_REVIEW) == (1, 0)

    def test_resolved_model_recorded_as_model_version(self, scorecard):
        """Regression: the primary's and EACH judge's resolved snapshot must
        land in the cell model_version. Previously tasks.py dropped
        resolved_model from the judge_analyses projection, so judge cells were
        always model_version=None."""
        results = {"f1": {
            "rule_id": "py/sqli",
            "judge": "disputed",
            "is_exploitable": False,
            "analysed_by": "claude-opus",
            "resolved_model": "claude-opus-4-7",
            "reasoning": "x",
            "judge_analyses": [
                {"model": "gpt-4", "resolved_model": "gpt-4-0613",
                 "is_exploitable": False, "reasoning": "a"},
                {"model": "gemini", "resolved_model": "gemini-2.5-pro-002",
                 "is_exploitable": False, "reasoning": "b"},
            ],
        }}
        record_judge_outcomes(
            scorecard,
            results_by_id=results,
            primary_verdicts_before_judge={"f1": True},
        )
        dc = "agentic:py/sqli"
        assert scorecard.get_stat(dc, "claude-opus").model_version == "claude-opus-4-7"
        assert scorecard.get_stat(dc, "gpt-4").model_version == "gpt-4-0613"
        assert scorecard.get_stat(dc, "gemini").model_version == "gemini-2.5-pro-002"

    def test_panel_kept_primary(self, scorecard):
        """Primary said exploitable; 1 judge dissented but the other
        agreed. With 3 voters (primary + 2 judges) and 2-vs-1
        in-favour, final stays exploitable. Primary → correct;
        agreeing judge → correct; dissenting judge → incorrect."""
        results = {"f1": {
            "rule_id": "py/sql-injection",
            "judge": "disputed",
            "is_exploitable": True,                     # final
            "analysed_by": "claude-opus",
            "judge_analyses": [
                {"model": "gpt-4",  "is_exploitable": True},
                {"model": "gemini", "is_exploitable": False,
                 "reasoning": "thought it was sanitised"},
            ],
        }}
        n = record_judge_outcomes(
            scorecard,
            results_by_id=results,
            primary_verdicts_before_judge={"f1": True},
        )
        assert n == 3
        dc = "agentic:py/sql-injection"
        assert _stat(scorecard, dc, "claude-opus", EventType.JUDGE_REVIEW) == (1, 0)
        assert _stat(scorecard, dc, "gpt-4",       EventType.JUDGE_REVIEW) == (1, 0)
        assert _stat(scorecard, dc, "gemini",      EventType.JUDGE_REVIEW) == (0, 1)

    def test_minority_reasoning_captured(self, scorecard):
        """Dissenter's reasoning attached to disagreement-samples log."""
        results = {"f1": {
            "rule_id": "py/sql-injection",
            "judge": "disputed",
            "is_exploitable": False,
            "analysed_by": "claude-opus",
            "reasoning": "primary: clearly tainted via request.GET",
            "judge_analyses": [
                {"model": "gpt-4", "is_exploitable": False, "reasoning": "ok"},
                {"model": "gemini", "is_exploitable": False, "reasoning": "ok"},
            ],
        }}
        record_judge_outcomes(
            scorecard,
            results_by_id=results,
            primary_verdicts_before_judge={"f1": True},
        )
        s = scorecard.get_stat("agentic:py/sql-injection", "claude-opus")
        samples = [
            samp for samp in s.disagreement_samples
            if samp.get("event_type") == EventType.JUDGE_REVIEW
        ]
        assert len(samples) == 1
        assert "tainted via request.GET" in samples[0]["this_reasoning"]


# ---------------------------------------------------------------------------
# Single-judge disputes — INTENTIONALLY skipped
# ---------------------------------------------------------------------------


class TestSingleJudgeSkipped:
    def test_single_judge_dispute_records_nothing(self, scorecard):
        """``JudgeTask.finalize`` keeps primary's verdict when there's
        only one judge — there's no panel-majority truth signal and
        recording would arbitrarily flag one side. Skip cleanly."""
        results = {"f1": {
            "rule_id": "py/sql-injection",
            "judge": "disputed",
            "is_exploitable": True,                     # primary kept
            "analysed_by": "claude-opus",
            "judge_analyses": [
                {"model": "gpt-4", "is_exploitable": False,
                 "reasoning": "single-judge dissent"},
            ],
        }}
        n = record_judge_outcomes(
            scorecard,
            results_by_id=results,
            primary_verdicts_before_judge={"f1": True},
        )
        assert n == 0
        # No events for either model.
        assert scorecard.get_stat("agentic:py/sql-injection", "claude-opus") is None
        assert scorecard.get_stat("agentic:py/sql-injection", "gpt-4") is None


# ---------------------------------------------------------------------------
# Agreed cases — skipped (no useful signal)
# ---------------------------------------------------------------------------


class TestAgreedSkipped:
    def test_agreed_no_events(self, scorecard):
        results = {"f1": {
            "rule_id": "py/sql-injection",
            "judge": "agreed",
            "is_exploitable": True,
            "analysed_by": "claude-opus",
            "judge_analyses": [
                {"model": "gpt-4", "is_exploitable": True},
                {"model": "gemini", "is_exploitable": True},
            ],
        }}
        n = record_judge_outcomes(
            scorecard,
            results_by_id=results,
            primary_verdicts_before_judge={"f1": True},
        )
        assert n == 0


# ---------------------------------------------------------------------------
# Decision-class shape + isolation
# ---------------------------------------------------------------------------


class TestIsolationFromGate:
    def test_does_not_pollute_cheap_short_circuit(self, scorecard):
        # Pre-seed cheap-tier counter.
        for _ in range(20):
            scorecard.record_event(
                "agentic:py/sql-injection", "claude-opus",
                EventType.CHEAP_SHORT_CIRCUIT, "correct",
            )
        before = _stat(scorecard, "agentic:py/sql-injection", "claude-opus",
                       EventType.CHEAP_SHORT_CIRCUIT)

        results = {"f1": {
            "rule_id": "py/sql-injection",
            "judge": "disputed",
            "is_exploitable": False,
            "analysed_by": "claude-opus",
            "judge_analyses": [
                {"model": "gpt-4", "is_exploitable": False},
                {"model": "gemini", "is_exploitable": False},
            ],
        }}
        record_judge_outcomes(
            scorecard,
            results_by_id=results,
            primary_verdicts_before_judge={"f1": True},
        )
        after = _stat(scorecard, "agentic:py/sql-injection", "claude-opus",
                      EventType.CHEAP_SHORT_CIRCUIT)
        assert before == after


class TestMissingSnapshot:
    def test_skips_when_primary_snapshot_missing(self, scorecard):
        """Defensive: if the caller didn't snapshot primary's verdict
        before judge ran, the producer can't know which way primary
        originally voted (JudgeTask overwrote it). Skip rather than
        mis-attribute."""
        results = {"f1": {
            "rule_id": "py/sql-injection",
            "judge": "disputed",
            "is_exploitable": False,
            "analysed_by": "claude-opus",
            "judge_analyses": [
                {"model": "gpt-4", "is_exploitable": False},
                {"model": "gemini", "is_exploitable": False},
            ],
        }}
        # Empty snapshot.
        n = record_judge_outcomes(
            scorecard,
            results_by_id=results,
            primary_verdicts_before_judge={},
        )
        assert n == 0


class TestPanelTie:
    """An exact tie among the recorded votes (primary + judges) means
    the finalised verdict is a mechanical tie-break, not a panel
    majority — scoring anyone against it would mint arbitrary
    correct/incorrect events."""

    def test_tie_records_nothing(self, scorecard):
        """2-vs-2 panel: primary votes True, judges vote
        False/False/True — no majority, so no events."""
        results = {"f1": {
            "rule_id": "py/sql-injection",
            "judge": "disputed",
            "is_exploitable": False,          # tie-broken final
            "analysed_by": "claude-opus",
            "reasoning": "primary reasoning",
            "judge_analyses": [
                {"model": "gpt-5", "is_exploitable": False},
                {"model": "gemini", "is_exploitable": False},
                {"model": "mistral", "is_exploitable": True},
            ],
        }}
        n = record_judge_outcomes(
            scorecard,
            results_by_id=results,
            primary_verdicts_before_judge={"f1": True},
        )
        assert n == 0
        for model in ("claude-opus", "gpt-5", "gemini", "mistral"):
            assert _stat(
                scorecard, "agentic:py/sql-injection", model,
                EventType.JUDGE_REVIEW,
            ) == (0, 0)

class TestAbstentions:
    """A judge with ``is_exploitable: None`` (errored / refused /
    schema-failed response) cast no vote — same abstention rule as
    ``tally_verdict_votes`` (the contract ``JudgeTask.finalize``
    applies). Abstainers never join the tie computation and never
    receive a JUDGE_REVIEW event."""

    def test_abstainer_gets_no_event_on_real_majority(self, scorecard):
        """Judges [True, True, None] vs primary False: JudgeTask's
        abstention-aware tally finalises exploitable on a real 2-1
        majority. Pre-fix the producer bool()-coerced the abstainer
        into a False vote, saw a 2-2 'tie' and dropped the whole
        finding's signal. Post-fix: primary incorrect, both voting
        judges correct, abstainer untouched."""
        results = {"f1": {
            "rule_id": "py/sql-injection",
            "judge": "disputed",
            "is_exploitable": True,           # real 2-1 majority
            "analysed_by": "claude-opus",
            "reasoning": "primary reasoning",
            "judge_analyses": [
                {"model": "gpt-5", "is_exploitable": True},
                {"model": "gemini", "is_exploitable": True},
                {"model": "mistral", "is_exploitable": None,
                 "reasoning": ""},
            ],
        }}
        n = record_judge_outcomes(
            scorecard,
            results_by_id=results,
            primary_verdicts_before_judge={"f1": False},
        )
        assert n == 3
        dc = "agentic:py/sql-injection"
        assert _stat(scorecard, dc, "claude-opus", EventType.JUDGE_REVIEW) == (0, 1)
        assert _stat(scorecard, dc, "gpt-5",       EventType.JUDGE_REVIEW) == (1, 0)
        assert _stat(scorecard, dc, "gemini",      EventType.JUDGE_REVIEW) == (1, 0)
        # The abstaining judge cast no vote — no cell, no event.
        assert scorecard.get_stat(dc, "mistral") is None

    def test_junk_judge_vote_is_an_abstention(self, scorecard):
        """A judge whose is_exploitable is a non-bool shape ("yes")
        cast no readable vote. Pre-fix the `is not None` filter kept
        it as a voter and bool()-coerced the junk into a True vote —
        minting a JUDGE_REVIEW reliability event for a vote never
        cast (the tri-state accessor reads junk as abstention)."""
        results = {"f1": {
            "rule_id": "py/sql-injection",
            "judge": "disputed",
            "is_exploitable": True,           # real 2-1 majority
            "analysed_by": "claude-opus",
            "reasoning": "primary reasoning",
            "judge_analyses": [
                {"model": "gpt-5", "is_exploitable": True},
                {"model": "gemini", "is_exploitable": True},
                {"model": "mistral", "is_exploitable": "yes",
                 "reasoning": ""},
            ],
        }}
        n = record_judge_outcomes(
            scorecard,
            results_by_id=results,
            primary_verdicts_before_judge={"f1": False},
        )
        assert n == 3
        dc = "agentic:py/sql-injection"
        # The junk-vote judge gets no cell, exactly like a None vote.
        assert scorecard.get_stat(dc, "mistral") is None
        assert _stat(scorecard, dc, "gpt-5", EventType.JUDGE_REVIEW) == (1, 0)

    def test_junk_primary_snapshot_value_is_an_abstention(self, scorecard):
        """A junk value in the pre-judge snapshot is not a primary
        vote. Pre-fix bool()-coercion minted a phantom True vote that
        broke this genuine 1-1 judge tie into a 2-1 "majority" —
        scoring a real judge "incorrect" and fabricating a "correct"
        primary event for a vote never cast. Junk = abstention: the
        real votes are a tie, nothing is recorded."""
        results = {"f1": {
            "rule_id": "py/sql-injection",
            "judge": "disputed",
            "is_exploitable": True,
            "analysed_by": "claude-opus",
            "reasoning": "primary reasoning",
            "judge_analyses": [
                {"model": "gpt-5", "is_exploitable": True},
                {"model": "gemini", "is_exploitable": False,
                 "reasoning": "dissent"},
            ],
        }}
        n = record_judge_outcomes(
            scorecard,
            results_by_id=results,
            primary_verdicts_before_judge={"f1": "yes"},
        )
        assert n == 0
        for model in ("claude-opus", "gpt-5", "gemini"):
            assert scorecard.get_stat("agentic:py/sql-injection", model) is None

    def test_junk_final_verdict_records_nothing(self, scorecard):
        """A junk finalised is_exploitable is not a majority outcome
        to score anyone against — pre-fix bool() read it as True and
        scored the panel against a fabricated verdict."""
        results = {"f1": {
            "rule_id": "py/sql-injection",
            "judge": "disputed",
            "is_exploitable": "yes",
            "analysed_by": "claude-opus",
            "reasoning": "primary reasoning",
            "judge_analyses": [
                {"model": "gpt-5", "is_exploitable": True},
                {"model": "gemini", "is_exploitable": True},
            ],
        }}
        n = record_judge_outcomes(
            scorecard,
            results_by_id=results,
            primary_verdicts_before_judge={"f1": False},
        )
        assert n == 0

    def test_abstention_tie_skips_and_mints_nothing(self, scorecard):
        """Judges [True, None] vs primary False: the real vote is a
        1-1 tie, so JudgeTask preserves the primary verdict as a
        mechanical tie-break. Pre-fix the producer counted the
        abstainer as a False vote, saw a 1-vs-2 'majority', scored
        the True judge incorrect AND minted a correct JUDGE_REVIEW
        event for the abstainer — a reliability event for a vote
        never cast. Post-fix: tie over actual voters, nothing
        recorded."""
        results = {"f1": {
            "rule_id": "py/sql-injection",
            "judge": "disputed",
            "is_exploitable": False,          # preserved primary
            "analysed_by": "claude-opus",
            "reasoning": "primary reasoning",
            "judge_analyses": [
                {"model": "gpt-5", "is_exploitable": True,
                 "reasoning": "judge dissent"},
                {"model": "gemini", "is_exploitable": None,
                 "reasoning": ""},
            ],
        }}
        n = record_judge_outcomes(
            scorecard,
            results_by_id=results,
            primary_verdicts_before_judge={"f1": False},
        )
        assert n == 0
        for model in ("claude-opus", "gpt-5", "gemini"):
            assert scorecard.get_stat("agentic:py/sql-injection", model) is None

    def test_abstention_negative_majority_direction(self, scorecard):
        """Mirror direction: judges [False, False, None] vs primary
        True — a real 2-1 not-exploitable majority. Primary
        incorrect, voting judges correct, abstainer untouched."""
        results = {"f1": {
            "rule_id": "py/sql-injection",
            "judge": "disputed",
            "is_exploitable": False,          # real 2-1 majority
            "analysed_by": "claude-opus",
            "reasoning": "primary reasoning",
            "judge_analyses": [
                {"model": "gpt-5", "is_exploitable": False},
                {"model": "gemini", "is_exploitable": False},
                {"model": "mistral", "is_exploitable": None},
            ],
        }}
        n = record_judge_outcomes(
            scorecard,
            results_by_id=results,
            primary_verdicts_before_judge={"f1": True},
        )
        assert n == 3
        dc = "agentic:py/sql-injection"
        assert _stat(scorecard, dc, "claude-opus", EventType.JUDGE_REVIEW) == (0, 1)
        assert _stat(scorecard, dc, "gpt-5",       EventType.JUDGE_REVIEW) == (1, 0)
        assert _stat(scorecard, dc, "gemini",      EventType.JUDGE_REVIEW) == (1, 0)
        assert scorecard.get_stat(dc, "mistral") is None

    def test_all_judges_abstained_records_nothing(self, scorecard):
        """Defensive: JudgeTask marks a fully-abstained panel
        ``judge == "no-verdict"``, but a dirty record tagged
        disputed must not score the primary against its own
        preserved verdict (self-corroboration)."""
        results = {"f1": {
            "rule_id": "py/sql-injection",
            "judge": "disputed",
            "is_exploitable": True,
            "analysed_by": "claude-opus",
            "judge_analyses": [
                {"model": "gpt-5", "is_exploitable": None},
                {"model": "gemini", "is_exploitable": None},
            ],
        }}
        n = record_judge_outcomes(
            scorecard,
            results_by_id=results,
            primary_verdicts_before_judge={"f1": True},
        )
        assert n == 0
        assert scorecard.get_stat("agentic:py/sql-injection", "claude-opus") is None

    def test_abstention_unmasks_tie_into_majority_both_ways(self, scorecard):
        """Judges [False, None, True, True] vs primary True: voting
        panel is 3-1 exploitable (abstainer coerced to False would
        have faked a 3-2 — still majority — but with primary False
        and judges [True, None] the coercion direction flips; this
        case pins the abstainer excluded from the denominator)."""
        results = {"f1": {
            "rule_id": "py/sql-injection",
            "judge": "disputed",
            "is_exploitable": True,
            "analysed_by": "claude-opus",
            "judge_analyses": [
                {"model": "gpt-5", "is_exploitable": False,
                 "reasoning": "dissent"},
                {"model": "gemini", "is_exploitable": None},
                {"model": "mistral", "is_exploitable": True},
                {"model": "llama", "is_exploitable": True},
            ],
        }}
        n = record_judge_outcomes(
            scorecard,
            results_by_id=results,
            primary_verdicts_before_judge={"f1": True},
        )
        assert n == 4
        dc = "agentic:py/sql-injection"
        assert _stat(scorecard, dc, "claude-opus", EventType.JUDGE_REVIEW) == (1, 0)
        assert _stat(scorecard, dc, "gpt-5",       EventType.JUDGE_REVIEW) == (0, 1)
        assert _stat(scorecard, dc, "mistral",     EventType.JUDGE_REVIEW) == (1, 0)
        assert _stat(scorecard, dc, "llama",       EventType.JUDGE_REVIEW) == (1, 0)
        assert scorecard.get_stat(dc, "gemini") is None


class TestPanelTieMajority:
    def test_clear_majority_still_records(self, scorecard):
        """3-vs-1 panel: every voter is scored against the majority."""
        results = {"f1": {
            "rule_id": "py/sql-injection",
            "judge": "disputed",
            "is_exploitable": False,          # majority verdict
            "analysed_by": "claude-opus",
            "reasoning": "primary reasoning",
            "judge_analyses": [
                {"model": "gpt-5", "is_exploitable": False},
                {"model": "gemini", "is_exploitable": False},
                {"model": "mistral", "is_exploitable": False},
            ],
        }}
        n = record_judge_outcomes(
            scorecard,
            results_by_id=results,
            primary_verdicts_before_judge={"f1": True},
        )
        assert n == 4
        assert _stat(
            scorecard, "agentic:py/sql-injection", "claude-opus",
            EventType.JUDGE_REVIEW,
        ) == (0, 1)
        assert _stat(
            scorecard, "agentic:py/sql-injection", "gpt-5",
            EventType.JUDGE_REVIEW,
        ) == (1, 0)


class TestAbstainedPrimarySnapshot:
    """A ``None`` snapshot entry means the primary ABSTAINED — it cast
    no vote. Pre-fix ``bool(None)`` minted a "not exploitable" primary
    vote, skewing the tie computation and writing a fabricated primary
    outcome into the ledger against exploitable-voting judges."""

    def _record(self, scorecard, judges, final, primary_snap):
        results = {"f1": {
            "rule_id": "py/sql-injection",
            "judge": "disputed",
            "is_exploitable": final,
            "analysed_by": "claude-opus",
            "reasoning": "primary reasoning",
            "judge_analyses": [
                {"model": m, "is_exploitable": v} for m, v in judges
            ],
        }}
        return record_judge_outcomes(
            scorecard,
            results_by_id=results,
            primary_verdicts_before_judge={"f1": primary_snap},
        )

    def test_abstained_primary_gets_no_event_judges_still_score(self, scorecard):
        n = self._record(
            scorecard,
            judges=[("gpt-5", True), ("gemini", True)],
            final=True,
            primary_snap=None,
        )
        assert n == 2
        dc = "agentic:py/sql-injection"
        assert scorecard.get_stat(dc, "claude-opus") is None
        assert _stat(scorecard, dc, "gpt-5",  EventType.JUDGE_REVIEW) == (1, 0)
        assert _stat(scorecard, dc, "gemini", EventType.JUDGE_REVIEW) == (1, 0)

    def test_abstained_primary_split_judges_is_a_tie_skip(self, scorecard):
        """Primary None + judges [True, False]: the real vote is 1-1 —
        JudgeTask's finalised value is a mechanical tie-break, so
        nothing scores. Pre-fix the coerced primary made it 1-vs-2
        and the exploitable-voting judge was minted incorrect against
        a majority the primary never joined."""
        n = self._record(
            scorecard,
            judges=[("gpt-5", True), ("gemini", False)],
            final=False,          # mechanical (preserved abstention)
            primary_snap=None,
        )
        assert n == 0
        for model in ("claude-opus", "gpt-5", "gemini"):
            assert scorecard.get_stat("agentic:py/sql-injection", model) is None

    def test_abstained_primary_single_voting_judge_skips(self, scorecard):
        """Primary None + judges [True, None]: one real vote cannot
        define a majority — recording the lone voter correct against
        a verdict only it produced would mint self-corroboration."""
        n = self._record(
            scorecard,
            judges=[("gpt-5", True), ("gemini", None)],
            final=True,
            primary_snap=None,
        )
        assert n == 0

    def test_voting_primary_unchanged(self, scorecard):
        """Control: a primary that actually voted keeps scoring
        exactly as before."""
        n = self._record(
            scorecard,
            judges=[("gpt-5", True), ("gemini", True)],
            final=True,
            primary_snap=False,
        )
        assert n == 3
        dc = "agentic:py/sql-injection"
        assert _stat(scorecard, dc, "claude-opus", EventType.JUDGE_REVIEW) == (0, 1)


class TestUnattributablePrimarySkipped:
    """A result without ``analysed_by`` cannot attribute the primary's
    outcome — minting it on a literal "?" cell accumulates noise no
    producer ever revisits (cmd_tool_evidence skips no-model records
    for exactly this reason; this was sibling drift). The primary's
    VOTE still counts toward the tie computation; only the event is
    skipped, and the judges still grade."""

    def test_no_analysed_by_skips_primary_event_keeps_judges(
        self, tmp_path,
    ):
        sc = ModelScorecard(tmp_path / "sc.json")
        results = {"f1": {
            "rule_id": "r",
            "judge": "disputed",
            "is_exploitable": True,
            "judge_analyses": [
                {"model": "j1", "is_exploitable": True},
                {"model": "j2", "is_exploitable": True},
            ],
            # no analysed_by
        }}
        n = record_judge_outcomes(
            sc,
            results_by_id=results,
            primary_verdicts_before_judge={"f1": False},
        )
        # Judges grade (2 events); no "?"-keyed primary cell.
        assert n == 2
        assert sc.get_stat("agentic:r", "?") is None
        assert sc.get_stat("agentic:r", "j1") is not None
