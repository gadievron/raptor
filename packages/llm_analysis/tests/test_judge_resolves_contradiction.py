"""Tests for JudgeTask.finalize's contradiction-resolution behaviour.

When the primary's reasoning came back self_contradictory after the
Stage F retry, AND a judge model is configured, the judge HAS now
seen the finding and produced a verdict. That verdict is the
tie-break — JudgeTask.finalize should clear ``self_contradictory``
so the headline's ''Inconsistent (review needed)'' count drops,
while preserving the audit trail (``contradictions`` list +
``contradiction_resolved_by_judge`` marker) for operators who want
to inspect HOW the contradiction was resolved.
"""

from __future__ import annotations

from packages.llm_analysis.tasks import JudgeTask


def _judge_result(fid: str, is_exploitable: bool,
                  reasoning: str = "judge says so") -> dict:
    return {
        "finding_id": fid,
        "is_exploitable": is_exploitable,
        "reasoning": reasoning,
        "analysed_by": "claude-haiku-judge",
    }


class TestJudgeResolvesContradiction:
    def test_contradictory_finding_resolved_by_judge_clears_flag(self):
        # Primary came back exploitable=True but with reasoning that
        # contradicted itself (self_contradictory=True). Single judge
        # agreed with the primary's verdict.
        prior = {
            "F1": {
                "finding_id": "F1",
                "is_exploitable": True,
                "self_contradictory": True,
                "contradictions": ["reasoning says FP but verdict is TP"],
                "reasoning": "...",
            },
        }
        results = [_judge_result("F1", True)]
        task = JudgeTask(results_by_id=prior)
        task.finalize(results, prior)
        # self_contradictory cleared because judge produced a verdict.
        assert prior["F1"]["self_contradictory"] is False
        # Resolution marker set so the audit trail is honest.
        assert prior["F1"].get("contradiction_resolved_by_judge") is True
        # Original ``contradictions`` list preserved for operator
        # review.
        assert prior["F1"]["contradictions"] == [
            "reasoning says FP but verdict is TP",
        ]
        # judge_analyses populated for inspection.
        assert len(prior["F1"]["judge_analyses"]) == 1

    def test_clean_finding_unchanged_by_judge_run(self):
        # Primary wasn't self_contradictory; judge agreed. No flag to
        # clear, no resolution marker needed.
        prior = {
            "F1": {
                "finding_id": "F1",
                "is_exploitable": True,
                "reasoning": "clean analysis",
            },
        }
        results = [_judge_result("F1", True)]
        task = JudgeTask(results_by_id=prior)
        task.finalize(results, prior)
        # No self_contradictory field at all on clean findings.
        assert "self_contradictory" not in prior["F1"]
        # No spurious resolution marker either.
        assert "contradiction_resolved_by_judge" not in prior["F1"]

    def test_judge_disputed_still_clears_contradiction(self):
        # Multi-judge panel: primary says True, judges split. The
        # FINAL verdict is whatever the panel majority decides.
        # Regardless of agreement/dispute, the contradiction IS
        # resolved (the judge stage saw the finding and produced a
        # tie-break). The ``disputed`` marker carries the panel
        # signal; the contradiction-resolution marker carries the
        # ''Stage F couldn't decide; judge did'' signal.
        prior = {
            "F1": {
                "finding_id": "F1",
                "is_exploitable": True,
                "self_contradictory": True,
                "contradictions": ["something"],
            },
        }
        # Two judges: one agrees with primary, one disagrees.
        results = [
            _judge_result("F1", True),
            _judge_result("F1", False),
        ]
        task = JudgeTask(results_by_id=prior)
        task.finalize(results, prior)
        # Contradiction marker still clears — judge stage made a call.
        assert prior["F1"]["self_contradictory"] is False
        assert prior["F1"]["contradiction_resolved_by_judge"] is True
        # Dispute marker independently records that judges split.
        assert prior["F1"]["judge"] == "disputed"

    def test_no_judge_analyses_leaves_contradiction_flag_alone(self):
        # Edge case: prior_results has a finding marked
        # self_contradictory, but no judge result was emitted for it
        # (e.g. judge dispatch errored on this finding specifically).
        # Don't clear the flag — operator still needs to review.
        prior = {
            "F1": {
                "finding_id": "F1",
                "is_exploitable": True,
                "self_contradictory": True,
                "contradictions": ["x"],
            },
        }
        results: list = []  # judge dispatched 0 results for F1
        task = JudgeTask(results_by_id=prior)
        task.finalize(results, prior)
        # Flag preserved because no judge verdict landed.
        assert prior["F1"]["self_contradictory"] is True
        assert "contradiction_resolved_by_judge" not in prior["F1"]

    def test_funnel_inconsistent_count_drops_after_judge(self):
        # End-to-end: a self_contradictory + exploitable finding goes
        # through judge resolution; ``bucket_orchestration_results``
        # then classifies it as ''exploitable'', not ''inconsistent''.
        # That's the operator-facing payoff — headline "Inconsistent
        # (review needed)" count drops automatically when a judge is
        # configured and resolves the contradiction.
        from core.orchestration.funnel import bucket_orchestration_results
        prior = {
            "F1": {
                "finding_id": "F1",
                "is_true_positive": True,
                "is_exploitable": True,
                "self_contradictory": True,
                "contradictions": ["x"],
            },
        }
        # Pre-judge bucketing: this finding lands in ``inconsistent``
        # (was the QoL #11-11b behaviour).
        b_pre = bucket_orchestration_results(list(prior.values()))
        assert b_pre["inconsistent"] == 1
        assert b_pre["exploitable"] == 0

        # Run judge with a single agreeing result.
        results = [_judge_result("F1", True)]
        task = JudgeTask(results_by_id=prior)
        task.finalize(results, prior)

        # Post-judge bucketing: contradiction resolved, finding now
        # lands in ``exploitable``.
        b_post = bucket_orchestration_results(list(prior.values()))
        assert b_post["inconsistent"] == 0
        assert b_post["exploitable"] == 1
