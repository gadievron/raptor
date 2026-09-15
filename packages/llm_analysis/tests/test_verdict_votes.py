"""Shared verdict-vote tally — abstention semantics across all voters.

One counting rule (``correlation.tally_verdict_votes``) backs every
surface that counts ``is_exploitable`` votes: the correlation engine,
``ConsensusTask.finalize``, and ``JudgeTask.finalize``. A missing or
null ``is_exploitable`` (errored model, refused response, schema
failure nulled by response validation) is an ABSTENTION — it must
never count as a "not exploitable" vote, and a stage whose whole
panel abstained must report an explicit no-verdict outcome instead of
minting agreement.
"""

from packages.llm_analysis.correlation import (
    VoteTally,
    tally_verdict_votes,
)
from packages.llm_analysis.tasks import ConsensusTask, JudgeTask


class TestTallyVerdictVotes:
    def test_counts_each_bucket(self):
        t = tally_verdict_votes([True, False, None, True, None])
        assert t == VoteTally(exploitable=2, not_exploitable=1, abstained=2)
        assert t.voted == 3

    def test_majority_is_strict_over_voters_only(self):
        # 1 yes + 2 abstains: the single real vote IS the majority —
        # pre-fix the abstainers read as 2 "no" votes and inverted it.
        assert tally_verdict_votes([True, None, None]).majority() is True
        assert tally_verdict_votes([False, None, None]).majority() is False
        assert tally_verdict_votes([True, False, False]).majority() is False

    def test_tie_has_no_majority(self):
        t = tally_verdict_votes([True, False])
        assert t.tie is True
        assert t.majority() is None

    def test_all_abstain_is_explicitly_inconclusive(self):
        t = tally_verdict_votes([None, None, None])
        assert t.voted == 0
        assert t.majority() is None
        assert t.tie is False
        assert t.disputed is False
        assert t.unanimous is False

    def test_abstainers_never_create_a_dispute(self):
        assert tally_verdict_votes([True, None]).disputed is False
        assert tally_verdict_votes([True, None]).unanimous is True
        assert tally_verdict_votes([True, False]).disputed is True

    def test_truthy_values_are_boolean_coerced(self):
        t = tally_verdict_votes([1, 0, "yes"])
        assert t.exploitable == 2
        assert t.not_exploitable == 1


def _consensus(fid: str, is_exploitable, model: str = "m2") -> dict:
    return {
        "finding_id": fid,
        "analysed_by": model,
        "is_exploitable": is_exploitable,
        "reasoning": "r",
    }


class TestConsensusFinalizeAbstention:
    def test_two_abstaining_models_do_not_flip_exploitable(self):
        # The verdict-direction hazard: a real "exploitable" primary
        # plus two consensus responses whose verdicts were nulled by
        # response validation. Pre-fix the abstainers counted as two
        # False votes — a 2-1 "majority" AGAINST — and the true
        # positive was silently downgraded.
        primary = {"is_exploitable": True}
        results = [_consensus("f1", None, "m2"), _consensus("f1", None, "m3")]
        ConsensusTask().finalize(results, {"f1": primary})
        assert primary["is_exploitable"] is True
        assert primary["consensus"] == "no-verdict"

    def test_abstainer_plus_real_vote_uses_only_the_real_vote(self):
        primary = {"is_exploitable": True}
        results = [_consensus("f1", True, "m2"), _consensus("f1", None, "m3")]
        ConsensusTask().finalize(results, {"f1": primary})
        assert primary["is_exploitable"] is True
        assert primary["consensus"] == "agreed"

    def test_genuine_not_exploitable_majority_still_wins(self):
        primary = {"is_exploitable": True}
        results = [
            _consensus("f1", False, "m2"),
            _consensus("f1", False, "m3"),
        ]
        ConsensusTask().finalize(results, {"f1": primary})
        assert primary["is_exploitable"] is False
        assert primary["consensus"] == "disputed"

    def test_all_abstain_leaves_primary_untouched(self):
        primary = {"is_exploitable": False}
        results = [_consensus("f1", None, "m2"), _consensus("f1", None, "m3")]
        ConsensusTask().finalize(results, {"f1": primary})
        assert primary["is_exploitable"] is False
        assert primary["consensus"] == "no-verdict"
        # The per-model record still lands for operator inspection.
        assert len(primary["consensus_analyses"]) == 2

    def test_tie_resolves_conservative_exploitable(self):
        # primary True + one False + one abstainer = a 1-1 tie among
        # actual voters: no majority — conservative-max applies (same
        # rule as the 1-vote dispute), surfacing the finding for
        # review instead of silently resolving against it.
        primary = {"is_exploitable": True}
        results = [
            _consensus("f1", False, "m2"),
            _consensus("f1", None, "m3"),
        ]
        ConsensusTask().finalize(results, {"f1": primary})
        assert primary["is_exploitable"] is True
        assert primary["consensus"] == "disputed"

    def test_single_consensus_conservative_max_unchanged(self):
        # Pre-existing 1-vote rule survives the tally refactor.
        primary = {"is_exploitable": False}
        results = [_consensus("f1", True, "m2")]
        ConsensusTask().finalize(results, {"f1": primary})
        assert primary["is_exploitable"] is True
        assert primary["consensus"] == "disputed"

    def test_pre_consensus_verdict_still_captured(self):
        primary = {"is_exploitable": False}
        results = [_consensus("f1", True, "m2")]
        ConsensusTask().finalize(results, {"f1": primary})
        assert primary["pre_consensus_is_exploitable"] is False

    def test_abstained_primary_never_stamps_agreed(self):
        # The primary cast no vote (schema-nulled verdict) and the
        # panel voted one-sided: nothing exists to agree WITH.
        # "agreed" here minted corroboration — reconcile's soft
        # downgrade path reads consensus=="agreed" as "two strong
        # signals support the original verdict" while no original
        # verdict existed. The panel verdict stands under its own
        # stamp instead (JudgeTask's primary_abstained semantics).
        primary = {"is_exploitable": None}
        results = [_consensus("f1", True, "m2")]
        ConsensusTask().finalize(results, {"f1": primary})
        assert primary["consensus"] == "panel-verdict"
        assert primary["is_exploitable"] is True
        assert primary["pre_consensus_is_exploitable"] is None

    def test_abstained_primary_single_false_vote_stands(self):
        primary = {"is_exploitable": None}
        results = [_consensus("f1", False, "m2")]
        ConsensusTask().finalize(results, {"f1": primary})
        assert primary["consensus"] == "panel-verdict"
        assert primary["is_exploitable"] is False

    def test_missing_primary_verdict_never_stamps_agreed(self):
        # Absent key is the same abstention as an explicit null.
        primary: dict = {}
        results = [
            _consensus("f1", True, "m2"),
            _consensus("f1", True, "m3"),
        ]
        ConsensusTask().finalize(results, {"f1": primary})
        assert primary["consensus"] == "panel-verdict"
        assert primary["is_exploitable"] is True

    def test_abstained_primary_disputed_panel_stamps_disputed(self):
        primary = {"is_exploitable": None}
        results = [
            _consensus("f1", True, "m2"),
            _consensus("f1", False, "m3"),
        ]
        ConsensusTask().finalize(results, {"f1": primary})
        assert primary["consensus"] == "disputed"

    def test_junk_primary_verdict_is_an_abstention_for_the_stamp(self):
        # A non-bool shape that bypassed response validation is not
        # a vote the panel could have agreed with.
        primary = {"is_exploitable": "true"}
        results = [_consensus("f1", True, "m2")]
        ConsensusTask().finalize(results, {"f1": primary})
        assert primary["consensus"] == "panel-verdict"

    def test_junk_decisive_vote_is_not_certified_as_panel_verdict(self):
        # The tally must consume the same parsed tri-state value the
        # stamp decision reads: feeding the raw field let junk-truthy
        # "true" cast a coerced DECISIVE vote (conservative-max) on a
        # row stamped "panel-verdict" — a junk-swung verdict carrying
        # the panel's authority while the panel itself voted False.
        primary = {"is_exploitable": "true"}
        results = [_consensus("f1", False, "m2")]
        ConsensusTask().finalize(results, {"f1": primary})
        # panel voted False; if final is True the junk was decisive —
        # that must not carry the panel's authority stamp
        assert not (primary["is_exploitable"] is True
                    and primary["consensus"] == "panel-verdict")

    def test_junk_primary_never_outvotes_the_panel(self):
        # Positive pin of the same rule: junk primary + one False
        # consensus vote resolves to the panel's verdict — matching
        # JudgeTask on identical input.
        primary = {"is_exploitable": "true"}
        results = [_consensus("f1", False, "m2")]
        ConsensusTask().finalize(results, {"f1": primary})
        assert primary["is_exploitable"] is False
        assert primary["consensus"] == "panel-verdict"


def _judge(fid: str, is_exploitable, model: str = "j1") -> dict:
    return {
        "finding_id": fid,
        "analysed_by": model,
        "is_exploitable": is_exploitable,
        "reasoning": "r",
    }


class TestJudgeFinalizeAbstention:
    def test_abstaining_judge_cannot_flip_majority(self):
        # primary True + judges [True, None, False]: 2-1 among actual
        # voters keeps True. Pre-fix the abstainer was a False vote —
        # 2-2, "no majority" resolved to False.
        primary = {"is_exploitable": True}
        results = [
            _judge("f1", True, "j1"),
            _judge("f1", None, "j2"),
            _judge("f1", False, "j3"),
        ]
        JudgeTask().finalize(results, {"f1": primary})
        assert primary["is_exploitable"] is True
        assert primary["judge"] == "disputed"

    def test_genuine_judge_majority_against_still_wins(self):
        primary = {"is_exploitable": True}
        results = [_judge("f1", False, "j1"), _judge("f1", False, "j2")]
        JudgeTask().finalize(results, {"f1": primary})
        assert primary["is_exploitable"] is False

    def test_all_judges_abstain_preserves_primary(self):
        primary = {"is_exploitable": True, "self_contradictory": True}
        results = [_judge("f1", None, "j1"), _judge("f1", None, "j2")]
        JudgeTask().finalize(results, {"f1": primary})
        assert primary["is_exploitable"] is True
        assert primary["judge"] == "no-verdict"
        # No judge voted: nothing exists to tie-break a
        # self-contradiction with — the flag must survive.
        assert primary["self_contradictory"] is True
        assert "contradiction_resolved_by_judge" not in primary
        assert len(primary["judge_analyses"]) == 2

    def test_tie_preserves_primary(self):
        # Judge overrides only on a strict majority.
        primary = {"is_exploitable": True}
        results = [_judge("f1", True, "j1"), _judge("f1", False, "j2")]
        JudgeTask().finalize(results, {"f1": primary})
        assert primary["is_exploitable"] is True

    def test_voting_judge_still_resolves_contradiction(self):
        primary = {"is_exploitable": True, "self_contradictory": True}
        results = [_judge("f1", True, "j1")]
        JudgeTask().finalize(results, {"f1": primary})
        assert primary["self_contradictory"] is False
        assert primary["contradiction_resolved_by_judge"] is True

    def test_single_judge_preserves_primary_verdict(self):
        primary = {"is_exploitable": False}
        results = [_judge("f1", True, "j1")]
        JudgeTask().finalize(results, {"f1": primary})
        assert primary["is_exploitable"] is False
        assert primary["judge"] == "disputed"

    def test_abstained_primary_single_judge_vote_stands(self):
        # The common single-judge config: the primary abstained
        # (schema-nulled verdict) and the judge cast a real vote.
        # Pre-fix "preserve primary" kept the None — the exact
        # second opinion select_items admitted the finding for was
        # thrown away — and "agreed" was stamped, minting
        # corroboration from a one-sided pair.
        primary = {"is_exploitable": None}
        results = [_judge("f1", True, "j1")]
        JudgeTask().finalize(results, {"f1": primary})
        assert primary["is_exploitable"] is True
        assert primary["judge"] == "panel-verdict"

    def test_abstained_primary_single_judge_false_vote_stands(self):
        primary = {"is_exploitable": None}
        results = [_judge("f1", False, "j1")]
        JudgeTask().finalize(results, {"f1": primary})
        assert primary["is_exploitable"] is False
        assert primary["judge"] == "panel-verdict"

    def test_abstained_primary_panel_majority_stands(self):
        primary = {"is_exploitable": None}
        results = [
            _judge("f1", True, "j1"),
            _judge("f1", True, "j2"),
            _judge("f1", False, "j3"),
        ]
        JudgeTask().finalize(results, {"f1": primary})
        assert primary["is_exploitable"] is True
        assert primary["judge"] == "disputed"

    def test_abstained_primary_tied_panel_keeps_abstention(self):
        # No majority among the actual voters and no primary vote to
        # fall back on: the abstention survives honestly instead of
        # being coerced to either side.
        primary = {"is_exploitable": None, "self_contradictory": True}
        results = [_judge("f1", True, "j1"), _judge("f1", False, "j2")]
        JudgeTask().finalize(results, {"f1": primary})
        assert primary["is_exploitable"] is None
        assert primary["judge"] == "disputed"
        # A tied panel produced no verdict — nothing exists to
        # tie-break the self-contradiction with.
        assert primary["self_contradictory"] is True
        assert "contradiction_resolved_by_judge" not in primary

    def test_absent_primary_verdict_panel_vote_stands(self):
        # Absent key is the same abstention the combined tally
        # already read it as.
        primary = {}
        results = [_judge("f1", True, "j1")]
        JudgeTask().finalize(results, {"f1": primary})
        assert primary["is_exploitable"] is True
        assert primary["judge"] == "panel-verdict"


class TestJudgeSelectItemsAbstention:
    def test_junk_primary_verdict_is_abstained_for_the_stamp(self):
        # The one-idiom rule: the abstained-primary snapshot goes
        # through read_verdict, so a non-bool shape that bypassed
        # response validation reads as an abstention. Pre-fix the raw
        # `.get(...) is None` treated junk as a voted primary and the
        # single-judge branch "preserved" a verdict that never
        # existed.
        primary = {"is_exploitable": "true"}
        results = [_judge("f1", False, "j1")]
        JudgeTask().finalize(results, {"f1": primary})
        assert primary["judge"] == "panel-verdict"
        assert primary["is_exploitable"] is False

    def test_abstained_tp_still_reaches_judge_panel(self):
        # A schema-nulled is_true_positive is an abstention, not a
        # "false positive" verdict. Pre-fix the truthiness gate read
        # the None as falsy and silently dropped the finding from the
        # judge panel — exactly the malformed-response findings that
        # most need a second opinion.
        findings = [{"finding_id": "f1"}]
        prior = {"f1": {"is_true_positive": None, "is_exploitable": True}}
        assert JudgeTask().select_items(findings, prior) == findings

    def test_absent_tp_still_reaches_judge_panel(self):
        findings = [{"finding_id": "f1"}]
        prior = {"f1": {"is_exploitable": True}}
        assert JudgeTask().select_items(findings, prior) == findings

    def test_explicit_false_tp_still_skips_judge(self):
        # Two-direction: an explicit not-a-true-positive verdict is
        # still excluded from the panel.
        findings = [{"finding_id": "f1"}]
        prior = {"f1": {"is_true_positive": False, "is_exploitable": False}}
        assert JudgeTask().select_items(findings, prior) == []
