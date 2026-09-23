"""Producer wiring for ``EventType.JUDGE_REVIEW``.

When /agentic dispatches a judge panel (``--judge <model>``,
``--judge <m1> <m2>`` etc.) over the primary's analysis, the
``JudgeTask`` finalises a final verdict by majority vote across
(primary + judges). Disputes — where one or more participants
disagreed — are this producer's signal:

  * Primary's vote != final → primary's model gets ``incorrect``.
  * Primary's vote == final → primary's model gets ``correct``.
  * Each judge's vote vs final → same.

Single-judge mode is INTENTIONALLY SKIPPED. There the ``JudgeTask``
keeps the primary's verdict (``final = primary_exploitable``) and
just flags the dispute for operator review — there's no automated
truth signal worth recording. Multi-judge mode is where the panel
collectively overrules and the producer can attribute correctness.

Agreed findings produce no signal — every model voted the same way
so the cell would just bump uniformly without distinguishing models.
Same skip pattern as ``record_consensus_outcomes``.

Cells are keyed by ``agentic:<rule_id>``, shared with the
multi-model-consensus and prefilter producers; different event
slots (``JUDGE_REVIEW`` vs ``MULTI_MODEL_CONSENSUS`` vs
``CHEAP_SHORT_CIRCUIT``) keep their counters isolated. The
auto-policy gate's Wilson math runs over the cheap-tier slot
only — judge events do NOT shift the prefilter gate.
"""

from __future__ import annotations

import logging

from core.run.finding_status import read_verdict

from . import _MAX_REASONING_CHARS
from ._batch import record_event_batch
from .scorecard import EventType, ModelScorecard

logger = logging.getLogger(__name__)


def record_judge_outcomes(
    scorecard: ModelScorecard | None,
    *,
    results_by_id: dict[str, dict],
    primary_verdicts_before_judge: dict[str, bool | None],
    decision_class_prefix: str = "agentic",
) -> int:
    """Walk results that ran through ``JudgeTask``; record one
    ``JUDGE_REVIEW`` event per (model, finding) for disputed
    multi-judge findings.

    ``primary_verdicts_before_judge`` is a snapshot of each finding's
    primary verdict captured BEFORE ``JudgeTask`` ran — JudgeTask
    overwrites ``primary["is_exploitable"]`` with the final majority
    verdict, so we need the snapshot to know which way primary
    originally voted. ``None`` means the primary ABSTAINED (its
    analysis carried no verdict): it joins neither the vote count nor
    the event stream.

    Returns count of events written. No-op on ``scorecard=None``.
    """
    if scorecard is None or not results_by_id:
        return 0

    pending: list[dict] = []
    for fid, result in results_by_id.items():
        if not isinstance(result, dict) or "error" in result:
            continue
        if result.get("judge") != "disputed":
            continue

        judge_analyses = result.get("judge_analyses") or []
        if len(judge_analyses) < 2:
            # Single-judge disputes don't yield a panel-majority
            # signal — JudgeTask keeps the primary's verdict in that
            # case and only flags the dispute for operator review.
            # Recording a "primary correct, judge incorrect" event
            # would be wrong — the dispute is real, the resolution
            # isn't operator-trusted.
            continue

        if fid not in primary_verdicts_before_judge:
            # Defensive — caller didn't snapshot this finding. Skip
            # rather than mis-attribute against the now-overwritten
            # primary verdict.
            continue

        rule_id = str(result.get("rule_id") or "unknown")
        decision_class = f"{decision_class_prefix}:{rule_id}"
        final_verdict = read_verdict(result, "is_exploitable")
        if final_verdict is None:
            # The finalised verdict itself is an abstention (a tied
            # panel on an abstained primary) or a junk shape —
            # there is no majority outcome to score anyone against.
            continue
        # No attributable model → the primary's VOTE still counts in
        # the tie computation below, but no event is minted (a
        # literal "?"-keyed cell accumulates noise no producer ever
        # revisits — cmd_tool_evidence skips no-model records for
        # exactly this reason; this was sibling drift).
        primary_model = str(result.get("analysed_by") or "")
        # The snapshot preserves abstention: a None entry means the
        # primary's analysis carried no verdict (errored / refused /
        # schema-nulled) — the primary cast NO vote. bool()-coercing
        # it minted a "not exploitable" primary vote, which both
        # skewed the tie computation and wrote a fabricated primary
        # outcome into the ledger — scoring exploitable-voting judges
        # "incorrect" against a majority the primary never joined.
        primary_raw = primary_verdicts_before_judge[fid]
        # The snapshot contract is bool | None, but guard the
        # boundary anyway: a junk value must read as an abstention,
        # never a bool()-coerced phantom vote (which could break a
        # genuine judge tie and mint an event for a vote never cast).
        primary_vote: bool | None = (
            primary_raw if isinstance(primary_raw, bool) else None
        )

        # Abstention-aware voter list. A judge whose
        # ``is_exploitable`` is None (errored / refused /
        # schema-failed response — response_validation nulls the
        # field) cast NO vote: it must not join the tie computation
        # and must never receive a JUDGE_REVIEW event, which would
        # mint a reliability outcome for a vote never cast. Same
        # counting rule as ``tally_verdict_votes`` in
        # packages/llm_analysis/correlation.py (the contract
        # JudgeTask.finalize applies) — handled locally like the
        # consensus producer because a core/llm producer importing
        # packages.llm_analysis would invert the layering.
        voting_judges = [
            ja for ja in judge_analyses
            if read_verdict(ja, "is_exploitable") is not None
        ]
        if not voting_judges:
            # Whole panel abstained. JudgeTask marks these
            # ``judge == "no-verdict"`` so they shouldn't reach
            # here, but scoring the primary against its own
            # preserved verdict would mint self-corroboration —
            # skip defensively.
            continue

        # Exact tie across the ACTUAL voters (e.g. 2-vs-2): the
        # finalised verdict is a mechanical tie-break, not a panel
        # majority, so scoring voters against it would arbitrarily
        # declare one side "incorrect". Skip — same rationale as the
        # consensus producer's even-split skip. An abstained primary
        # contributes no vote here.
        votes = ([] if primary_vote is None else [primary_vote]) + [
            read_verdict(ja, "is_exploitable") for ja in voting_judges
        ]
        if len(votes) < 2:
            # Fewer than two real votes cannot define a majority —
            # recording the lone voter "correct" against a verdict
            # only it produced would mint self-corroboration (same
            # guard as the consensus producer).
            continue
        n_pos = sum(1 for v in votes if v)
        if n_pos * 2 == len(votes):
            continue

        # Primary's outcome — only when the primary actually voted
        # AND is attributable; an abstainer never receives a
        # JUDGE_REVIEW event.
        if primary_vote is not None and primary_model:
            primary_correct = (primary_vote == final_verdict)
            pending.append(_event(
                decision_class=decision_class,
                model=primary_model,
                model_version=result.get("resolved_model"),
                outcome="correct" if primary_correct else "incorrect",
                sample_reasoning=(
                    None if primary_correct
                    else str(result.get("reasoning") or "")
                ),
                other_summary=(
                    f"panel of {len(voting_judges)} judge(s) voted "
                    f"{'exploitable' if final_verdict else 'not exploitable'}"
                ),
            ))

        # Each voting judge's outcome (abstainers get no event).
        for ja in voting_judges:
            judge_model = str(ja.get("model") or "?")
            judge_vote = read_verdict(ja, "is_exploitable")
            judge_correct = (judge_vote == final_verdict)
            pending.append(_event(
                decision_class=decision_class,
                model=judge_model,
                model_version=ja.get("resolved_model"),
                outcome="correct" if judge_correct else "incorrect",
                sample_reasoning=(
                    None if judge_correct
                    else str(ja.get("reasoning") or "")
                ),
                other_summary=(
                    f"panel majority voted "
                    f"{'exploitable' if final_verdict else 'not exploitable'}"
                ),
            ))
    # One lock/load/verify/rewrite cycle for the whole run — a
    # disputed multi-judge run over hundreds of findings previously
    # paid that full cycle per event (see _batch's rationale).
    return record_event_batch(
        scorecard, pending, log=logger, producer="record_judge_outcomes",
    )


def _event(
    *,
    decision_class: str,
    model: str,
    outcome: str,
    sample_reasoning: str | None,
    other_summary: str,
    model_version: str | None = None,
) -> dict:
    """Build one ``record_events`` entry for a JUDGE_REVIEW outcome."""
    sample = None
    if outcome == "incorrect" and sample_reasoning is not None:
        sample = {
            "this_reasoning": sample_reasoning[:_MAX_REASONING_CHARS],
            "other_reasoning": other_summary,
        }
    return {
        "decision_class": decision_class,
        "model": model,
        "event_type": EventType.JUDGE_REVIEW,
        "outcome": outcome,
        "model_version": model_version,
        "sample": sample,
    }


__all__ = ["record_judge_outcomes"]
