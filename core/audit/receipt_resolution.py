"""Receipt matching and evidence dominance for post-loop verdict resolution.

This module owns receipt policy; the orchestrator owns pass ordering,
source loading, verdict mutation, counters, and journal writes.
"""

from __future__ import annotations

import logging
import re

logger = logging.getLogger(__name__)


def receipt_override(
    outcome, *, config, receipts, detector_findings=None,
    pre_evidence=None, source=None,
):
    """Evaluate the post-verification receipt decision without mutating
    the verdict. Shared by orchestration and offline regression replay.
    Callers supply the same-function receipts and captured source; this
    function does not dispatch tools or call an LLM.
    """
    from .refutation import rescue_self_refuted

    if outcome.status != "clean":
        return None
    verdict = rescue_self_refuted(
        outcome, config=config, negative_space=receipts,
        detector_findings=detector_findings, pre_evidence=pre_evidence,
        source=source, target_path=config.target_path,
        out_dir=config.out_dir, repo_trusted=config.repo_trusted,
        require_receipt=True,
    )
    if verdict is None and receipts:
        verdict = _receipt_corroborated_hypothesis(
            outcome, receipts, config=config, source=source,
        )
    return verdict

# Structural negative-space checkers whose receipts are precise enough
# to outrank an unverified self-refutation (the same families the
# review-time gate consumes via ctx["negative_space"]).
_STRUCTURAL_RECEIPT_CHECKS = frozenset({
    "auth_mode_registration",
    "url_boundary_composition",
    "shared_writer_race",
})


# A structural receipt names the concrete call sites whose gating is
# asymmetric ("2 add_view_no_menu() call(s) are gated on ...").
_RECEIPT_CALL_NAME_RE = re.compile(r"\b(\w+)\(\)\s+(?:call|perform)")

# Family bridge: the hypothesis must talk about the receipt's bug
# family, in the reviewer's own words — receipt check-type token stems
# rarely survive natural phrasing ("two Write calls without a lock"
# carries none of shared/writer/race).
_RECEIPT_FAMILY_HYP_RES = {
    "auth_mode_registration": re.compile(
        r"auth[\s_-]*(?:mode|type)|regist|reset|unconditional", re.IGNORECASE,
    ),
    "shared_writer_race": re.compile(
        r"concurren|race|interleav|unsynchron|\block\b|mutex|goroutine",
        re.IGNORECASE,
    ),
    "url_boundary_composition": re.compile(
        r"\burl\b|boundar|redirect|\bhost\b|origin", re.IGNORECASE,
    ),
}


def _receipt_corroborated_hypothesis(
    outcome, receipts, *, config=None, source=None,
):
    """Floor a clean verdict when the reviewer RAISED the receipt's
    exact shape and dismissed it without tool evidence.

    The anti-self-refutation gate only consumes confidence=refuted;
    the observed dismissal mode is different — the reviewer holds the
    matching hypothesis at low confidence and rules clean, so the
    receipt never reaches the verdict. Preconditions are deliberately
    tighter than the refuted clause: the hypothesis must name at least
    one of the concrete call sites the receipt flagged AND match the
    receipt family's token stems, and the outcome must carry no tool
    evidence. Returns a RefutationVerdict-shaped object or None.

    Same dominance rule as the in-gate receipt floors: the receipt
    outranks an UNVERIFIED dismissal, not a mechanical refuter. A
    proof-grade refuter of the receipt's claim family, or the
    race-protection witness corroborating a shared-writer dismissal
    on *source*, overrides the floor — the clean verdict stands and
    the overridden receipt is persisted (``dropped: false``) through
    the suppressions chokepoint.  Record-or-refuse: an override whose
    record cannot be written is refused and the floor stands.
    """
    from .evidence_grade import is_tool_evidence
    from .refutation import (
        RefutationVerdict,
        _dominating_refuter,
        _ProbeContext,
        _receipt_matches_mechanism,
        _record_floor_dominance,
    )

    if is_tool_evidence(outcome.evidence_tool or ""):
        return None
    hypotheses = getattr(outcome, "hypotheses", None) or []
    if not hypotheses and outcome.review_result:
        hypotheses = outcome.review_result.get("hypotheses") or []

    probe_ctx = _ProbeContext(
        source=source,
        target_path=getattr(config, "target_path", None) if config else None,
        repo_trusted=bool(getattr(config, "repo_trusted", False)),
    )

    race_protected = False
    if source:
        try:
            from .condition_smt import check_race_protection
            race_protected = check_race_protection(source).protected
        except Exception:
            logger.debug("race-protection probe failed", exc_info=True)

    for receipt in receipts:
        check_type = receipt.get("check_type", "")
        called = set(
            _RECEIPT_CALL_NAME_RE.findall(receipt.get("evidence", "")),
        )
        if not called:
            continue
        family_re = _RECEIPT_FAMILY_HYP_RES.get(check_type)
        for h in hypotheses:
            if not isinstance(h, dict):
                continue
            mechanism = h.get("mechanism", "") or ""
            call_overlap = any(
                re.search(rf"\b{re.escape(c)}\b", mechanism)
                for c in called
            )
            # Two corroboration routes: the check-type's own token
            # stems in the hypothesis (strong — reviewer used the
            # receipt's vocabulary), or the concrete call-site overlap
            # plus the family keyword bridge (natural phrasing).
            strong_stem = _receipt_matches_mechanism(
                check_type, mechanism,
            )
            if not (
                strong_stem
                or (call_overlap and family_re
                    and family_re.search(mechanism))
            ):
                continue
            # Dominance: a proof-grade refuter of the receipt's
            # family outranks the detection-grade receipt — the
            # clean verdict stands, demote-with-record.
            # Record-or-refuse: an override whose record cannot be
            # written is refused (the floor stands) — an unrecorded
            # override would be silent.
            refuter = _dominating_refuter(
                outcome, h, check_type, ctx=probe_ctx,
            )
            if refuter is not None and _record_floor_dominance(
                outcome, config,
                refuter=refuter, receipt=check_type,
                floor_gate="receipt_corroborated_hypothesis",
            ):
                logger.info(
                    "receipt floor overridden for %s:%s — %s (%s) "
                    "dominates %s",
                    outcome.file, outcome.function,
                    refuter.gate, refuter.refuter_grade, check_type,
                )
                continue
            if refuter is not None:
                logger.info(
                    "receipt floor dominance for %s:%s refused — "
                    "demote-with-record could not write its record",
                    outcome.file, outcome.function,
                )
            # Witness discharge, same authority the anti-self-
            # refutation gate grants mechanically corroborated
            # dismissals: when every shared-state access in the
            # source is lock-protected, a shared-writer dismissal
            # is corroborated, not unverified — re-flooring it
            # manufactures a false positive.  Accept-with-record or
            # nothing, same as the dominance route.
            if (
                refuter is None
                and race_protected
                and check_type == "shared_writer_race"
                and _record_floor_dominance(
                    outcome, config,
                    refuter=RefutationVerdict(
                        gate="race_protection_witness",
                        reason=(
                            "every shared-state access in the "
                            "function is mechanically lock-protected"
                        ),
                        demote_to="clean",
                    ),
                    receipt=check_type,
                    floor_gate="receipt_corroborated_hypothesis",
                    verdict="witness_corroborates_dismissal",
                    reason=(
                        f"receipt floor overridden: the dismissal is "
                        f"mechanically corroborated by the race-"
                        f"protection witness (every shared-state "
                        f"access lock-protected); the {check_type} "
                        f"receipt does not outrank a corroborated "
                        f"dismissal"
                    ),
                )
            ):
                logger.info(
                    "receipt floor overridden for %s:%s — race-"
                    "protection witness corroborates the dismissal "
                    "(%s receipt does not outrank it)",
                    outcome.file, outcome.function, check_type,
                )
                continue
            return RefutationVerdict(
                gate="receipt_corroborated_hypothesis",
                reason=(
                    f"reviewer raised the exact shape an active "
                    f"{check_type} receipt flags (same call sites: "
                    f"{', '.join(sorted(called & _mechanism_calls(mechanism, called)))}) "
                    f"and dismissed it without tool evidence; the "
                    f"structural receipt outranks the dismissal"
                ),
                demote_to="suspicious",
            )
    return None


def _mechanism_calls(mechanism: str, called: set) -> set:
    """Subset of *called* names the hypothesis mechanism mentions."""
    return {
        c for c in called
        if re.search(rf"\b{re.escape(c)}\b", mechanism)
    }
