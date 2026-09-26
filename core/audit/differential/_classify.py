"""Directional comparison over authenticated member observations.

The classifier consumes only what the witness harness protocol
reported (``DarkVerifyResult.observed_status`` and its accompanying
value), never member stdout, and renders the four verdicts described
in :mod:`._types`. Directionality is deliberately narrow: the ONLY
confirming pattern is "the deviant accepted what every executed
conforming peer rejected", under a contract that compares acceptance.
Everything else that diverges is nondirectional, and agreement is
never more than a failure to promote.
"""

from __future__ import annotations

from typing import Any

from ._rails import MIN_CONFORMING_EXECUTED
from ._types import (
    CONTRACT_RETURN_EQUIVALENCE,
    OBS_ACCEPT,
    OBS_ERROR,
    OBS_REJECT,
    VERDICT_CONFIRMED,
    VERDICT_FAMILY_AGREES,
    VERDICT_INCONCLUSIVE,
    VERDICT_NONDIRECTIONAL,
    LeadVerdict,
    MemberObservation,
    VectorVerdict,
)


def observation_from_result(
    result: Any, *, member: str, file: str,
) -> MemberObservation:
    """One member's observation, derived ONLY from the authenticated
    protocol status of its witness result.

    ``returned`` is the member accepting the vector; ``exception`` is
    the member rejecting it. EVERYTHING else — crash, timeout,
    sandbox refusal, import/binding failure, a vector that never
    bound the member's signature (``arg_binding_error``: the call
    boundary refused the arguments before the member body ran, so the
    "rejection" characterises the shared vector's fit, not the
    member's semantics), unauthenticated or malformed output — is a
    member error: a segfaulting or unloadable
    member never counts as an accept (that would mint divergence out
    of breakage) and never counts as a reject (that would mint
    agreement out of breakage), so it can only poison the vector.
    """
    status = getattr(result, "observed_status", "")
    detail = getattr(result, "match_detail", "")
    if status == "returned":
        return MemberObservation(
            member=member, file=file, kind=OBS_ACCEPT,
            value=getattr(result, "actual_return", ""), detail=detail,
        )
    if status == "exception":
        return MemberObservation(
            member=member, file=file, kind=OBS_REJECT,
            value=getattr(result, "actual_exception", ""),
            detail=detail,
        )
    return MemberObservation(
        member=member, file=file, kind=OBS_ERROR,
        detail=detail or f"no authenticated observation ({status!r})",
    )


def classify_vector(
    contract: str,
    deviant: MemberObservation | None,
    conforming: list[MemberObservation],
    *,
    vector_index: int,
) -> VectorVerdict:
    """The comparison verdict for one shared vector (fail-closed:
    any member error, or a missed conforming quorum, is
    inconclusive)."""

    def _v(verdict: str, reason: str) -> VectorVerdict:
        return VectorVerdict(
            vector_index=vector_index, verdict=verdict, reason=reason,
            contract=contract, deviant=deviant,
            conforming=list(conforming),
        )

    if deviant is None or deviant.kind == OBS_ERROR:
        return _v(
            VERDICT_INCONCLUSIVE,
            "deviant did not execute validly"
            + (f": {deviant.detail}" if deviant else ""),
        )
    broken = [o for o in conforming if o.kind == OBS_ERROR]
    if broken:
        return _v(
            VERDICT_INCONCLUSIVE,
            f"conforming member(s) did not execute validly: "
            f"{', '.join(o.member for o in broken[:3])}",
        )
    if len(conforming) < MIN_CONFORMING_EXECUTED:
        return _v(
            VERDICT_INCONCLUSIVE,
            f"{len(conforming)} conforming member(s) executed; "
            f"need {MIN_CONFORMING_EXECUTED}",
        )

    kinds = {o.kind for o in conforming}

    if contract == CONTRACT_RETURN_EQUIVALENCE:
        # A value contract never confirms: return-value differences
        # (and kind mixes under a value comparison) have no security
        # direction the classifier can vouch for.
        if kinds == {deviant.kind}:
            if deviant.kind == OBS_REJECT:
                return _v(
                    VERDICT_FAMILY_AGREES,
                    "every member rejected the vector",
                )
            values = {o.value for o in conforming}
            if values == {deviant.value}:
                return _v(
                    VERDICT_FAMILY_AGREES,
                    "every member returned the same value",
                )
            if len(values) > 1:
                return _v(
                    VERDICT_NONDIRECTIONAL,
                    "conforming members returned differing values",
                )
            return _v(
                VERDICT_NONDIRECTIONAL,
                "deviant returned a different value than its peers",
            )
        return _v(
            VERDICT_NONDIRECTIONAL,
            "members diverged between returning and rejecting",
        )

    # Acceptance contracts (accept-reject-equivalence and
    # exception-parity share the axis): the single confirming
    # pattern is deviant-accepts / every-peer-rejects.
    if deviant.kind == OBS_ACCEPT and kinds == {OBS_REJECT}:
        return _v(
            VERDICT_CONFIRMED,
            f"deviant accepted the vector; all "
            f"{len(conforming)} executed conforming members "
            f"rejected it",
        )
    if kinds == {deviant.kind}:
        return _v(
            VERDICT_FAMILY_AGREES,
            "every member handled the vector identically "
            f"({deviant.kind})",
        )
    if deviant.kind == OBS_REJECT and kinds == {OBS_ACCEPT}:
        return _v(
            VERDICT_NONDIRECTIONAL,
            "deviant is stricter than its peers (rejected what "
            "they accepted)",
        )
    return _v(
        VERDICT_NONDIRECTIONAL,
        "conforming members disagreed among themselves",
    )


def classify_lead(
    contract: str,
    vectors: list[VectorVerdict],
    *,
    family_floor: int,
    excluded: list[dict[str, str]] | None = None,
) -> LeadVerdict:
    """Fold a lead's vector verdicts.

    Verdict order is fixed: one confirmed vector confirms the lead
    (a real directional divergence is not undone by other vectors
    agreeing — most inputs NOT triggering a bug is the normal shape
    of a bug); otherwise any divergence is nondirectional; otherwise
    unanimous clean agreement is family-agrees; otherwise nothing
    classified. ``meets_family_floor`` is computed only for the
    confirmed case — it is the promotion gate's input, and holds the
    deciding vector's executed conforming subset ALONE to the census
    family floor (a verdict never borrows unexecuted members to meet
    a floor).
    """
    lead = LeadVerdict(
        verdict=VERDICT_INCONCLUSIVE,
        reason="no vector classified",
        contract=contract,
        vectors=list(vectors),
        excluded=list(excluded or []),
        family_floor=family_floor,
    )
    clean = [v for v in vectors if v.verdict != VERDICT_INCONCLUSIVE]
    if not clean:
        if vectors:
            lead.reason = vectors[0].reason
        return lead

    confirmed = [v for v in clean if v.verdict == VERDICT_CONFIRMED]
    if confirmed:
        deciding = confirmed[0]
        lead.verdict = VERDICT_CONFIRMED
        lead.reason = deciding.reason
        lead.executed_conforming = len(deciding.conforming)
        lead.meets_family_floor = (
            lead.executed_conforming >= family_floor
            and lead.executed_conforming >= MIN_CONFORMING_EXECUTED
        )
        return lead

    lead.executed_conforming = max(len(v.conforming) for v in clean)
    diverging = [
        v for v in clean if v.verdict == VERDICT_NONDIRECTIONAL
    ]
    if diverging:
        lead.verdict = VERDICT_NONDIRECTIONAL
        lead.reason = diverging[0].reason
        return lead

    lead.verdict = VERDICT_FAMILY_AGREES
    lead.reason = (
        f"all {len(clean)} classified vector(s) agree across the "
        f"family"
    )
    return lead
