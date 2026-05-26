"""Adapters that normalise a producer's record into a :class:`VerifiedOutcome`.

Only *core-typed* producers belong here (the witness now; the CodeQL/trust
record later) -- this keeps ``core`` free of ``packages`` imports. The
``/web`` adapter (live-HTTP) takes a ``packages``-level finding, so it lives
next to the web scanner when it lands, per the same layering rule
``core.witness`` follows.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from core.verified_outcome.types import Oracle, OutcomeStatus, VerifiedOutcome
from core.witness.types import Witness, WitnessOutcome, WitnessSource

if TYPE_CHECKING:  # type-only — keep core.verified_outcome import-cheap
    from core.dataflow.barrier_synth import BarrierProposal, SynthResult

# A run that triggered the bug is a positive verification; "ran but nothing
# fired" / "didn't run" / "unknown" is not decisive either way (it does not
# refute the finding -- the attempt simply failed to confirm it).
_TRIGGERED = frozenset({
    WitnessOutcome.SANITIZER_REPORT,
    WitnessOutcome.EXIT_SIGNAL,
    WitnessOutcome.FLAG_CAPTURED,
})


def _status_from_outcome(outcome: WitnessOutcome) -> OutcomeStatus:
    if outcome in _TRIGGERED:
        return OutcomeStatus.VERIFIED
    return OutcomeStatus.INCONCLUSIVE


def _oracle_from_source(source: WitnessSource) -> Oracle:
    if source is WitnessSource.FUZZ:
        return Oracle.FUZZER
    if source is WitnessSource.MANUAL:
        return Oracle.MANUAL
    # CRASH_REPLAY / VALIDATE_SKILL_POC / LLM_EMIT_RUN all run the target
    # under core.sandbox.
    return Oracle.SANDBOX


def from_witness(witness: Witness) -> VerifiedOutcome:
    """Project a :class:`~core.witness.types.Witness` onto a
    :class:`VerifiedOutcome`.

    The witness remains the backend of record for the raw bytes; ``evidence``
    carries a *reference* (``witness_bytes_hash``) plus the normalised
    outcome, not a copy of the bytes. Witness-backed outcomes are
    ``reproducible`` -- the bytes are hash-addressed and the run is
    deterministic by the witness contract.
    """
    detail = (
        witness.outcome_detail
        if isinstance(witness.outcome_detail, dict)
        else {}
    )

    evidence: dict = {
        "witness_bytes_hash": witness.bytes_hash,
        "observed_outcome": witness.observed_outcome.value,
        "source": witness.source.value,
        "bytes_len": witness.bytes_len,
    }
    for k in ("signal", "sanitizer", "stack_hash"):
        if k in detail:
            evidence[k] = detail[k]
    if witness.target_binary_hash:
        evidence["target_binary_hash"] = witness.target_binary_hash

    return VerifiedOutcome(
        finding_id=str(detail.get("finding_id") or ""),
        oracle=_oracle_from_source(witness.source),
        status=_status_from_outcome(witness.observed_outcome),
        reproducible=True,
        evidence=evidence,
        cwe_id=detail.get("cwe_id"),
        file=detail.get("file_path"),
        produced_by=witness.produced_by,
        timestamp=witness.timestamp,
    )


# barrier_synth's sink-class taxonomy -> CWE id, so CodeQL-oracle outcomes
# rank on cwe in retrieval (the proposal carries no explicit CWE/file).
_SINK_CLASS_CWE = {
    "cmdi": "CWE-78",
    "sqli": "CWE-89",
    "pathtrav": "CWE-22",
    "xss": "CWE-79",
}


def from_barrier_synthesis(
    proposal: "BarrierProposal",
    result: "SynthResult",
) -> VerifiedOutcome:
    """Project a CodeQL ``isBarrier`` adjudication onto a VerifiedOutcome.

    The trust/CodeQL oracle's "success" is *refuting* a finding: a sound
    barrier (suppresses the FP on the fixed build, preserves the TP on the
    vulnerable build) proves the flagged finding a false positive. This is the
    polymorphism the record exists for — where the sandbox oracle emits
    VERIFIED (the bug fires), this oracle emits REFUTED (sound FP). A barrier
    that compiled but isn't sound is INCONCLUSIVE (it didn't establish the
    suppression).

    Reproducible: CodeQL compiles + runs the query mechanically, so the
    verdict re-derives deterministically. Duck-typed on purpose (reads
    ``finding_id`` / ``sink_class`` / ``after_count`` / ``before_count`` /
    ``is_sound``) so this module never imports ``core.dataflow`` at load time.
    """
    sound = bool(result.is_sound)
    return VerifiedOutcome(
        finding_id=str(proposal.finding_id or ""),
        oracle=Oracle.CODEQL,
        status=OutcomeStatus.REFUTED if sound else OutcomeStatus.INCONCLUSIVE,
        reproducible=True,
        evidence={
            "mechanism": "isBarrier",
            "sink_class": proposal.sink_class,
            "after_count": result.after_count,
            "before_count": result.before_count,
            "suppressed_fp": bool(result.suppressed_fp),
            "preserved_tp": bool(result.preserved_tp),
        },
        cwe_id=_SINK_CLASS_CWE.get(proposal.sink_class),
        file=None,
    )
