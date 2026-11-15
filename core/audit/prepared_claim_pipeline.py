"""Run-owned preparation availability and nonauthoritative existing-result inputs.

Preparation producers supply measured bindings and an independently current
accessor. Missing build/dependency facts are never reconstructed from a source
hash, ABI selection, cache key or checker response.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict, dataclass
from pathlib import Path
from threading import RLock
from uuid import uuid4

from .claim_support_contracts import PreparedTargetBinding
from .prepared_claim_context import (
    CONTRACT_ID,
    OBLIGATION,
    CurrentPrepared,
    PreparationUnavailable,
    PreparedOverflowContext,
    prepare_overflow_claim_context,
)
from .refutation_source import capture_source_identity
from .smt_claim_contracts import (
    PreparedSMTAnchor,
    adapt_smt_claim_fact,
    smt_fact_from_result,
)


@dataclass(frozen=True)
class _Staged:
    target: PreparedTargetBinding
    anchor: PreparedSMTAnchor
    current: CurrentPrepared


class PreparedClaimPipeline:
    """One run's explicit preparation inputs; never a process-global registry.

    ``stage`` accepts only producer-owned inputs, not model/tool JSON. The
    accessor must re-read the complete preparation epoch (including build,
    dependencies and assumptions), rather than echo the staged pair. Source
    freshness is additionally checked here against the current confined file.
    """

    def __init__(self, target_path: Path, out_dir: Path | None):
        self.target_path = Path(target_path)
        self.out_dir = Path(out_dir) if out_dir is not None else None
        self._lock = RLock()
        self._staged: dict[tuple, _Staged] = {}
        self._observed: list[tuple] = []
        self._conditional_run = None

    def _record_conditional_phase(self, outcome, phase, *, origin=None, enabled=None):
        """Sanitised phase metadata, outside owner locks; never checker input."""
        from .conditional_claim_pipeline import DELIVERY_FIELD, request_field_diagnostic
        from .knowledge_requests import KnowledgeOrigin
        if (self.out_dir is None or (outcome.file, outcome.function)
                != ("protocol/parser.c", "parse_header")):
            return
        review = outcome.review_result
        delivery = review.get(DELIVERY_FIELD) if type(review) is dict else None
        if (self._conditional_run is None and not (type(delivery) is dict
                and delivery.get("schema_offered") is True)
                and not (type(review) is dict and "conditional_verification_requests" in review)):
            return
        snapshot = self._conditional_run.phase_diagnostic(outcome) if self._conditional_run else {
            "grant_current": False, "active_count": 0, "pending_count": 0,
            "availability_reason": None, "entry_reasons": [], "pass_id": None}
        if type(origin) is KnowledgeOrigin:
            snapshot["pass_id"] = origin.pass_id
        from .record import append_audit_log
        import logging
        try:
            append_audit_log(self.out_dir, {"action": "conditional_phase_diagnostic",
                "role": "availability-only-not-authority", "phase": phase,
                "file": "protocol/parser.c", "function": "parse_header",
                "line": outcome.line if type(outcome.line) is int else None,
                "schema_offered": type(delivery) is dict and delivery.get("schema_offered") is True,
                "enabled": enabled if type(enabled) is bool else None,
                **request_field_diagnostic(review), **snapshot})
        except (OSError, ValueError):
            logging.getLogger(__name__).warning("conditional phase diagnostic unavailable")

    def bind_conditional_live_review(self, outcome, origin):
        """Bind only at the owned real review-return seam, before IHV issuance."""
        review = outcome.review_result
        requested = type(review) is dict and "conditional_verification_requests" in review
        if self._conditional_run is None and not requested:
            self._record_conditional_phase(outcome, "review-return", origin=origin)
            return
        if self._conditional_run is None:
            from .conditional_claim_pipeline import ConditionalClaimRun
            with self._lock:
                if self._conditional_run is None:
                    self._conditional_run = ConditionalClaimRun(self.target_path, self.out_dir)
        self._conditional_run.bind_live_review(outcome, origin)
        self._record_conditional_phase(outcome, "review-return", origin=origin)

    def intake_conditional_live(self, outcome, *, enabled):
        """Separate explicit live request schema; no legacy material adaptation."""
        review = outcome.review_result
        requested = type(review) is dict and "conditional_verification_requests" in review
        if self._conditional_run is None and (not requested or enabled is not True):
            self._record_conditional_phase(outcome, "intake", enabled=enabled)
            return
        if self._conditional_run is None:
            from .conditional_claim_pipeline import ConditionalClaimRun
            with self._lock:
                if self._conditional_run is None:
                    self._conditional_run = ConditionalClaimRun(self.target_path, self.out_dir)
        self._conditional_run.intake_live(outcome, enabled=enabled)
        self._record_conditional_phase(outcome, "intake", enabled=enabled)

    def conditional_shadow_inputs(self, claim_index):
        """Only privately executed conditional run state, never supplied facts."""
        run = self._conditional_run
        return run.shadow_inputs(claim_index) if run is not None else ([], [], {}, [])

    @staticmethod
    def _key(record):
        revision = record.claim_revision
        return (
            revision.reference()["claim_id"],
            revision.reference()["revision_id"],
            record.binding,
        )

    def stage(
        self, record, *, target, anchor, current_prepared: CurrentPrepared
    ) -> None:
        """Stage an existing typed producer pair; this does not admit support."""
        if not callable(current_prepared):
            raise TypeError("preparation requires an independently current accessor")
        with self._lock:
            self._staged[self._key(record)] = _Staged(target, anchor, current_prepared)

    def stage_from_capture(self, record, capture_owner, reference):
        """Consume only privately admitted capture inputs, never CP metadata.

        The production capture source/admission remain unavailable by default.
        A refused replacement clears prior staging for this claim rather than
        silently reusing evidence from an earlier preparation attempt.
        """
        from .prepared_build_capture import BuildCaptureUnavailable, PreparedBuildCaptureOwner

        try:
            key = self._key(record)
        except Exception:
            return PreparationUnavailable("prepared-capture-claim-unavailable")
        with self._lock:
            self._staged.pop(key, None)
        if type(capture_owner) is not PreparedBuildCaptureOwner:
            return PreparationUnavailable("prepared-capture-owner-unavailable")
        admitted = capture_owner.for_pipeline(record, reference)
        if isinstance(admitted, BuildCaptureUnavailable):
            return PreparationUnavailable(admitted.reason)
        self.stage(record, target=admitted.target, anchor=admitted.anchor,
                   current_prepared=admitted.current)
        return None

    def prepare(self, record, *, integer_abi):
        if self.out_dir is None:
            return PreparationUnavailable("durable-output-unavailable")
        if record.claim_revision is None:
            return PreparationUnavailable("request-revision-unavailable")
        with self._lock:
            staged = self._staged.get(self._key(record))
        if staged is None:
            return PreparationUnavailable(
                "prepared-target-build-or-dependencies-unavailable"
            )

        def current():
            pair = staged.current()
            if (
                not isinstance(pair, tuple)
                or len(pair) != 2
                or capture_source_identity(self.target_path, record.binding.file)
                != record.binding.source_identity
            ):
                return None
            return pair

        try:
            return prepare_overflow_claim_context(
                revision=record.claim_revision,
                scope=record.binding,
                target=staged.target,
                anchor=staged.anchor,
                integer_abi=integer_abi,
                current_prepared=current,
            )
        except Exception:
            return PreparationUnavailable("prepared-context-unavailable")

    def observe(self, record, result, *, prepared, integer_abi) -> None:
        """Retain one existing result, without executing or altering a checker."""
        from .prepared_result_retention import retain_smt_result

        event = None
        out_dir = self.out_dir
        retention_failed = False

        def retain(snapshot):
            nonlocal retention_failed
            try:
                return retain_smt_result(out_dir, snapshot)
            except Exception:
                retention_failed = True
                raise

        try:
            snapshot = (
                deepcopy(result)
                if isinstance(prepared, PreparedOverflowContext)
                else None
            )
            if isinstance(prepared, PreparedOverflowContext) and out_dir is not None:
                event = smt_fact_from_result(
                    record,
                    result=result,
                    event_id=str(uuid4()),
                    obligation=OBLIGATION,
                    expected_context=prepared.context,
                    expected_scope=record.binding,
                    expected_revision=record.claim_revision,
                    contracts=prepared.contracts,
                    prepared_admission=prepared.admission,
                    expected_target=prepared.target,
                    expected_conclusion=prepared.conclusion,
                    retain_result=retain,
                )
        except Exception:
            snapshot = None
            prepared = PreparationUnavailable("result-retention-unavailable")
        if retention_failed:
            snapshot = None
            event = None
            prepared = PreparationUnavailable("result-retention-unavailable")
        with self._lock:
            self._observed.append((record, snapshot, prepared, event, integer_abi))

    def shadow_inputs(self):
        """Revalidate current inputs and durable bytes at the publication boundary."""
        from .prepared_result_retention import retained_smt_result_matches

        contexts, events, contracts, availability = [], [], {}, []
        with self._lock:
            rows = list(self._observed)
        for record, result, prior, event, abi in rows:
            projected_event = None
            current = self.prepare(record, integer_abi=abi)
            reason = "unknown-result"
            if isinstance(current, PreparationUnavailable):
                reason = current.reason
            elif isinstance(prior, PreparationUnavailable):
                reason = prior.reason
            if (
                isinstance(current, PreparedOverflowContext)
                and isinstance(prior, PreparedOverflowContext)
                and current.context == prior.context
                and current.target == prior.target
                and current.admission == prior.admission
                and current.conclusion == prior.conclusion
                and event is not None
                and self.out_dir is not None
                and retained_smt_result_matches(
                    self.out_dir, event.raw_reference, result
                )
            ):
                refreshed = adapt_smt_claim_fact(
                    record,
                    event=event,
                    expected_context=current.context,
                    expected_scope=record.binding,
                    expected_revision=record.claim_revision,
                    result=result,
                    contracts=current.contracts,
                    prepared_admission=current.admission,
                    expected_target=current.target,
                    expected_conclusion=current.conclusion,
                )
                if refreshed is not None:
                    projected_event = asdict(refreshed)
                    contexts.append(current.context)
                    events.append(refreshed)
                    contracts[CONTRACT_ID] = current.contracts[CONTRACT_ID].contract
                    reason = "retained-" + refreshed.semantic
            reference = (
                record.claim_revision.reference()
                if record.claim_revision is not None
                else None
            )
            availability.append(
                {
                    "claim_reference": reference,
                    "fact_event": projected_event,
                    "prepared_target": asdict(current.target)
                    if isinstance(current, PreparedOverflowContext)
                    else None,
                    "requested_conclusion": asdict(current.conclusion)
                    if isinstance(current, PreparedOverflowContext)
                    else None,
                    "reason": reason,
                    "assessment": "shadow-only",
                    "authoritative": False,
                    "representation": current.target.representation
                    if isinstance(current, PreparedOverflowContext)
                    else "unavailable",
                    "applicability_domain": current.target.applicability_domain
                    if isinstance(current, PreparedOverflowContext)
                    else "unavailable",
                    "effect_scope": current.conclusion.effect_scope
                    if isinstance(current, PreparedOverflowContext)
                    else "unavailable",
                }
            )
        return contexts, events, contracts, availability
