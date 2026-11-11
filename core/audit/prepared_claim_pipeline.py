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
                    retain_result=lambda snapshot: retain_smt_result(out_dir, snapshot),
                )
        except Exception:
            snapshot = None
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
            reason = (
                current.reason
                if isinstance(current, PreparationUnavailable)
                else "unknown-result"
            )
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
