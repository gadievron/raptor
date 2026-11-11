"""Typed SMT facts require current bindings and registered conclusion coverage.

Worker invocation identity is provenance, not semantic proof. Binding-only
prerequisite checks remain distinct from executed-result interpretation.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
import hashlib
from pathlib import PurePosixPath
from typing import TYPE_CHECKING

from .claim_adjudication import ClaimContext, ClaimContract, FactEvent
from .claim_verification import ClaimVerification
from .claims import ClaimRevision
from .refutation_source import SourceIdentity
from .smt_evidence import is_diagnostic_smt_rule, is_non_refuting_smt_rule
from .verification_results import ClaimRefutation, VerificationScope

if TYPE_CHECKING:
    from .sweep import SweepResult


def smt_claim_binding_rejection(
    record: object, *, expected_scope: VerificationScope, expected_revision: ClaimRevision,
) -> str | None:
    """Reject unknown/mismatched legacy bindings before contract validation.

    expected_scope/revision must be pipeline-owned current request context.
    Typed wrappers and matching names alone do not authenticate execution.
    """
    if not isinstance(expected_scope, VerificationScope) or not expected_scope.has_claim:
        return "request-scope-unavailable"
    if not isinstance(expected_scope.source_identity, SourceIdentity):
        return "request-source-unavailable"
    if not isinstance(expected_revision, ClaimRevision):
        return "request-revision-unavailable"
    if not expected_revision.matches_occurrence(
        file=expected_scope.file, function=expected_scope.function,
        line_start=expected_scope.line_start, hypothesis=expected_scope.hypothesis,
    ):
        return "request-revision-scope-mismatch"
    if isinstance(record, ClaimVerification):
        actual_scope = record.binding
        statement = record.hypothesis
    elif isinstance(record, ClaimRefutation):
        actual_scope = VerificationScope(record.file, record.function,
                                        record.line_start, record.hypothesis,
                                        record.source_identity)
        statement = record.claim_revision.hypothesis if record.claim_revision is not None else {}
    else:
        return "claim-record-type-unavailable"
    if not isinstance(actual_scope, VerificationScope) or not actual_scope.has_claim:
        return "producer-scope-unavailable"
    if not isinstance(actual_scope.source_identity, SourceIdentity):
        return "producer-source-unavailable"
    if actual_scope != expected_scope:
        return "producer-scope-or-source-mismatch"
    revision = record.claim_revision
    if not isinstance(revision, ClaimRevision):
        return "producer-revision-unavailable"
    if revision.reference() != expected_revision.reference() or statement != expected_revision.hypothesis:
        return "producer-revision-material-mismatch"
    return None


@dataclass(frozen=True)
class PreparedSMTAnchor:
    """Exact bytes from a pipeline-prepared source; no snapshot authority alone."""

    file: str
    source: SourceIdentity
    prepared_content: bytes
    byte_start: int
    byte_end: int
    expected_span: bytes


@dataclass(frozen=True)
class PreparedSMTAdmission:
    """Prepared claim inputs whose provenance the registered validator checks."""

    context: ClaimContext
    unit_id: str
    target_snapshot_id: str
    build_identity: str
    origin_pass_id: str
    statement: str
    anchors: tuple[PreparedSMTAnchor, ...]
    processing_status: str
    conclusion_signature: str


@dataclass(frozen=True)
class SMTValidatedConclusion:
    """A project validator's binding, never accepted from model JSON."""

    admission: PreparedSMTAdmission
    request_id: str
    executed_request_id: str
    raw_reference: str
    producer_kind: str
    execution_scope: str
    effect_scope: str
    validated_conclusion_signature: str


def _prepared_binding_matches(admission: object, context: ClaimContext,
                              scope: VerificationScope) -> bool:
    if not isinstance(admission, PreparedSMTAdmission) or admission.context != context:
        return False
    if (admission.processing_status != "admitted" or admission.statement != scope.hypothesis
            or not all(isinstance(value, str) and value.strip() for value in (
                admission.unit_id, admission.target_snapshot_id, admission.build_identity,
                admission.origin_pass_id, admission.statement, admission.conclusion_signature))
            or not isinstance(admission.anchors, tuple) or not admission.anchors):
        return False
    occurrence_anchored = False
    for anchor in admission.anchors:
        if not isinstance(anchor, PreparedSMTAnchor):
            return False
        if (not isinstance(anchor.file, str) or not anchor.file
                or PurePosixPath(anchor.file).is_absolute()
                or any(part in {"", ".", ".."} for part in anchor.file.split("/"))
                or not isinstance(anchor.source, SourceIdentity)
                or not isinstance(anchor.prepared_content, bytes)
                or len(anchor.prepared_content) > 10 * 1024 * 1024
                or type(anchor.byte_start) is not int or type(anchor.byte_end) is not int
                or not 0 <= anchor.byte_start < anchor.byte_end <= len(anchor.prepared_content)
                or not isinstance(anchor.expected_span, bytes) or not anchor.expected_span
                or anchor.prepared_content[anchor.byte_start:anchor.byte_end] != anchor.expected_span
                or hashlib.sha256(anchor.prepared_content).hexdigest() != anchor.source.sha256):
            return False
        if anchor.file == scope.file and anchor.source == scope.source_identity:
            # Byte offsets are exact; line counting follows the prepared source's
            # normalised LF model, including CRLF and bare CR inputs.
            prefix = anchor.prepared_content[:anchor.byte_start].replace(b"\r\n", b"\n").replace(b"\r", b"\n")
            occurrence_anchored |= prefix.count(b"\n") + 1 == scope.line_start
    return occurrence_anchored


@dataclass(frozen=True)
class SMTContractAdapter:
    """Pipeline registration coupling declared coverage to its validator.

    Registrations are project-owned policy, never derived from model fields or
    receipt labels. The validator must check the actual result against the exact
    conclusion, obligation and source/model assumptions it declares covered.
    """

    contract: ClaimContract
    validate_conclusion: Callable[[ClaimVerification | ClaimRefutation, SweepResult, ClaimContext, str], object]
    validate_prepared_admission: Callable[[PreparedSMTAdmission, SweepResult, FactEvent], object] | None = None
    effect_scopes: frozenset[str] = frozenset()



def adapt_smt_claim_fact(
    record: object, *, event: object, expected_context: ClaimContext,
    expected_scope: VerificationScope, expected_revision: ClaimRevision,
    result: object, contracts: Mapping[str, SMTContractAdapter],
    prepared_admission: PreparedSMTAdmission | None = None,
) -> FactEvent | None:
    """Adapt an executed pipeline observation without inferring its authority.

    The caller supplies current admission context and an invocation-owned event
    from the parent-validated SMT execution. This function does not authenticate
    arbitrary deserialised producer dictionaries or build current dependencies.
    The parent result must bind the same invocation as the event. Prepared exact
    anchors are checked against full source bytes; only project registration can
    certify snapshot/build provenance and complete conclusion meaning. No
    registered prepared/conclusion validators means unknown. This is not an
    authoritative publication switch.
    """
    from .sweep import SweepResult

    if not isinstance(event, FactEvent):
        return None
    fact = replace(event, semantic="unknown")
    if (not isinstance(expected_context, ClaimContext)
            or not isinstance(event.context, ClaimContext)
            or event.context != expected_context
            or smt_claim_binding_rejection(record, expected_scope=expected_scope,
                                           expected_revision=expected_revision) is not None):
        return fact
    if (expected_context.claim_id != expected_revision.claim_id
            or expected_context.revision_id != expected_revision.revision_id
            or expected_context.source != expected_scope.source_identity
            or expected_context.occurrence != (expected_scope.file, expected_scope.function, expected_scope.line_start)):
        return fact
    if (event.execution != "completed" or event.complete is not True
            or not isinstance(event.request_id, str) or not event.request_id.strip()
            or event.request_id != event.executed_request_id
            or not isinstance(event.raw_reference, str) or not event.raw_reference.strip()):
        return fact
    if not isinstance(contracts, Mapping):
        return fact
    registration = contracts.get(expected_context.contract)
    if not isinstance(registration, SMTContractAdapter) or not isinstance(registration.contract, ClaimContract):
        return fact
    contract = registration.contract
    if (not isinstance(contract.obligations, frozenset) or not isinstance(contract.negative_obligations, frozenset)
            or not contract.obligations or not contract.negative_obligations <= contract.obligations
            or not contract.adapter or not contract.version
            or event.adapter != contract.adapter or event.contract_version != contract.version
            or event.obligation not in contract.obligations
            or not callable(registration.validate_conclusion)):
        return fact
    if (not isinstance(result, SweepResult) or result.tool != "smt"
            or result.file_path != expected_scope.file or result.function_name != expected_scope.function
            or result.outcome not in {"confirmed", "refuted"}
            or not isinstance(result.rule_id, str) or not result.rule_id.startswith("smt:")
            or is_diagnostic_smt_rule(result.rule_id)):
        return fact
    details = result.details if isinstance(result.details, dict) else {}
    execution = details.get("smt_execution")
    if (not isinstance(execution, dict) or execution.get("identity_status") != "matched"
            or execution.get("scope") != "worker-invocation-only"
            or execution.get("request_id") != event.request_id
            or execution.get("executed_request_id") != event.executed_request_id):
        return fact
    if (not _prepared_binding_matches(prepared_admission, expected_context, expected_scope)
            or not isinstance(prepared_admission, PreparedSMTAdmission)
            or prepared_admission.origin_pass_id != expected_revision.pass_id
            or not callable(registration.validate_prepared_admission)
            or not isinstance(registration.effect_scopes, frozenset)
            or not registration.effect_scopes):
        return fact
    try:
        validated = registration.validate_prepared_admission(prepared_admission, result, event)
    except Exception:
        return fact
    if (not isinstance(validated, SMTValidatedConclusion)
            or validated.admission != prepared_admission
            or validated.request_id != event.request_id
            or validated.executed_request_id != event.executed_request_id
            or validated.raw_reference != event.raw_reference
            or validated.producer_kind != "mechanical_observation"
            or validated.execution_scope != "registered-worker-invocation"
            or validated.effect_scope not in registration.effect_scopes
            or validated.validated_conclusion_signature != prepared_admission.conclusion_signature):
        return fact
    if not isinstance(record, (ClaimVerification, ClaimRefutation)):
        return fact
    try:
        semantic = registration.validate_conclusion(record, result, expected_context, event.obligation)
    except Exception:
        return fact  # validator failure supplies no semantic conclusion
    if not isinstance(semantic, str):
        return fact
    if semantic == "supports_fact":
        return replace(fact, semantic=semantic)
    if (semantic == "contradicts_fact" and event.obligation in contract.negative_obligations
            and not is_non_refuting_smt_rule(result.rule_id)):
        return replace(fact, semantic=semantic)
    return fact
