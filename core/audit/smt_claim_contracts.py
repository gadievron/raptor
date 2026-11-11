"""Binding prerequisites for whole-claim SMT contract validation.

A None return means only that local binding checks passed. The caller must
still validate an executed result under the registered conclusion contract.
This helper neither runs a checker nor grants proof authority.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
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
class SMTContractAdapter:
    """Pipeline registration coupling declared coverage to its validator.

    Registrations are project-owned policy, never derived from model fields or
    receipt labels. The validator must check the actual result against the exact
    conclusion, obligation and source/model assumptions it declares covered.
    """

    contract: ClaimContract
    validate_conclusion: Callable[[ClaimVerification | ClaimRefutation, SweepResult, ClaimContext, str], object]


def adapt_smt_claim_fact(
    record: object, *, event: object, expected_context: ClaimContext,
    expected_scope: VerificationScope, expected_revision: ClaimRevision,
    result: object, contracts: Mapping[str, SMTContractAdapter],
) -> FactEvent | None:
    """Adapt an executed pipeline observation without inferring its authority.

    The caller supplies current admission context and an invocation-owned event
    from the parent-validated SMT execution. This function does not authenticate
    arbitrary deserialised producer dictionaries or build current dependencies.
    No registered validator means unknown, even for legacy positive receipts.
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
