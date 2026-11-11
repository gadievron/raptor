"""Prepare one source-entry arithmetic predicate from pipeline-owned inputs.

This module neither discovers a target/build manifest nor retains tool output.
The current_prepared callback must atomically return the target and source anchor
from ONE independently prepared manifest epoch. A file digest/ABI is not a
substitute for target/build identity. Unknown context stays unavailable.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from types import MappingProxyType
import re

from .arithmetic_claim import ArithmeticClaim, parse_overflow_claim
from .arithmetic_operation import ArithmeticOperation, bind_arithmetic_operation
from .claim_adjudication import ClaimContext, ClaimContract, FactEvent
from .claim_support_contracts import ConclusionSignature, ExecutedSupportBinding, PreparedTargetBinding
from .claims import ClaimRevision
from .condition_extraction import language_for_file
from .integer_abi import IntegerABIInput, integer_abi_key, integer_abi_record, resolve_integer_abi
from .integer_witness import source_model_scope, validate_overflow_result
from .smt_claim_contracts import (
    PreparedSMTAdmission, PreparedSMTAnchor, SMTContractAdapter, SMTValidatedConclusion,
    _prepared_binding_matches, smt_claim_binding_rejection,
)
from .verification_results import VerificationScope
from .probe_function_scope import source_for_function, source_binding
from .refutation_source import SourceIdentity

CONTRACT_ID = "source-entry-arithmetic-overflow-v1"
OBLIGATION = "entry-arithmetic-out-of-range"
EFFECT_SCOPE = "function-entry-source-model"
IDENTITY = ("mechanical_observation", "smt", "check-overflow-v1",
            "entry-arithmetic-overflow", "v1", "registered-worker-invocation")
CurrentPrepared = Callable[[], tuple[PreparedTargetBinding, PreparedSMTAnchor] | None]


@dataclass(frozen=True)
class PreparationUnavailable:
    reason: str


@dataclass(frozen=True)
class PreparedOverflowContext:
    context: ClaimContext
    admission: PreparedSMTAdmission
    target: PreparedTargetBinding
    conclusion: ConclusionSignature
    contracts: Mapping[str, SMTContractAdapter]


def _nonempty_text(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _target_valid(target: object) -> bool:
    return (isinstance(target, PreparedTargetBinding)
            and all(_nonempty_text(value) for value in (
                target.unit_id, target.target_snapshot_id, target.build_identity))
            and target.representation == "source"
            and target.applicability_domain == "source-language"
            and all(isinstance(value, tuple) and all(_nonempty_text(item) for item in value)
                    for value in (target.dependencies, target.assumptions, target.correspondence_ids))
            and bool(target.dependencies))


def _current_matches(current: CurrentPrepared, target: PreparedTargetBinding,
                     anchor: PreparedSMTAnchor) -> bool:
    try:
        actual = current()
    except Exception:
        return False
    return (isinstance(actual, tuple) and len(actual) == 2
            and actual == (target, anchor))


def _claim(statement: str) -> ArithmeticClaim | None:
    # Do not turn a broader model claim into this narrow fact by parsing a prefix.
    if re.fullmatch(r"integer overflow in `[^`\r\n]+`", statement) is None:
        return None
    claim = parse_overflow_claim(statement)
    if claim is None:
        return None
    canonical = f"integer overflow in `{claim.operands[0]} {claim.operator} {claim.operands[1]}`"
    return claim if statement == canonical else None


def _operation_details(operation: ArithmeticOperation, integer_abi: IntegerABIInput) -> dict:
    return {"line": operation.line, "column": operation.column,
            "guards": list(operation.premises), "profile": operation.profile,
            "kind": operation.kind, "types": dict(operation.types),
            "domains": list(operation.domains), "integer_abi": integer_abi_record(integer_abi)}


def _conditions(target: PreparedTargetBinding, operation: ArithmeticOperation,
                integer_abi: IntegerABIInput) -> tuple[str, ...]:
    return (target.assumptions + ("integer-abi:" + integer_abi_key(integer_abi),
                                  "result-profile:" + operation.profile,
                                  "operation-kind:" + operation.kind)
            + tuple("guard:" + value for value in operation.premises)
            + tuple("domain:" + value for value in operation.domains)
            + tuple("type:" + name + ":" + spelling for name, spelling in operation.types))


def prepare_overflow_claim_context(
    *, revision: ClaimRevision, scope: VerificationScope, anchor: PreparedSMTAnchor,
    target: PreparedTargetBinding | None, integer_abi: IntegerABIInput,
    current_prepared: CurrentPrepared | None,
) -> PreparedOverflowContext | PreparationUnavailable:
    """Construct existing SMT wrappers; no actual manifest is invented here.

    current_prepared is pipeline-owned and atomic across target+anchor. Its
    independently prepared snapshot is checked at construction and on every
    validator invocation. The lead still owns durable retention and publication.
    Missing registration for any other claim leaves that concern reportable.
    """
    if not _target_valid(target) or not isinstance(target, PreparedTargetBinding):
        return PreparationUnavailable("prepared-target-build-or-dependencies-unavailable")
    if not callable(current_prepared) or not isinstance(anchor, PreparedSMTAnchor):
        return PreparationUnavailable("atomic-current-prepared-inputs-unavailable")
    if not _current_matches(current_prepared, target, anchor):
        return PreparationUnavailable("current-prepared-inputs-mismatch")
    if (not isinstance(revision, ClaimRevision) or not isinstance(scope, VerificationScope)
            or not all(_nonempty_text(value) for value in (scope.file, scope.function, scope.hypothesis))
            or type(scope.line_start) is not int or scope.line_start < 1
            or not scope.has_claim or not revision.matches_occurrence(
                file=scope.file, function=scope.function, line_start=scope.line_start,
                hypothesis=scope.hypothesis)):
        return PreparationUnavailable("pipeline-claim-occurrence-unavailable")
    if not isinstance(scope.source_identity, SourceIdentity):
        return PreparationUnavailable("current-source-identity-unavailable")
    claim = _claim(scope.hypothesis)
    if claim is None:
        return PreparationUnavailable("unsupported-conclusion-shape")
    integer_abi = resolve_integer_abi(integer_abi)
    if integer_abi is None:
        return PreparationUnavailable("integer-abi-unavailable")
    abi_condition = "integer-abi:" + integer_abi_key(integer_abi)
    if abi_condition not in target.dependencies and abi_condition not in target.assumptions:
        return PreparationUnavailable("prepared-integer-abi-binding-unavailable")
    required = tuple(source_model_scope()["assumptions"])
    if not set(required) <= set(target.assumptions):
        return PreparationUnavailable("source-model-assumptions-unavailable")
    context = ClaimContext(revision.claim_id, revision.revision_id, scope.source_identity,
                           CONTRACT_ID, target.dependencies, target.assumptions,
                           (scope.file, scope.function, scope.line_start), revision.parent_revision)
    admission = PreparedSMTAdmission(context, target.unit_id, target.target_snapshot_id,
                                    target.build_identity, revision.pass_id, scope.hypothesis,
                                    (anchor,), "admitted", CONTRACT_ID, target, None)
    if not _prepared_binding_matches(admission, context, scope):
        return PreparationUnavailable("prepared-exact-source-anchor-unavailable")
    try:
        source = anchor.expected_span.decode("utf-8")
    except UnicodeError:
        return PreparationUnavailable("prepared-source-encoding-unavailable")
    selected_scope, selected_source = source_for_function(source, scope.file, scope.function)
    if selected_source is None or selected_scope.status != "selected":
        return PreparationUnavailable("prepared-function-occurrence-unavailable")
    source = selected_source
    expected_source_binding = source_binding(source, scope.function, verb="check-overflow",
                                             integer_abi=integer_abi, hypothesis=scope.hypothesis)
    operation = bind_arithmetic_operation(source, claim.operands, claim.operator,
                                         language=language_for_file(scope.file), integer_abi=integer_abi)
    if (operation.status != "bound" or operation.type_status != "bound"
            or operation.guard_status == "unavailable"):
        return PreparationUnavailable("source-operation-unavailable")
    conclusion = ConclusionSignature(scope.hypothesis, "entry-arithmetic-overflow", EFFECT_SCOPE,
                                     _conditions(target, operation, integer_abi))
    admission = replace(admission, requested_conclusion=conclusion)

    def validates(actual: object) -> bool:
        from .sweep import SweepResult
        if (not _current_matches(current_prepared, target, anchor)
                or not isinstance(actual, SweepResult) or actual.tool != "smt"
                or actual.rule_id != "smt:check-overflow" or actual.outcome != "confirmed"
                or actual.errors or (actual.file_path, actual.function_name) != (scope.file, scope.function)):
            return False
        rebound = bind_arithmetic_operation(source, claim.operands, claim.operator,
                                            language=language_for_file(scope.file), integer_abi=integer_abi)
        if rebound != operation:
            return False
        details = actual.details if isinstance(actual.details, dict) else {}
        if details.get("source_scope") != expected_source_binding:
            return False
        scope_values = source_model_scope()
        if any(details.get(key) != value for key, value in scope_values.items()):
            return False
        described = details.get("source_operation")
        if not isinstance(described, dict):
            return False
        expected = _operation_details(operation, integer_abi)
        if (set(described) != set(expected)
                or any(described.get(key) != value for key, value in expected.items() if key != "integer_abi")
                or integer_abi_record(described.get("integer_abi")) != expected["integer_abi"]):
            return False
        replay = validate_overflow_result(details, replace(operation,
                    premises=operation.premises + operation.domains), claim.operands,
                    claim.operator, integer_abi)
        return (replay.get("feasible") is True and replay.get("witness_validated") is True
                and details.get("witness_validated") is True
                and all(details.get(key) == replay.get(key) for key in (
                    "model", "mathematical_result", "result_range")))

    def validate_prepared(prepared, actual, event):
        if (prepared != admission or not isinstance(event, FactEvent)
                or event.context != context or event.obligation != OBLIGATION
                or event.execution != "completed" or event.complete is not True
                or not _nonempty_text(event.request_id) or event.request_id != event.executed_request_id
                or not _nonempty_text(event.raw_reference) or not validates(actual)):
            return None
        execution = actual.details.get("smt_execution")
        if (not isinstance(execution, dict) or execution.get("identity_status") != "matched"
                or execution.get("scope") != "worker-invocation-only"
                or execution.get("request_id") != event.request_id
                or execution.get("executed_request_id") != event.executed_request_id):
            return None
        support = ExecutedSupportBinding(target, event.request_id, event.executed_request_id,
                                         event.raw_reference, *IDENTITY, "supports_fact", conclusion)
        return SMTValidatedConclusion(prepared, event.request_id, event.executed_request_id,
                                      event.raw_reference, IDENTITY[0], IDENTITY[-1], EFFECT_SCOPE,
                                      prepared.conclusion_signature, support)

    def validate_conclusion(record, actual, current, obligation):
        if (current != context or obligation != OBLIGATION
                or smt_claim_binding_rejection(record, expected_scope=scope,
                                               expected_revision=revision) is not None):
            return "unknown"
        return "supports_fact" if validates(actual) else "unknown"

    registration = SMTContractAdapter(
        ClaimContract("smt", "check-overflow-v1", frozenset({OBLIGATION})),
        validate_conclusion, validate_prepared, frozenset({EFFECT_SCOPE}), IDENTITY,
        frozenset({"entry-arithmetic-overflow"}), frozenset())
    return PreparedOverflowContext(context, admission, target, conclusion,
                                   MappingProxyType({CONTRACT_ID: registration}))
