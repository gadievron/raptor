"""Binding vocabulary for project-owned validators; never authority by itself.

Callers must invoke a registered validator over actual executed results and exact
prepared anchors first. Expectations below are pipeline-owned, not model fields.
"""
from __future__ import annotations
from dataclasses import dataclass

@dataclass(frozen=True)
class PreparedTargetBinding:
    unit_id: str
    target_snapshot_id: str
    build_identity: str
    dependencies: tuple[str, ...]
    assumptions: tuple[str, ...]
    representation: str
    applicability_domain: str
    correspondence_ids: tuple[str, ...] = ()

@dataclass(frozen=True)
class ConclusionSignature:
    """Exact meaning certified by the registered validator, not an opaque hash."""
    statement: str
    conclusion_kind: str
    effect_scope: str
    conditions: tuple[str, ...]

@dataclass(frozen=True)
class ExecutedSupportBinding:
    target: PreparedTargetBinding
    request_id: str
    executed_request_id: str
    raw_reference: str
    producer_kind: str
    producer_id: str
    producer_version: str
    validator_id: str
    validator_version: str
    execution_scope: str
    semantic: str
    validated_conclusion_signature: ConclusionSignature

def _nonempty_text(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())

def _strings(value: object) -> bool:
    return isinstance(value, tuple) and all(_nonempty_text(item) for item in value)

def support_binding_rejection(
    binding: object, *, expected_target: PreparedTargetBinding,
    expected_conclusion: ConclusionSignature, request_id: str,
    executed_request_id: str, raw_reference: str,
    registered_identity: tuple[str, str, str, str, str, str],
    effect_scopes: frozenset[str], positive_kinds: frozenset[str],
    negative_kinds: frozenset[str] = frozenset(),
) -> str | None:
    """Check bindings AFTER the project-owned semantic validator runs.

    None means matching prerequisites only, NOT admitted support. The adapter
    must independently validate exact prepared spans/module ranges, actual
    executed-request provenance, completion/coverage/exclusions, and the whole
    registered conclusion. No deserialized identity or callback echo is proof.
    Diagnostic/nonrefuting adapters must retain narrower policies. Novel concerns
    without registered contracts remain reportable unresolved, not rejected.
    """
    if not isinstance(expected_target, PreparedTargetBinding):
        return "prepared-target-unavailable"
    if (not all(_nonempty_text(value) for value in (
            expected_target.unit_id, expected_target.target_snapshot_id,
            expected_target.build_identity, expected_target.representation,
            expected_target.applicability_domain))
            or not all(_strings(value) for value in (
                expected_target.dependencies, expected_target.assumptions,
                expected_target.correspondence_ids))):
        return "prepared-target-invalid"
    if not isinstance(expected_conclusion, ConclusionSignature):
        return "requested-conclusion-unavailable"
    if (not all(_nonempty_text(value) for value in (
            expected_conclusion.statement, expected_conclusion.conclusion_kind,
            expected_conclusion.effect_scope))
            or not _strings(expected_conclusion.conditions)):
        return "requested-conclusion-invalid"
    if not isinstance(binding, ExecutedSupportBinding):
        return "validated-support-binding-unavailable"
    if binding.target != expected_target:
        return "target-build-or-assumption-mismatch"
    if (not all(_nonempty_text(value) for value in (request_id, executed_request_id, raw_reference))
            or request_id != executed_request_id
            or (binding.request_id, binding.executed_request_id, binding.raw_reference)
            != (request_id, executed_request_id, raw_reference)):
        return "executed-request-or-artifact-mismatch"
    if (not isinstance(registered_identity, tuple) or len(registered_identity) != 6
            or not all(_nonempty_text(value) for value in registered_identity)):
        return "registered-validator-unavailable"
    if (binding.producer_kind, binding.producer_id, binding.producer_version,
            binding.validator_id, binding.validator_version,
            binding.execution_scope) != registered_identity:
        return "registered-producer-or-validator-mismatch"
    if (not isinstance(effect_scopes, frozenset) or not effect_scopes
            or not all(_nonempty_text(value) for value in effect_scopes)
            or not isinstance(positive_kinds, frozenset)
            or not isinstance(negative_kinds, frozenset)
            or not all(_nonempty_text(value) for value in positive_kinds | negative_kinds)):
        return "registered-policy-invalid"
    if expected_conclusion.effect_scope not in effect_scopes:
        return "unsupported-effect-scope"
    if binding.validated_conclusion_signature != expected_conclusion:
        return "validated-conclusion-mismatch"
    allowed = (positive_kinds if binding.semantic == "supports_fact" else
               negative_kinds if binding.semantic == "contradicts_fact" else frozenset())
    if expected_conclusion.conclusion_kind not in allowed:
        return "unsupported-semantic-interpretation"
    return None
