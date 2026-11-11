"""Controls for binding prerequisites, not proof admission."""

import hashlib
from dataclasses import replace

import pytest

from core.audit.claims import ClaimRevision
from core.audit.claim_verification import ClaimVerification
from core.audit.refutation_source import SourceIdentity
from core.audit.verification_results import VerificationScope

from core.audit.smt_claim_contracts import smt_claim_binding_rejection


def records():
    hypothesis = {"mechanism": "A scoped claim", "cwe": "CWE-125"}
    revision = ClaimRevision(hypothesis, pass_id="pipeline-pass", file="unit.c", function="Read", line_start=1)
    source = SourceIdentity(hashlib.sha256(b"int Read(void) { return 8; }\n").hexdigest(), (1, 2, 3, 4, 5))
    scope = VerificationScope("unit.c", "Read", 1, hypothesis["mechanism"], source)
    return hypothesis, revision, scope


def test_unbound_legacy_receipt_cannot_satisfy_binding_prerequisite():
    hypothesis, revision, scope = records()
    claim = ClaimVerification(hypothesis, ("smt:check-array-bounds",))
    assert smt_claim_binding_rejection(claim, expected_scope=scope, expected_revision=revision) == "producer-scope-unavailable"


def test_typed_scope_with_unknown_source_cannot_satisfy_binding_prerequisite():
    hypothesis, revision, scope = records()
    unknown = VerificationScope(scope.file, scope.function, scope.line_start, scope.hypothesis)
    claim = ClaimVerification(hypothesis, ("smt:check-array-bounds",), binding=unknown, claim_revision=revision)
    assert smt_claim_binding_rejection(claim, expected_scope=scope, expected_revision=revision) == "producer-source-unavailable"


def test_changed_source_is_not_current_support():
    hypothesis, revision, scope = records()
    changed = VerificationScope(scope.file, scope.function, scope.line_start, scope.hypothesis,
                                SourceIdentity("b" * 64, (1, 2, 3, 4, 6)))
    claim = ClaimVerification(hypothesis, ("smt:check-array-bounds",), binding=scope, claim_revision=revision)
    assert smt_claim_binding_rejection(claim, expected_scope=changed, expected_revision=revision) == "producer-scope-or-source-mismatch"


def test_model_complete_and_confirmed_fields_do_not_construct_a_typed_record():
    _, revision, scope = records()
    record = {"complete": True, "confirmed": True, "rule_id": "smt:check-array-bounds"}
    assert smt_claim_binding_rejection(record, expected_scope=scope, expected_revision=revision) == "claim-record-type-unavailable"


def test_matching_local_binding_only_passes_prerequisites():
    hypothesis, revision, scope = records()
    claim = ClaimVerification(hypothesis, ("smt:check-array-bounds",), binding=scope, claim_revision=revision)
    # None is not support: executed-result/registered-contract validation remains required.
    assert smt_claim_binding_rejection(claim, expected_scope=scope, expected_revision=revision) is None


def test_a_revision_with_stronger_assumptions_cannot_reuse_old_binding():
    hypothesis, revision, scope = records()
    claim = ClaimVerification(hypothesis, ("smt:check-array-bounds",), binding=scope, claim_revision=revision)
    revised = revision.revise({**hypothesis, "assumed_property": "external caller precondition"}, pass_id="later-pass")
    assert smt_claim_binding_rejection(claim, expected_scope=scope, expected_revision=revised) == "producer-revision-material-mismatch"


def test_refutation_requires_the_same_pipeline_revision():
    from core.audit.verification_results import ClaimRefutation, ProbeOutcome

    _, revision, scope = records()
    checks = (ProbeOutcome("smt", "refuted", "smt:unregistered"),)
    receipt = ClaimRefutation(scope.file, scope.function, scope.line_start, scope.hypothesis,
                              checks, scope.source_identity)
    assert smt_claim_binding_rejection(receipt, expected_scope=scope, expected_revision=revision) == "producer-revision-unavailable"
    bound = ClaimRefutation(scope.file, scope.function, scope.line_start, scope.hypothesis,
                            checks, scope.source_identity, revision)
    # An unregistered rule may pass binding, but that is never a conclusion contract.
    assert smt_claim_binding_rejection(bound, expected_scope=scope, expected_revision=revision) is None


def test_matching_source_does_not_transfer_to_a_different_occurrence():
    hypothesis, revision, scope = records()
    claim = ClaimVerification(hypothesis, ("smt:check-array-bounds",), binding=scope, claim_revision=revision)
    other_revision = ClaimRevision(hypothesis, pass_id="another-pass", file="unit.c", function="Other", line_start=9)
    other_scope = VerificationScope("unit.c", "Other", 9, scope.hypothesis, scope.source_identity)
    assert smt_claim_binding_rejection(claim, expected_scope=other_scope, expected_revision=other_revision) == "producer-scope-or-source-mismatch"


@pytest.mark.parametrize("source_kind,reason", [
    ("unknown", "producer-source-unavailable"),
    ("changed", "producer-scope-or-source-mismatch"),
])
def test_refutation_source_is_required_and_current(source_kind, reason):
    from core.audit.verification_results import ClaimRefutation, ProbeOutcome

    _, revision, scope = records()
    source = None if source_kind == "unknown" else SourceIdentity("b" * 64, (1, 2, 3, 4, 6))
    receipt = ClaimRefutation(scope.file, scope.function, scope.line_start, scope.hypothesis,
                              (ProbeOutcome("smt", "refuted", "smt:unregistered"),), source, revision)
    assert smt_claim_binding_rejection(receipt, expected_scope=scope, expected_revision=revision) == reason


@pytest.fixture
def adapter_case():
    from types import SimpleNamespace
    from core.audit.claim_adjudication import ClaimContext, ClaimContract, FactEvent
    from core.audit.smt_claim_contracts import (
        PreparedSMTAdmission, PreparedSMTAnchor, SMTContractAdapter, SMTValidatedConclusion,
    )
    from core.audit.sweep import SweepResult
    from core.audit.claim_support_contracts import (
        PreparedTargetBinding, ConclusionSignature, ExecutedSupportBinding,
    )

    hypothesis, revision, scope = records()
    record = ClaimVerification(hypothesis, ("smt:check-overflow",), binding=scope, claim_revision=revision)
    context = ClaimContext(revision.claim_id, revision.revision_id, scope.source_identity,
                           "inert-test-contract", ("source-v1", "types-lp64"),
                           ("fixture-entry-model",), (scope.file, scope.function, scope.line_start))
    contract = ClaimContract("inert-smt-validator", "v1", frozenset({"exact-fault"}), frozenset({"exact-fault"}))
    event = FactEvent("event-1", context, "exact-fault", contract.adapter, contract.version,
                      "completed", "supports_fact", "request-1", "request-1", True, "owned-result-1")
    result = SweepResult(tool="smt", file_path=scope.file, function_name=scope.function,
                         outcome="confirmed", rule_id="smt:check-overflow",
                         details={"value": 8, "limit": 7, "smt_execution": {
                             "request_id": event.request_id, "executed_request_id": event.executed_request_id,
                             "identity_status": "matched", "scope": "worker-invocation-only"}})
    prepared = PreparedSMTAdmission(context, "unit-1", "snapshot-1", "build-lp64", "pipeline-pass",
                                    scope.hypothesis, (PreparedSMTAnchor(
                                        scope.file, scope.source_identity,
                                        b"int Read(void) { return 8; }\n", 0, 28,
                                        b"int Read(void) { return 8; }"),),
                                    "admitted", "fixture-exact-conclusion-v1")
    target = PreparedTargetBinding(prepared.unit_id, prepared.target_snapshot_id, prepared.build_identity,
                                   context.dependencies, context.assumptions, "source", "fixture-source-arithmetic")
    conclusion = ConclusionSignature(scope.hypothesis, "bounded-arithmetic-witness",
                                     "bounded-fixture-arithmetic", ("exact integer domain",))
    prepared = replace(prepared, target_binding=target, requested_conclusion=conclusion)
    identity = ("mechanical_observation", contract.adapter, contract.version,
                "inert-witness-validator", "v1", "registered-worker-invocation")
    support = ExecutedSupportBinding(target, event.request_id, event.executed_request_id,
                                     event.raw_reference, *identity, "supports_fact", conclusion)
    validated = SMTValidatedConclusion(prepared, event.request_id, event.executed_request_id,
                                       event.raw_reference, "mechanical_observation",
                                       "registered-worker-invocation", "bounded-fixture-arithmetic",
                                       prepared.conclusion_signature, support)

    def validate_prepared(admission, actual_result, actual_event):
        # Pipeline-owned fixture registration checks complete prepared inputs.
        if (admission == prepared and actual_result.rule_id == result.rule_id
                and actual_event.context == event.context):
            return validated
        return None

    calls = []

    def validate(claim, actual_result, actual_context, obligation):
        calls.append((claim, actual_result, actual_context, obligation))
        # An inert fixture contract with exact conclusion and arithmetic facts.
        # This is not a registration for any production SMT operation.
        if (claim.hypothesis == hypothesis and actual_context == context and obligation == "exact-fault"
                and actual_result.details.get("value") == 8 and actual_result.details.get("limit") == 7):
            return "supports_fact"
        return "unknown"

    return SimpleNamespace(record=record, revision=revision, scope=scope, context=context,
                           contract=contract, event=event, result=result, calls=calls,
                           prepared=prepared, validated=validated, target=target, conclusion=conclusion,
                           registration=SMTContractAdapter(contract, validate, validate_prepared,
                                                           frozenset({"bounded-fixture-arithmetic"}), identity,
                                                           frozenset({"bounded-arithmetic-witness"}),
                                                           frozenset({"bounded-arithmetic-witness"})))


def adapt(case, **overrides):
    from core.audit.smt_claim_contracts import adapt_smt_claim_fact

    arguments = dict(event=case.event, expected_context=case.context,
                     expected_scope=case.scope, expected_revision=case.revision,
                     result=case.result, contracts={case.context.contract: case.registration},
                     prepared_admission=case.prepared, expected_target=case.target,
                     expected_conclusion=case.conclusion)
    arguments.update(overrides)
    return adapt_smt_claim_fact(case.record, **arguments)


def test_only_registered_validated_coverage_can_support_a_fact(adapter_case):
    from core.audit.claim_adjudication import reduce_claims

    case = adapter_case
    fact = adapt(case)
    assert fact.semantic == "supports_fact" and len(case.calls) == 1
    reduced = reduce_claims([case.context], [fact], contracts={case.context.contract: case.contract})
    assert reduced["claims"][0]["state"] == "supported"
    # Admission does not mutate or replace the original observation.
    assert fact is not case.event and case.event.semantic == "supports_fact"


def test_legacy_receipts_and_booleans_without_registration_remain_unknown(adapter_case):
    from core.audit.claim_adjudication import reduce_claims

    case = adapter_case
    fact = adapt(case, contracts={})
    assert fact.semantic == "unknown" and not case.calls
    reduced = reduce_claims([case.context], [fact], contracts={case.context.contract: case.contract})
    assert reduced["claims"][0]["state"] == "unresolved"


@pytest.mark.parametrize("change", [
    {"execution": "not_run"}, {"execution": "partial"}, {"execution": "timed_out"},
    {"execution": "unsupported"}, {"complete": False}, {"complete": 1},
    {"executed_request_id": "different-request"}, {"request_id": ""}, {"raw_reference": ""},
])
def test_incomplete_or_unexecuted_events_never_call_the_validator(adapter_case, change):
    from dataclasses import replace

    case = adapter_case
    fact = adapt(case, event=replace(case.event, **change))
    assert fact.semantic == "unknown" and not case.calls


@pytest.mark.parametrize("field,value", [
    ("dependencies", ("different-source",)), ("assumptions", ("different-ABI",)),
    ("revision_id", "different-revision"), ("occurrence", ("unit.c", "Other", 9)),
])
def test_current_admission_context_must_match_in_full(adapter_case, field, value):
    from dataclasses import replace

    case = adapter_case
    stale = replace(case.event, context=replace(case.context, **{field: value}))
    fact = adapt(case, event=stale)
    assert fact.semantic == "unknown" and not case.calls


@pytest.mark.parametrize("rule", [
    "smt:check-encoding-residual", "smt:check-encoding-residual:witness",
    "smt:check-integer-comparison", "smt:validate-path", "smt:check-oob",
])
def test_diagnostic_smt_receipts_cannot_become_whole_claim_facts(adapter_case, rule):
    from dataclasses import replace

    case = adapter_case
    fact = adapt(case, result=replace(case.result, rule_id=rule))
    assert fact.semantic == "unknown" and not case.calls


def test_model_authored_contract_dictionary_is_not_a_registration(adapter_case):
    case = adapter_case
    fact = adapt(case, contracts={case.context.contract: {"complete": True, "confirmed": True}})
    assert fact.semantic == "unknown" and not case.calls


def test_registered_validator_boolean_is_not_a_semantic_fact(adapter_case):

    case = adapter_case
    registration = replace(case.registration, validate_conclusion=lambda *args: True)
    assert adapt(case, contracts={case.context.contract: registration}).semantic == "unknown"


def test_result_content_must_satisfy_the_registered_validator(adapter_case):
    from dataclasses import replace

    case = adapter_case
    fact = adapt(case, result=replace(case.result, details={**case.result.details, "value": 1}))
    assert fact.semantic == "unknown" and len(case.calls) == 1


def test_registered_negative_coverage_and_existing_nonrefuting_policy_are_both_required(adapter_case):
    from dataclasses import replace

    case = adapter_case
    registration = replace(case.registration, validate_conclusion=lambda *args: "contradicts_fact")
    negative = replace(case.validated, executed_support=replace(case.validated.executed_support,
                                                               semantic="contradicts_fact"))
    registration = replace(registration, validate_prepared_admission=lambda *args: negative)
    contracts = {case.context.contract: registration}
    assert adapt(case, contracts=contracts).semantic == "contradicts_fact"
    # Existing source-array safety checks do not refute a whole claim.
    result = replace(case.result, rule_id="smt:check-array-bounds", outcome="refuted")
    assert adapt(case, result=result, contracts=contracts).semantic == "unknown"
    no_negative = replace(case.contract, negative_obligations=frozenset())
    registration = replace(case.registration, contract=no_negative, validate_conclusion=lambda *args: "contradicts_fact")
    assert adapt(case, contracts={case.context.contract: registration}).semantic == "unknown"


def test_fully_current_stronger_conclusion_has_no_coverage_under_the_old_contract(adapter_case):
    from dataclasses import replace
    from core.audit.smt_claim_contracts import adapt_smt_claim_fact

    case = adapter_case
    hypothesis = {**case.record.hypothesis, "mechanism": "A stronger conclusion at the same source anchor"}
    revision = case.revision.revise(hypothesis, pass_id="later-pass")
    scope = replace(case.scope, hypothesis=hypothesis["mechanism"])
    record = ClaimVerification(hypothesis, case.record.receipts, binding=scope, claim_revision=revision)
    context = replace(case.context, revision_id=revision.revision_id, parent_revision_id=case.revision.revision_id)
    event = replace(case.event, context=context)
    fact = adapt_smt_claim_fact(record, event=event, expected_context=context, expected_scope=scope,
                               expected_revision=revision, result=case.result,
                               contracts={context.contract: case.registration})
    assert fact.semantic == "unknown" and not case.calls


def test_validator_failure_cannot_supply_a_fact(adapter_case):

    case = adapter_case
    calls = []

    def failed(*args):
        calls.append(args)
        raise RuntimeError("validator failure")

    registration = replace(case.registration, validate_conclusion=failed)
    assert adapt(case, contracts={case.context.contract: registration}).semantic == "unknown"
    assert len(calls) == 1


@pytest.mark.parametrize("change", [
    {"tool": "semgrep"}, {"file_path": "other.c"}, {"function_name": "Other"},
    {"outcome": "inconclusive"}, {"outcome": "error"},
])
def test_wrong_or_nonprobative_result_never_calls_the_validator(adapter_case, change):
    from dataclasses import replace

    case = adapter_case
    fact = adapt(case, result=replace(case.result, **change))
    assert fact.semantic == "unknown" and not case.calls


def test_raw_model_event_is_not_a_pipeline_fact_event(adapter_case):
    case = adapter_case
    event = {"context": case.context, "complete": True, "semantic": "supports_fact"}
    assert adapt(case, event=event) is None and not case.calls


@pytest.mark.parametrize("change", [
    {"adapter": "other-adapter"}, {"contract_version": "old-version"}, {"obligation": "uncovered-fact"},
])
def test_event_must_name_exact_registered_coverage(adapter_case, change):
    from dataclasses import replace

    case = adapter_case
    fact = adapt(case, event=replace(case.event, **change))
    assert fact.semantic == "unknown" and not case.calls


def test_a_result_from_another_execution_cannot_support_the_current_event(adapter_case):
    from dataclasses import replace

    case = adapter_case
    result = replace(case.result, details={**case.result.details, "smt_execution": {
        "request_id": "other-request", "executed_request_id": "other-request",
        "identity_status": "matched", "scope": "worker-invocation-only",
    }})
    fact = adapt(case, result=result)
    assert fact.semantic == "unknown" and not case.calls


@pytest.mark.parametrize("receipt", [
    None, {}, {"complete": True},
    {"request_id": "request-1", "executed_request_id": "request-1", "identity_status": "missing",
     "scope": "worker-invocation-only"},
    {"request_id": "request-1", "executed_request_id": "request-1", "identity_status": "matched",
     "scope": "whole-claim-proof"},
])
def test_result_requires_a_parent_bound_execution_receipt(adapter_case, receipt):
    from dataclasses import replace

    case = adapter_case
    result = replace(case.result, details={**case.result.details, "smt_execution": receipt})
    assert adapt(case, result=result).semantic == "unknown" and not case.calls


def test_partial_context_without_prepared_admission_cannot_support(adapter_case):
    case = adapter_case
    # Existing context/IDs/obligations lack prepared anchors and full conclusion.
    assert adapt(case, prepared_admission=None).semantic == "unknown"
    assert not case.calls


@pytest.mark.parametrize("field,value", [
    ("statement", "different meaning"), ("unit_id", "other-unit"),
    ("target_snapshot_id", "other-snapshot"), ("build_identity", "other-build"),
    ("origin_pass_id", "other-pass"), ("processing_status", "proposed"),
    ("conclusion_signature", "different-conclusion"), ("anchors", ()),
])
def test_changed_prepared_claim_cannot_reuse_registered_validation(adapter_case, field, value):
    case = adapter_case
    fact = adapt(case, prepared_admission=replace(case.prepared, **{field: value}))
    assert fact.semantic == "unknown" and not case.calls


@pytest.mark.parametrize("change", [
    {"byte_start": 1}, {"byte_end": 999}, {"byte_start": True},
    {"expected_span": b"invented span"}, {"file": "../unit.c"},
    {"prepared_content": b"changed source"},
])
def test_invalid_exact_anchor_never_reaches_support_validator(adapter_case, change):
    case = adapter_case
    anchor = replace(case.prepared.anchors[0], **change)
    assert adapt(case, prepared_admission=replace(case.prepared, anchors=(anchor,))).semantic == "unknown"
    assert not case.calls


@pytest.mark.parametrize("change", [
    {"validated_conclusion_signature": "echoed-old-conclusion"},
    {"producer_kind": "reviewer_judgment"}, {"execution_scope": "model-asserted"},
    {"effect_scope": "whole-program"}, {"request_id": "other-request"},
    {"executed_request_id": "other-request"}, {"raw_reference": "other-result"},
])
def test_registered_validation_must_bind_conclusion_and_execution(adapter_case, change):
    case = adapter_case
    registration = replace(case.registration, validate_prepared_admission=lambda *args: replace(case.validated, **change))
    assert adapt(case, contracts={case.context.contract: registration}).semantic == "unknown"
    assert not case.calls


@pytest.mark.parametrize("returned", [True, "supports_fact", {"complete": True}, None])
def test_untyped_admission_validator_output_grants_no_coverage(adapter_case, returned):
    case = adapter_case
    registration = replace(case.registration, validate_prepared_admission=lambda *args: returned)
    assert adapt(case, contracts={case.context.contract: registration}).semantic == "unknown"
    assert not case.calls


def test_prepared_envelope_without_independent_current_shared_binding_is_unknown(adapter_case):
    case = adapter_case
    assert adapt(case, expected_target=None).semantic == "unknown"
    assert not case.calls


@pytest.mark.parametrize("field,value", [
    ("build_identity", "new-build"), ("unit_id", "other-unit"),
    ("target_snapshot_id", "other-snapshot"), ("dependencies", ("new-header",)),
    ("assumptions", ("stronger-precondition",)), ("representation", "binary"),
    ("applicability_domain", "different-domain"), ("correspondence_ids", ("other-map",)),
])
def test_independent_current_target_cannot_be_copied_from_old_admission(adapter_case, field, value):
    case = adapter_case
    assert adapt(case, expected_target=replace(case.target, **{field: value})).semantic == "unknown"
    assert not case.calls


@pytest.mark.parametrize("field,value", [
    ("statement", "stronger whole-program assertion"), ("conclusion_kind", "exploitability"),
    ("effect_scope", "all-paths"), ("conditions", ("additional condition",)),
])
def test_independent_requested_conclusion_rejects_old_signature(adapter_case, field, value):
    case = adapter_case
    assert adapt(case, expected_conclusion=replace(case.conclusion, **{field: value})).semantic == "unknown"
    assert not case.calls


@pytest.mark.parametrize("field,value", [
    ("request_id", "other-request"), ("executed_request_id", "other-execution"),
    ("raw_reference", "other-result"), ("producer_kind", "reviewer_judgment"),
    ("producer_id", "model-authored"), ("producer_version", "other-version"),
    ("validator_id", "unregistered"), ("validator_version", "other-version"),
    ("execution_scope", "supplied-model"), ("semantic", "contradicts_fact"),
])
def test_canonical_executed_binding_requires_registered_identity(adapter_case, field, value):
    case = adapter_case
    changed = replace(case.validated, executed_support=replace(case.validated.executed_support, **{field: value}))
    registration = replace(case.registration, validate_prepared_admission=lambda *args: changed)
    assert adapt(case, contracts={case.context.contract: registration}).semantic == "unknown"


def test_missing_canonical_executed_binding_remains_unknown(adapter_case):
    case = adapter_case
    registration = replace(case.registration, validate_prepared_admission=lambda *args: replace(case.validated, executed_support=None))
    assert adapt(case, contracts={case.context.contract: registration}).semantic == "unknown"


def test_existing_result_bridge_without_retention_ack_stays_unknown(adapter_case):
    from core.audit.smt_claim_contracts import smt_fact_from_result
    case = adapter_case
    fact = smt_fact_from_result(
        case.record, result=case.result, event_id="bridge-1", obligation=case.event.obligation,
        expected_context=case.context, expected_scope=case.scope, expected_revision=case.revision,
        prepared_admission=case.prepared, expected_target=case.target,
        expected_conclusion=case.conclusion, contracts={case.context.contract: case.registration},
    )
    assert fact.semantic == "unknown" and not fact.raw_reference
    assert not case.calls


def bridge(case, **overrides):
    from core.audit.smt_claim_contracts import smt_fact_from_result
    arguments = dict(result=case.result, event_id="bridge-1", obligation=case.event.obligation,
                     expected_context=case.context, expected_scope=case.scope,
                     expected_revision=case.revision, prepared_admission=case.prepared,
                     expected_target=case.target, expected_conclusion=case.conclusion,
                     contracts={case.context.contract: case.registration},
                     retain_result=lambda result: case.event.raw_reference)
    arguments.update(overrides)
    return smt_fact_from_result(case.record, **arguments)


def test_existing_result_bridge_uses_pipeline_ack_without_mutating_result(adapter_case):
    case = adapter_case
    retained = []
    def retain(result):
        assert result is not case.result and result == case.result
        retained.append(result)
        return case.event.raw_reference
    fact = bridge(case, retain_result=retain)
    assert fact.semantic == "supports_fact" and fact.raw_reference == case.event.raw_reference
    assert len(retained) == 1 and len(case.calls) == 1


@pytest.mark.parametrize("missing", ["manifest", "registry", "ack", "ack-error", "ack-empty", "ack-mutates"])
def test_bridge_missing_admission_or_retention_remains_unknown(adapter_case, missing):
    case = adapter_case
    overrides = {}
    if missing == "manifest":
        overrides["expected_target"] = None
    elif missing == "registry":
        overrides["contracts"] = {}
    elif missing == "ack":
        overrides["retain_result"] = None
    elif missing == "ack-empty":
        overrides["retain_result"] = lambda result: ""
    elif missing == "ack-error":
        def failed(result):
            raise OSError("retention unavailable")
        overrides["retain_result"] = failed
    else:
        def changed(result):
            result.outcome = "refuted"
            return case.event.raw_reference
        overrides["retain_result"] = changed
    assert bridge(case, **overrides).semantic == "unknown"
    assert not case.calls and case.result.outcome == "confirmed"


@pytest.mark.parametrize("change", [
    {"outcome": "inconclusive"}, {"outcome": "error"}, {"errors": ["timed out"]},
    {"rule_id": "smt:check-overflow:supplied-model", "outcome": "refuted"},
    {"rule_id": "smt:check-oob", "outcome": "refuted"},
])
def test_bridge_status_and_supplied_model_cannot_obtain_ack(adapter_case, change):
    case = adapter_case
    retained = []
    assert bridge(case, result=replace(case.result, **change),
                  retain_result=lambda result: retained.append(result)).semantic == "unknown"
    assert not retained and not case.calls


@pytest.mark.parametrize("change", ["anchor", "statement", "build", "assumptions", "request", "result", "signature"])
def test_bridge_changed_inputs_preserve_unknown(adapter_case, change):
    case = adapter_case
    overrides = {}
    if change == "anchor":
        overrides["prepared_admission"] = replace(case.prepared, anchors=())
    elif change == "statement":
        overrides["expected_conclusion"] = replace(case.conclusion, statement="all paths exploitable")
    elif change == "build":
        overrides["expected_target"] = replace(case.target, build_identity="other-build")
    elif change == "assumptions":
        overrides["expected_target"] = replace(case.target, assumptions=("caller always permits path",))
    elif change == "request":
        execution = {**case.result.details["smt_execution"], "executed_request_id": "other-request"}
        overrides["result"] = replace(case.result, details={**case.result.details, "smt_execution": execution})
    elif change == "result":
        overrides["result"] = replace(case.result, details={**case.result.details, "value": 1})
    else:
        overrides["expected_conclusion"] = replace(case.conclusion, conditions=("different semantic condition",))
    assert bridge(case, **overrides).semantic == "unknown"


def test_bridge_accepts_one_actual_existing_arithmetic_dispatch(tmp_path, adapter_case):
    from dataclasses import asdict
    import json
    from core.audit import sweep
    from core.audit.smt_claim_contracts import PreparedSMTAnchor, SMTValidatedConclusion
    from core.audit.claim_support_contracts import ExecutedSupportBinding

    pytest.importorskip("z3")
    pytest.importorskip("tree_sitter_c")
    source = b"int Read(int Value) { if (Value >= 2147483647) return Value + 1; return 0; }\n"
    statement = "integer overflow in `Value + 1`"
    result = sweep._smt_verb_in_subprocess(file_path="unit.c", function_name="Read", verb="check-overflow",
                                           source=source.decode(), hypothesis=statement, integer_abi="ilp32")
    assert result.outcome == "confirmed", (result.errors, result.details)
    assert result.details["witness_validated"] is True
    assert result.details["mathematical_result"] == 2147483648
    case = adapter_case
    revision = ClaimRevision({"mechanism": statement}, pass_id="pipeline-pass", file="unit.c", function="Read", line_start=1)
    scope = VerificationScope("unit.c", "Read", 1, statement, SourceIdentity(hashlib.sha256(source).hexdigest(), (1, 2, len(source), 4, 5)))
    target = replace(case.target, build_identity="fixture-ilp32-build",
                     dependencies=("source:" + scope.source_identity.sha256, "integer-abi:ilp32"),
                     assumptions=("supplied declarations describe the active build",
                                  "entry parameters have their declared value domains",
                                  "no additional caller constraints are encoded"))
    context = replace(case.context, claim_id=revision.claim_id, revision_id=revision.revision_id,
                      source=scope.source_identity, dependencies=target.dependencies, assumptions=target.assumptions)
    conclusion = replace(case.conclusion, statement=statement,
                         conditions=("integer-abi:ilp32", "Value >= 2147483647", "signed int32 addition"))
    prepared = replace(case.prepared, context=context, statement=statement, requested_conclusion=conclusion,
                       build_identity=target.build_identity, target_binding=target,
                       anchors=(PreparedSMTAnchor("unit.c", scope.source_identity, source, 0, len(source), source),))
    execution = result.details["smt_execution"]
    retained = tmp_path / "actual-result.json"
    def retain(actual):
        payload = json.dumps(asdict(actual), sort_keys=True)
        with retained.open("w") as stream:
            stream.write(payload)
            stream.flush()
            import os
            os.fsync(stream.fileno())
        assert retained.read_text() == payload
        return str(retained)
    def validate_admission(admission, actual, event):
        support = ExecutedSupportBinding(target, event.request_id, event.executed_request_id,
                                         event.raw_reference, *case.registration.registered_identity,
                                         "supports_fact", conclusion)
        return SMTValidatedConclusion(admission, event.request_id, event.executed_request_id,
                                      event.raw_reference, "mechanical_observation", "registered-worker-invocation",
                                      conclusion.effect_scope, admission.conclusion_signature, support)
    def validate_witness(record, actual, current, obligation):
        # Fixture covers this exact bounded arithmetic witness only. No product
        # registration, caller reachability or vulnerability claim is admitted.
        if (record.hypothesis == revision.hypothesis and current == context
                and actual.details.get("witness_validated") is True
                and actual.details.get("mathematical_result") == 2147483648
                and actual.details.get("model", {}).get("Value") == 2147483647
                and actual.details.get("source_operation", {}).get("profile") == "int32"
                and actual.details.get("result_range") == {"minimum": -2147483648, "maximum": 2147483647}
                and actual.details.get("proof_scope") == "function-entry-source-model"):
            return "supports_fact"
        return "unknown"
    registration = replace(case.registration, validate_prepared_admission=validate_admission,
                           validate_conclusion=validate_witness)
    record = ClaimVerification(revision.hypothesis, binding=scope, claim_revision=revision)
    from core.audit.smt_claim_contracts import smt_fact_from_result
    fact = smt_fact_from_result(record, result=result, event_id="actual-bridge", obligation="exact-fault",
                               expected_context=context, expected_scope=scope, expected_revision=revision,
                               contracts={context.contract: registration}, prepared_admission=prepared,
                               expected_target=target, expected_conclusion=conclusion, retain_result=retain)
    assert fact.semantic == "supports_fact" and fact.request_id == execution["request_id"]
    assert fact.executed_request_id == execution["executed_request_id"]
    assert fact.raw_reference == str(retained) and retained.exists()
