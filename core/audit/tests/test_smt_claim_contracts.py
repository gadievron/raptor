"""Controls for binding prerequisites, not proof admission."""

import pytest

from core.audit.claims import ClaimRevision
from core.audit.claim_verification import ClaimVerification
from core.audit.refutation_source import SourceIdentity
from core.audit.verification_results import VerificationScope

from core.audit.smt_claim_contracts import smt_claim_binding_rejection


def records():
    hypothesis = {"mechanism": "A scoped claim", "cwe": "CWE-125"}
    revision = ClaimRevision(hypothesis, pass_id="pipeline-pass", file="unit.c", function="Read", line_start=1)
    source = SourceIdentity("a" * 64, (1, 2, 3, 4, 5))
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
    from core.audit.smt_claim_contracts import SMTContractAdapter
    from core.audit.sweep import SweepResult

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
                           registration=SMTContractAdapter(contract, validate))


def adapt(case, **overrides):
    from core.audit.smt_claim_contracts import adapt_smt_claim_fact

    arguments = dict(event=case.event, expected_context=case.context,
                     expected_scope=case.scope, expected_revision=case.revision,
                     result=case.result, contracts={case.context.contract: case.registration})
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
    from core.audit.smt_claim_contracts import SMTContractAdapter

    case = adapter_case
    registration = SMTContractAdapter(case.contract, lambda *args: True)
    assert adapt(case, contracts={case.context.contract: registration}).semantic == "unknown"


def test_result_content_must_satisfy_the_registered_validator(adapter_case):
    from dataclasses import replace

    case = adapter_case
    fact = adapt(case, result=replace(case.result, details={**case.result.details, "value": 1}))
    assert fact.semantic == "unknown" and len(case.calls) == 1


def test_registered_negative_coverage_and_existing_nonrefuting_policy_are_both_required(adapter_case):
    from dataclasses import replace
    from core.audit.smt_claim_contracts import SMTContractAdapter

    case = adapter_case
    registration = SMTContractAdapter(case.contract, lambda *args: "contradicts_fact")
    contracts = {case.context.contract: registration}
    assert adapt(case, contracts=contracts).semantic == "contradicts_fact"
    # Existing source-array safety checks do not refute a whole claim.
    result = replace(case.result, rule_id="smt:check-array-bounds", outcome="refuted")
    assert adapt(case, result=result, contracts=contracts).semantic == "unknown"
    no_negative = replace(case.contract, negative_obligations=frozenset())
    registration = SMTContractAdapter(no_negative, lambda *args: "contradicts_fact")
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
    assert fact.semantic == "unknown" and len(case.calls) == 1


def test_validator_failure_cannot_supply_a_fact(adapter_case):
    from core.audit.smt_claim_contracts import SMTContractAdapter

    case = adapter_case
    calls = []

    def failed(*args):
        calls.append(args)
        raise RuntimeError("validator failure")

    registration = SMTContractAdapter(case.contract, failed)
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
