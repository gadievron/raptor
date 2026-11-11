"""Prepared-context integration with inert execution and existing integer replay."""
from dataclasses import replace
import hashlib
from types import SimpleNamespace

import pytest

from core.audit import prepared_claim_context as module
from core.audit.arithmetic_operation import ArithmeticOperation
from core.audit.claim_support_contracts import PreparedTargetBinding
from core.audit.claim_verification import ClaimVerification
from core.audit.claims import ClaimRevision
from core.audit.integer_abi import integer_abi_key
from core.audit.integer_witness import source_model_scope
from core.audit.probe_function_scope import FunctionScope, source_binding
from core.audit.refutation_source import SourceIdentity
from core.audit.smt_claim_contracts import PreparedSMTAnchor, smt_fact_from_result
from core.audit.sweep import SweepResult
from core.audit.verification_results import VerificationScope


@pytest.fixture
def case(monkeypatch):
    # Binding seam is inert here; source-parser/native execution is NOT claimed.
    source = b"int Read(int Value) { if (Value >= 2147483647) return Value + 1; return 0; }\n"
    identity = SourceIdentity(hashlib.sha256(source).hexdigest(), (1, 2, len(source), 4, 5))
    statement = "integer overflow in `Value + 1`"
    revision = ClaimRevision({"mechanism": statement}, pass_id="pipeline-pass",
                             file="unit.c", function="Read", line_start=1)
    scope = VerificationScope("unit.c", "Read", 1, statement, identity)
    anchor = PreparedSMTAnchor("unit.c", identity, source, 0, len(source), source)
    target = PreparedTargetBinding("prepared-unit", "prepared-target", "prepared-build",
                                   ("prepared-dependency", "integer-abi:" + integer_abi_key("ilp32")),
                                   tuple(source_model_scope()["assumptions"]),
                                   "source", "source-language")
    operation = ArithmeticOperation("bound", 1, 58, "bound", ("Value >= 2147483647",),
                                    "bound", "int32", "signed_wrap", (), (("Value", "int"),))
    monkeypatch.setattr(module, "bind_arithmetic_operation", lambda *a, **k: operation)
    monkeypatch.setattr(module, "source_for_function",
                        lambda value, file, name: (FunctionScope("selected", 0, len(source)), value))
    current = [(target, anchor)]
    args = dict(revision=revision, scope=scope, anchor=anchor, target=target,
                integer_abi="ilp32", current_prepared=lambda: current[0])
    prepared = module.prepare_overflow_claim_context(**args)
    assert isinstance(prepared, module.PreparedOverflowContext)
    details = {"feasible": True, "model": {"Value": 2147483647}, "witness_validated": True,
               "mathematical_result": 2147483648,
               "result_range": {"minimum": -2147483648, "maximum": 2147483647},
               **source_model_scope(),
               "source_scope": source_binding(source.decode(), "Read", verb="check-overflow",
                                              integer_abi="ilp32", hypothesis=statement),
               "source_operation": module._operation_details(operation, "ilp32"),
               "smt_execution": {"identity_status": "matched", "scope": "worker-invocation-only",
                                 "request_id": "actual-request", "executed_request_id": "actual-request"}}
    result = SweepResult(tool="smt", file_path="unit.c", function_name="Read",
                         outcome="confirmed", rule_id="smt:check-overflow", details=details)
    record = ClaimVerification(revision.hypothesis, binding=scope, claim_revision=revision)
    return SimpleNamespace(args=args, current=current, target=target, anchor=anchor,
                           operation=operation, prepared=prepared, result=result,
                           record=record, revision=revision, scope=scope)


def bridge(case, result=None, retain=None):
    retained = []
    def save(snapshot):
        retained.append(snapshot)
        return "durably-retained-result"
    prepared = case.prepared
    fact = smt_fact_from_result(
        case.record, result=result or case.result, event_id="event", obligation=module.OBLIGATION,
        expected_context=prepared.context, expected_scope=case.scope,
        expected_revision=case.revision, contracts=prepared.contracts,
        prepared_admission=prepared.admission, expected_target=prepared.target,
        expected_conclusion=prepared.conclusion, retain_result=retain or save)
    return fact, retained


def test_registered_positive_replays_actual_model_and_keeps_narrow_scope(case):
    fact, retained = bridge(case)
    assert fact.semantic == "supports_fact" and len(retained) == 1
    assert case.prepared.conclusion.effect_scope == "function-entry-source-model"
    assert not case.prepared.contracts[module.CONTRACT_ID].negative_kinds
    assert retained[0] == case.result and retained[0] is not case.result


@pytest.mark.parametrize("field,value", [("target", None), ("current_prepared", None),
                                         ("integer_abi", None)])
def test_missing_pipeline_manifest_never_invents_identity(case, field, value):
    assert isinstance(module.prepare_overflow_claim_context(**{**case.args, field: value}),
                      module.PreparationUnavailable)


@pytest.mark.parametrize("field,value", [
    ("unit_id", "other"), ("target_snapshot_id", "other"), ("build_identity", "other"),
    ("dependencies", ("other",)), ("assumptions", ("stronger-guarantee",)),
    ("representation", "decompiled"), ("applicability_domain", "binary-machine"),
    ("correspondence_ids", ("unrelated",)),
])
def test_atomic_current_manifest_drift_cannot_transfer_support(case, field, value):
    case.current[0] = (replace(case.target, **{field: value}), case.anchor)
    assert isinstance(module.prepare_overflow_claim_context(**case.args), module.PreparationUnavailable)
    fact, _ = bridge(case)
    assert fact.semantic == "unknown"


def test_current_anchor_drift_and_callback_exception_fail_closed(case):
    case.current[0] = (case.target, replace(case.anchor, byte_end=1, expected_span=b"i"))
    assert bridge(case)[0].semantic == "unknown"
    def unavailable():
        raise OSError("prepared manifest unavailable")
    assert isinstance(module.prepare_overflow_claim_context(
        **{**case.args, "current_prepared": unavailable}), module.PreparationUnavailable)


@pytest.mark.parametrize("statement", [
    "integer overflow in `Value + 1` is reachable and exploitable",
    "integer overflow in `Value + 1`; all callers reach it",
    "integer overflow in `Value + 1` ", "unknown novel semantic concern",
])
def test_stronger_or_novel_statement_has_no_registered_mechanical_credit(case, statement):
    revision = ClaimRevision({"mechanism": statement}, pass_id="new-pass", file="unit.c",
                             function="Read", line_start=1)
    scope = replace(case.scope, hypothesis=statement)
    actual = module.prepare_overflow_claim_context(**{**case.args, "revision": revision, "scope": scope})
    assert isinstance(actual, module.PreparationUnavailable)
    assert actual.reason == "unsupported-conclusion-shape"


@pytest.mark.parametrize("change", [
    {"witness_validated": True, "model": {"Value": 1}},
    {"model": {"Value": 2147483648}}, {"mathematical_result": 1},
    {"result_range": {"minimum": 0, "maximum": 1}},
    {"unknown": True}, {"unknown_reasons": ["missing predicate"]},
    {"proof_scope": "whole-program"}, {"assumptions": []},
])
def test_echoed_verdict_does_not_replace_independent_witness_replay(case, change):
    fact, _ = bridge(case, replace(case.result, details={**case.result.details, **change}))
    assert fact.semantic == "unknown"


@pytest.mark.parametrize("field,value", [
    ("line", 2), ("column", 1), ("guards", []), ("types", {"Value": "unsigned int"}),
    ("domains", ["Value < 0"]), ("profile", "uint32"), ("kind", "unsigned_wrap"),
    ("integer_abi", "lp64"),
])
def test_every_source_operation_component_must_match_current_binding(case, field, value):
    details = {**case.result.details, "source_operation": {
        **case.result.details["source_operation"], field: value}}
    assert bridge(case, replace(case.result, details=details))[0].semantic == "unknown"


@pytest.mark.parametrize("change", [
    {"outcome": "refuted"}, {"outcome": "inconclusive"}, {"errors": ["timeout"]},
    {"rule_id": "smt:check-overflow:supplied-model"}, {"file_path": "other.c"},
])
def test_negative_partial_other_or_supplied_model_result_remains_unknown(case, change):
    assert bridge(case, replace(case.result, **change))[0].semantic == "unknown"


def test_missing_durable_ack_cannot_admit_positive(case):
    fact, _ = bridge(case, retain=lambda snapshot: None)
    assert fact.semantic == "unknown" and not fact.raw_reference


def test_constructor_never_replaces_missing_build_with_source_hash_or_abi(case):
    target = replace(case.target, build_identity="")
    case.current[0] = (target, case.anchor)
    actual = module.prepare_overflow_claim_context(**{**case.args, "target": target})
    assert isinstance(actual, module.PreparationUnavailable)


@pytest.mark.parametrize("field,value", [("sha256", "wrong"), ("function", "Other"),
                                         ("query_contract", "old"), ("goal_contract", "other"),
                                         ("hypothesis_sha256", "other")])
def test_worker_source_contract_cannot_be_reused_for_changed_inputs(case, field, value):
    details = {**case.result.details, "source_scope": {
        **case.result.details["source_scope"], field: value}}
    assert bridge(case, replace(case.result, details=details))[0].semantic == "unknown"


def test_manifest_without_configured_abi_binding_is_unavailable(case):
    target = replace(case.target, dependencies=("prepared-dependency",))
    case.current[0] = (target, case.anchor)
    actual = module.prepare_overflow_claim_context(**{**case.args, "target": target})
    assert isinstance(actual, module.PreparationUnavailable)
    assert actual.reason == "prepared-integer-abi-binding-unavailable"


@pytest.mark.parametrize("error", [KeyboardInterrupt, SystemExit])
def test_current_manifest_cancellation_propagates_at_construction_and_validation(case, error):
    active = [False]
    def current():
        if active[0]:
            raise error("cancelled")
        return case.target, case.anchor
    case.prepared = module.prepare_overflow_claim_context(
        **{**case.args, "current_prepared": current})
    assert isinstance(case.prepared, module.PreparedOverflowContext)
    active[0] = True
    with pytest.raises(error):
        bridge(case)
    with pytest.raises(error):
        module.prepare_overflow_claim_context(**{**case.args, "current_prepared": current})


def test_current_manifest_ordinary_failure_retains_unknown_at_validation(case):
    active = [False]
    def current():
        if active[0]:
            raise OSError("manifest unavailable")
        return case.target, case.anchor
    case.prepared = module.prepare_overflow_claim_context(
        **{**case.args, "current_prepared": current})
    active[0] = True
    assert bridge(case)[0].semantic == "unknown"
