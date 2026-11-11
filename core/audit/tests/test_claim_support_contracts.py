"""Inert binding controls; no solver or target execution."""
from dataclasses import replace

import pytest

from core.audit.claim_support_contracts import (
    ConclusionSignature, ExecutedSupportBinding, PreparedTargetBinding,
    support_binding_rejection,
)


TARGET = PreparedTargetBinding("unit", "snapshot", "build", ("dep",), ("lp64",),
                               "source", "source-language")
CONCLUSION = ConclusionSignature("The selected addition wraps.", "storage-wrap",
                                 "selected-source-operation", ("lp64",))
IDENTITY = ("mechanical_observation", "smt", "v1", "wrap-validator", "v1",
            "registered-worker-invocation")
BINDING = ExecutedSupportBinding(TARGET, "request", "request", "raw.json", *IDENTITY,
                                 "supports_fact", CONCLUSION)


def rejection(binding=BINDING, **kwargs):
    values = dict(expected_target=TARGET, expected_conclusion=CONCLUSION,
                  request_id="request", executed_request_id="request",
                  raw_reference="raw.json", registered_identity=IDENTITY,
                  effect_scopes=frozenset({"selected-source-operation"}),
                  positive_kinds=frozenset({"storage-wrap"}))
    values.update(kwargs)
    return support_binding_rejection(binding, **values)


def test_exact_binding_is_prerequisite_only():
    assert rejection() is None
    assert not hasattr(BINDING, "supported")


@pytest.mark.parametrize("field,value", [
    ("unit_id", "other-unit"), ("target_snapshot_id", "other-snapshot"),
    ("build_identity", "other-build"), ("dependencies", ("other-dep",)),
    ("assumptions", ("ilp32",)), ("representation", "decompiled"),
    ("applicability_domain", "binary-machine"),
    ("correspondence_ids", ("unvalidated-correspondence",)),
])
def test_target_drift_cannot_transfer_support(field, value):
    assert rejection(replace(BINDING, target=replace(TARGET, **{field: value}))) == (
        "target-build-or-assumption-mismatch")


@pytest.mark.parametrize("field,value", [
    ("statement", "Every addition in the binary wraps."),
    ("conclusion_kind", "whole-program-safety"),
    ("effect_scope", "whole-binary"), ("conditions", ()),
])
def test_changed_conclusion_cannot_reuse_validated_signature(field, value):
    stronger = replace(CONCLUSION, **{field: value})
    assert rejection(expected_conclusion=stronger,
                     effect_scopes=frozenset({stronger.effect_scope})) == (
        "validated-conclusion-mismatch")


@pytest.mark.parametrize("field,value", [
    ("producer_kind", "reviewer_judgment"), ("producer_id", "model-claimed-smt"),
    ("producer_version", "v2"), ("validator_id", "echo"),
    ("validator_version", "v2"), ("execution_scope", "not-run"),
])
def test_registered_execution_identity_required(field, value):
    assert rejection(replace(BINDING, **{field: value})) == (
        "registered-producer-or-validator-mismatch")


@pytest.mark.parametrize("field,value", [
    ("request_id", "other"), ("executed_request_id", "other"),
    ("raw_reference", "other.json"),
])
def test_other_invocation_or_artifact_refused(field, value):
    assert rejection(replace(BINDING, **{field: value})) == (
        "executed-request-or-artifact-mismatch")


@pytest.mark.parametrize("semantic", ["unknown", "no_match", "confirmed", "failed"])
def test_execution_or_legacy_label_is_not_fact_semantics(semantic):
    assert rejection(replace(BINDING, semantic=semantic)) == (
        "unsupported-semantic-interpretation")


def test_negative_requires_separate_registered_interpretation():
    negative = replace(BINDING, semantic="contradicts_fact")
    assert rejection(negative) == "unsupported-semantic-interpretation"
    assert rejection(negative, negative_kinds=frozenset({"storage-wrap"})) is None


def test_narrow_diagnostic_cannot_become_source_effect():
    assert rejection(effect_scopes=frozenset({"supplied-byte-transfer"})) == (
        "unsupported-effect-scope")


def test_missing_novel_contract_is_unavailable_not_confirmation():
    assert rejection(registered_identity=()) == "registered-validator-unavailable"


def test_untyped_model_dict_is_not_validated_output():
    assert rejection({"complete": True, "confirmed": True}) == (
        "validated-support-binding-unavailable")


@pytest.mark.parametrize("field,value", [("unit_id", ""), ("assumptions", ("",)),
                                         ("representation", "")])
def test_malformed_pipeline_expectation_refused(field, value):
    assert rejection(expected_target=replace(TARGET, **{field: value})) == (
        "prepared-target-invalid")


def test_source_and_binary_need_explicit_matching_domain():
    binary = replace(TARGET, representation="decoded-instructions",
                     applicability_domain="binary-machine",
                     correspondence_ids=("matched-build-module-ranges",))
    assert rejection(expected_target=binary) == "target-build-or-assumption-mismatch"
