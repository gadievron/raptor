"""Unexecuted selected-callee regression control for the subject-currentness draft.

This exercises actual Runtime reservation/currentness with owned scripted
assessments. It is not an append-ACK, backend, provider or verification proof.
"""
from copy import copy

from core.audit.continuation_context import context_version
from core.audit.tests.test_binary_callee_assessments import assessment_case as assessment_case
from core.audit.tests.test_study_claim_retention import _owned_review_caches as _owned_review_caches
from core.json import dumps_canonical




def test_selected_callee_currentness_survives_subject_recheck_extension(assessment_case, tmp_path, monkeypatch):
    install = tmp_path / "owned-install"
    install.mkdir()
    monkeypatch.setenv("RAPTOR_DIR", str(install))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    case = assessment_case()
    payload = case.build()
    assert payload is not None and payload.current(case.ctx)
    ctx = {**case.ctx, "binary_callee_assessment_context": payload}
    module_before = case.target.read_bytes()
    database_before = dumps_canonical(case.database.to_dict())
    calls_before = dict(case.runtime._calls)
    canonical_caller = case.canonical[0]
    original_callee = case.callees[0]
    version = context_version(payload.render())
    assert case.runtime.offer_context_delta(ctx, kind="binary_callee_assessments", version=version)
    reservation = case.runtime.reserve_context_continuation(
        ctx, admission=lambda: True,
        required_context_id=f"context:binary_callee_assessments:{version}",
    )
    assert reservation is not None
    assert case.runtime.can_publish(reservation) is True
    assert case.canonical[1] is original_callee

    # Identical assessment bytes under a different canonical object do not
    # refresh the original observation owner carried by the retained payload.
    replacement = copy(original_callee)
    case.canonical[1] = replacement
    assert replacement is not original_callee
    assert payload.current(ctx) is False
    assert case.runtime.can_publish(reservation) is False
    assert case.target.read_bytes() == module_before
    assert dumps_canonical(case.database.to_dict()) == database_before
    assert case.canonical[0] is canonical_caller
    assert dict(case.runtime._calls) == calls_before
    assert not any(event["event"] == "continuation_completed" for event in case.runtime.events())
    assert case.runtime.fail(reservation, "owned_callee_regression_complete", ctx=ctx)
