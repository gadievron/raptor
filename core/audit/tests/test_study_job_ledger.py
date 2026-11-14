"""Pure semantic lineage accounting controls; no model or worker dispatch."""

from dataclasses import replace

import pytest

from core.audit.study_job_ledger import SemanticStudyJobLedger, StudyJobDescriptor


def _begin(ledger, jobs, *, owner="owner", requests=("request",), inputs=("binding",), caps=(6,)):
    return ledger.begin(owner_id=owner, jobs=jobs, request_ids=requests,
                        input_binding_ids=inputs, unit_caps=caps)


def _job(ledger, lineage):
    return next(row for row in ledger.snapshot()["jobs"] if row["lineage"] == lineage)


def test_shared_packet_debits_distinct_lineages_once_and_preflights_all():
    ledger = SemanticStudyJobLedger(2)
    first = StudyJobDescriptor("first", "generation")
    second = StudyJobDescriptor("second", "generation")
    token, reason = _begin(ledger, (first, first, second), requests=("A", "B"), caps=(4, 5))
    assert token is not None and reason == ""
    assert len(token.jobs) == 2
    ledger.debit(token)
    ledger.debit(token)  # Identified retry in the same physical invocation.
    assert _job(ledger, "first")["spent"] == _job(ledger, "second")["spent"] == 2
    with pytest.raises(ValueError, match="study_job_call_limit"):
        ledger.debit(token)
    assert _job(ledger, "first")["spent"] == _job(ledger, "second")["spent"] == 2
    ledger.retire(token, accounting_known=True)
    unspent = StudyJobDescriptor("unspent", "generation")
    refused, reason = _begin(ledger, (unspent, second))
    assert refused is None and reason == "study_job_call_limit"
    assert _job(ledger, "unspent")["spent"] == 0


def test_generation_changes_do_not_reset_spend_or_overlap_live_dispatch():
    ledger = SemanticStudyJobLedger(2)
    old = StudyJobDescriptor("declaration", "old-source")
    token, _ = _begin(ledger, (old,))
    assert token is not None
    ledger.debit(token)
    new = replace(old, generation="new-source")
    refused, reason = _begin(ledger, (new,), requests=("new-request",))
    assert refused is None and reason == "study_job_dispatch_live"
    assert ledger.admission_rejection(token) == "study_job_owner_or_generation_closed"
    ledger.retire(token, accounting_known=True)
    assert not ledger.permits_answer("request", ("binding",))
    replacement, _ = _begin(ledger, (new,), requests=("new-request",), inputs=("new-binding",))
    assert replacement is not None
    ledger.debit(replacement)
    ledger.retire(replacement, accounting_known=True)
    assert _job(ledger, "declaration")["spent"] == 2
    assert ledger.permits_answer("new-request", ("new-binding",))
    # Returning to an old generation cannot revive an old answer or allowance.
    refused, reason = _begin(ledger, (old,))
    assert refused is None and reason == "study_job_call_limit"
    assert not ledger.permits_answer("request", ("binding",))
    assert not ledger.permits_answer("new-request", ("new-binding",))


def test_logical_completion_does_not_retire_a_live_physical_invocation():
    ledger = SemanticStudyJobLedger(3)
    job = StudyJobDescriptor("declaration", "source")
    token, _ = _begin(ledger, (job,))
    assert token is not None
    ledger.debit(token)
    ledger.owner_finished("owner")
    assert ledger.snapshot()["leases"][0]["active"] is True
    refused, reason = _begin(ledger, (job,), owner="replacement")
    assert refused is None and reason == "study_job_dispatch_live"
    ledger.retire(token, accounting_known=True)
    assert not ledger.permits_answer("request", ("binding",))
    replacement, _ = _begin(ledger, (job,), owner="replacement")
    assert replacement is not None
    ledger.debit(replacement)
    assert _job(ledger, "declaration")["spent"] == 2


def test_opaque_accounting_tombstone_survives_retirement_and_generation_change():
    ledger = SemanticStudyJobLedger(3)
    job = StudyJobDescriptor("declaration", "source")
    token, _ = _begin(ledger, (job,))
    assert token is not None
    ledger.debit(token)
    ledger.mark_unknown(token, "opaque-client")
    assert ledger.admission_rejection(token) == "study_job_accounting_unknown"
    ledger.retire(token, accounting_known=True)
    ledger.retire(token, accounting_known=False)  # Duplicate completion is inert.
    assert not ledger.permits_answer("request", ("binding",))
    refused, reason = _begin(ledger, (replace(job, generation="changed"),))
    assert refused is None and reason == "study_job_accounting_unknown"
    assert _job(ledger, "declaration")["spent"] == 1
    assert _job(ledger, "declaration")["unknown_reasons"] == ["opaque-client"]


def test_answer_scope_requires_retired_known_original_request_and_all_inputs():
    ledger = SemanticStudyJobLedger(2)
    token, _ = _begin(ledger, (StudyJobDescriptor("declaration", "source"),),
                      requests=("original-A", "original-B"), inputs=("cited", "uncited"))
    assert token is not None
    ledger.debit(token)
    assert not ledger.permits_answer("original-A", ("cited", "uncited"))
    ledger.retire(token, accounting_known=True)
    assert ledger.permits_answer("original-A", ("cited", "uncited"))
    assert ledger.permits_answer("original-B", ("cited", "uncited"))
    assert not ledger.permits_answer("late-beneficiary", ("cited", "uncited"))
    assert not ledger.permits_answer("original-A", ("cited",))
    assert not ledger.permits_answer("original-A", ("rebound-cited", "rebound-uncited"))
    assert not ledger.permits_answer("original-A", ("uncited", "cited"))


def test_charged_invocation_validity_is_distinct_from_another_admission():
    ledger = SemanticStudyJobLedger(1)
    job = StudyJobDescriptor("declaration", "source")
    token, _ = _begin(ledger, (job,))
    assert token is not None
    ledger.debit(token)
    assert ledger.validity_rejection(token) is None
    assert ledger.admission_rejection(token) == "study_job_call_limit"
    ledger.owner_finished("owner")
    assert ledger.validity_rejection(token) == "study_job_owner_or_generation_closed"

    changed = SemanticStudyJobLedger(1)
    original, _ = _begin(changed, (job,))
    assert original is not None
    changed.debit(original)
    assert _begin(changed, (replace(job, generation="changed"),))[1] == "study_job_dispatch_live"
    assert changed.validity_rejection(original) == "study_job_owner_or_generation_closed"

    opaque = SemanticStudyJobLedger(1)
    unknown, _ = _begin(opaque, (job,))
    assert unknown is not None
    opaque.debit(unknown)
    opaque.mark_unknown(unknown, "opaque-client")
    assert opaque.validity_rejection(unknown) == "study_job_accounting_unknown"


def test_close_preserves_live_lease_until_actual_retirement_and_never_refunds():
    ledger = SemanticStudyJobLedger(2)
    token, _ = _begin(ledger, (StudyJobDescriptor("declaration", "source"),))
    assert token is not None
    ledger.debit(token)
    ledger.close()
    state = ledger.snapshot()
    assert state["closed"] is True and state["leases"][0]["active"] is True
    assert ledger.admission_rejection(token) == "study_jobs_closed"
    assert _begin(ledger, token.jobs)[1] == "study_jobs_closed"
    ledger.retire(token, accounting_known=True)
    assert ledger.snapshot()["leases"][0]["active"] is False
    assert not ledger.permits_answer("request", ("binding",))
    assert _job(ledger, "declaration")["spent"] == 1
    state["jobs"][0]["spent"] = 0
    assert _job(ledger, "declaration")["spent"] == 1


@pytest.mark.parametrize("limit", [None, True, 0, -1, 1.5])
def test_job_allowance_requires_explicit_positive_integer(limit):
    with pytest.raises(ValueError, match="explicit positive integer"):
        SemanticStudyJobLedger(limit)


def test_participant_freeze_refuses_policy_above_any_unit_cap_or_ambiguous_generation():
    ledger = SemanticStudyJobLedger(3)
    job = StudyJobDescriptor("declaration", "source")
    assert _begin(ledger, (job,), caps=(6, 2))[1] == "study_job_allowance_exceeds_unit_cap"
    assert _begin(ledger, (job, replace(job, generation="other")))[1] == "study_job_generation_ambiguous"
    assert ledger.snapshot()["jobs"] == []
    assert _begin(ledger, (job,), requests=("duplicate", "duplicate"))[1] == "study_job_inputs_unavailable"
    assert _begin(ledger, (job,), inputs=("same", "same"))[1] == "study_job_inputs_unavailable"
    token, _ = _begin(ledger, (job,))
    assert token is not None
    assert ledger.admission_rejection(replace(token)) == "study_job_lease_unavailable"
