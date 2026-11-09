"""Knowledge-only continuation decisions use actual bound source inputs."""

from dataclasses import replace

import pytest

from core.audit.knowledge_requests import KnowledgeOrigin, register_requests
from core.audit.refutation_source import capture_source_identity
from core.audit.review_cycle import KnowledgeCycle
from core.audit.study_inputs import StudyInputBindings
from core.concepts.model import StudyItem
from core.concepts.subject_study import StudySubject, StudySubjects
from core.language_reference import ReferenceContext, lookup


SOURCE = "typedef struct { unsigned length; } foo_t;\nunsigned f(foo_t v) { return v.length; }\n"


def _cycle(tmp_path, **policy):
    (tmp_path / "owned.c").write_text(SOURCE)
    identity = capture_source_identity(tmp_path, "owned.c")
    assert identity is not None
    origin = KnowledgeOrigin("owned-pass", "owned.c", "f", 1, 2, identity)
    batch = register_requests({"reading_list": [{"subject": "foo_t"}],
                               "language_reference_requests": [{"topic": "conversion"}]}, origin)
    bindings = StudyInputBindings(tmp_path)
    cycle = KnowledgeCycle(origin, batch, deadline=100, admit_study=bindings.admit, **policy)
    study, reference = batch.accepted
    answer = lookup(reference.request_id, reference.subject, ReferenceContext("c"))
    subjects = StudySubjects((StudySubject(study.request_id, study.subject, study.context,
                                         study.resolution, origin.file),), bind_packet=bindings.bind)
    packet = subjects.prepare([StudyItem("type", "struct", "foo_t", "owned.c", line=1,
                                        definition=SOURCE.splitlines()[0])], [])
    subjects.record(packet, {"subject_answers": [{"request_id": study.request_id,
        "status": "partial", "explanation": "The type carries a length; users are absent.",
        "reason": "Incomplete usage context", "material_ids": ["material-0"]}]})
    return cycle, identity, answer, subjects.snapshot()[0]


def _reserve(cycle, identity, now, calls=1, admission=lambda: True):
    return cycle.reserve(now=now, current_source=identity, admission=admission, all_model_calls=calls)


def test_ready_source_and_reference_coalesce_into_one_packet(tmp_path):
    cycle, identity, reference, explanation = _cycle(tmp_path)
    assert cycle.reference(reference, now=0)
    assert _reserve(cycle, identity, 0) is None
    assert cycle.explanation(explanation, now=5)
    assert cycle.finished(explanation.request_id)
    packet = _reserve(cycle, identity, 5)
    assert packet.references == (reference,)
    assert packet.explanations == (explanation,)
    assert not packet.pending_ids
    assert cycle.started == 1
    assert _reserve(cycle, identity, 6) is None
    assert cycle.complete(packet.pass_id, (reference.request_id, explanation.request_id))
    assert _reserve(cycle, identity, 7, calls=2) is None


def test_followup_requests_keep_original_allowance_and_source_scope(tmp_path):
    cycle, identity, reference, explanation = _cycle(tmp_path, max_continuations=1)
    cycle.reference(reference, now=0)
    cycle.finished(explanation.request_id)
    packet = _reserve(cycle, identity, 1)
    assert cycle.complete(packet.pass_id, (reference.request_id,))

    followup = replace(cycle.origin, pass_id=packet.pass_id)
    batch = register_requests({"language_reference_requests": [{"topic": "integer promotion"}]}, followup)
    assert cycle.add_requests(batch)
    request = batch.accepted[0]
    assert cycle.requests[request.request_id].origin.pass_id == packet.pass_id
    cycle.reference(lookup(request.request_id, request.subject, ReferenceContext("c")), now=2)
    assert _reserve(cycle, identity, 2, calls=2) is None
    assert cycle.started == 1 and cycle.deadline == 100
    assert any(e.reason == "continuation_limit" for e in cycle.events())

    previous = dict(cycle.requests)
    foreign = register_requests({"reading_list": [{"subject": "other_t"}]},
                                replace(followup, line_start=2))
    assert not cycle.add_requests(foreign)
    assert dict(cycle.requests) == previous
    (tmp_path / "owned.c").write_text(SOURCE + "/* another snapshot */\n")
    changed = register_requests({"reading_list": [{"subject": "other_t"}]},
                               replace(followup, source_identity=capture_source_identity(tmp_path, "owned.c")))
    assert not cycle.add_requests(changed)
    assert dict(cycle.requests) == previous


def test_duplicate_results_do_not_extend_coalescing_window(tmp_path):
    cycle, identity, reference, explanation = _cycle(tmp_path)
    cycle.reference(reference, now=0)
    cycle.reference(reference, now=9)
    assert _reserve(cycle, identity, 9) is None
    packet = _reserve(cycle, identity, 10)
    assert packet.references == (reference,)
    assert not packet.explanations
    assert packet.pending_ids == (explanation.request_id,)


def test_result_arriving_during_review_waits_for_the_active_pass(tmp_path):
    cycle, identity, reference, explanation = _cycle(tmp_path)
    cycle.reference(reference, now=0)
    first = _reserve(cycle, identity, 10)
    cycle.explanation(explanation, now=11)
    cycle.finished(explanation.request_id)
    assert _reserve(cycle, identity, 11, calls=2) is None
    cycle.complete(first.pass_id, (reference.request_id,))
    second = _reserve(cycle, identity, 11, calls=2)
    assert second is not None and second.pass_id != first.pass_id
    assert second.explanations == (explanation,)
    assert second.delta_ids == (explanation.request_id,)


def test_omitted_attempt_does_not_restore_continuation_allowance(tmp_path):
    cycle, identity, reference, explanation = _cycle(tmp_path, max_continuations=1)
    cycle.reference(reference, now=0)
    first = _reserve(cycle, identity, 10)
    assert cycle.complete(first.pass_id, ())
    cycle.explanation(explanation, now=11)
    cycle.finished(explanation.request_id)
    assert _reserve(cycle, identity, 11, calls=2) is None
    assert cycle.started == 1
    assert any(e.event == "prompt_omitted" for e in cycle.events())
    assert any(e.reason == "continuation_limit" for e in cycle.events())


def test_failed_attempt_is_not_a_prompt_omission_or_a_free_retry(tmp_path):
    cycle, identity, reference, explanation = _cycle(tmp_path, max_continuations=1)
    cycle.reference(reference, now=0)
    first = _reserve(cycle, identity, 10)
    assert cycle.failed(first.pass_id, reason="dispatch_failed")
    count = len(cycle.events())
    assert cycle.failed(first.pass_id, reason="dispatch_failed")
    assert len(cycle.events()) == count
    assert not cycle.complete(first.pass_id, ())
    assert any(e.event == "continuation_failed" and e.reason == "dispatch_failed" for e in cycle.events())
    assert not any(e.event in ("prompt_delivered", "prompt_omitted") for e in cycle.events())
    cycle.explanation(explanation, now=11)
    cycle.finished(explanation.request_id)
    assert _reserve(cycle, identity, 11, calls=2) is None
    assert cycle.started == 1


def test_shared_admission_and_attempt_limit_precede_dispatch(tmp_path):
    cycle, identity, reference, explanation = _cycle(tmp_path)
    cycle.reference(reference, now=0)
    cycle.finished(explanation.request_id)
    invoked = []

    def admit():
        invoked.append(True)
        return True

    assert _reserve(cycle, identity, 1, calls=6, admission=admit) is None
    assert not invoked and cycle.started == 0
    assert _reserve(cycle, identity, 1, calls=None, admission=admit) is None
    assert not invoked
    assert _reserve(cycle, identity, 1, admission=lambda: False) is None
    assert cycle.started == 0
    assert _reserve(cycle, identity, 1, admission=admit) is not None
    assert invoked == [True]


def test_source_change_cannot_restart_old_snapshot_with_a_new_pass_id(tmp_path):
    cycle, identity, reference, explanation = _cycle(tmp_path)
    cycle.reference(reference, now=0)
    cycle.finished(explanation.request_id)
    (tmp_path / "owned.c").write_text(SOURCE + "/* changed */\n")
    current = capture_source_identity(tmp_path, "owned.c")
    assert _reserve(cycle, current, 1) is None
    # Even a caller replaying the old identity cannot revive a retired unit.
    assert _reserve(cycle, identity, 2) is None
    assert cycle.started == 0
    assert any(e.event == "source_changed" for e in cycle.events())


def test_material_rechecked_after_answer_arrival(tmp_path):
    cycle, identity, reference, explanation = _cycle(tmp_path)
    assert cycle.explanation(explanation, now=0)
    cycle.finished(explanation.request_id)
    cycle.reference(replace(reference, status="unsupported", entries=()), now=0)
    (tmp_path / "owned.c").write_text(SOURCE + "/* changed */\n")
    # A stale consumer-supplied current-source value cannot bypass the study
    # material's independent recheck immediately before reserving a review.
    assert _reserve(cycle, identity, 1) is None
    assert cycle.started == 0
    assert any(e.reason == "study_material_changed" for e in cycle.events())


def test_completion_replays_are_idempotent_and_conflicts_do_not_acknowledge(tmp_path):
    cycle, identity, reference, explanation = _cycle(tmp_path)
    cycle.reference(reference, now=0)
    cycle.finished(explanation.request_id)
    packet = _reserve(cycle, identity, 1)
    assert not cycle.complete(packet.pass_id, ("foreign-request",))
    assert cycle.complete(packet.pass_id, (reference.request_id,))
    count = len(cycle.events())
    assert cycle.complete(packet.pass_id, (reference.request_id,))
    assert len(cycle.events()) == count
    assert not cycle.complete(packet.pass_id, ())
    assert cycle.events()[-1].reason == "conflicting_replay"


def test_unavailable_information_or_deadline_does_not_buy_an_empty_review(tmp_path):
    cycle, identity, reference, explanation = _cycle(tmp_path)
    cycle.reference(replace(reference, status="unsupported", entries=()), now=0)
    cycle.explanation(replace(explanation, status="unavailable", explanation="", materials=()), now=0)
    cycle.finished(explanation.request_id)
    assert _reserve(cycle, identity, 1) is None
    assert cycle.started == 0
    cycle.reference(reference, now=2)
    assert _reserve(cycle, identity, 100) is None
    assert cycle.started == 0
    assert any(e.reason == "deadline" for e in cycle.events())


def test_unknown_request_identity_is_rejected_and_request_snapshot_is_read_only(tmp_path):
    cycle, identity, reference, explanation = _cycle(tmp_path)
    assert not cycle.reference(replace(reference, request_id="foreign"), now=0)
    assert not cycle.explanation(replace(explanation, request_id=reference.request_id), now=0)
    assert not cycle.finished("foreign")
    assert _reserve(cycle, identity, 10) is None
    with pytest.raises(TypeError):
        cycle.requests["foreign"] = next(iter(cycle.requests.values()))


def test_panel_reservation_cannot_exceed_remaining_calls(tmp_path):
    cycle, identity, reference, explanation = _cycle(tmp_path)
    cycle.reference(reference, now=0)
    cycle.finished(explanation.request_id)
    admitted = []
    assert cycle.reserve(now=1, current_source=identity,
                         admission=lambda: admitted.append(True) or True,
                         all_model_calls=3, required_calls=4) is None
    assert not admitted
    assert cycle.events()[-1].reason == "model_call_limit"
    assert cycle.started == 0


def test_wake_stops_when_count_is_unknown_or_round_exhausted(tmp_path):
    cycle, identity, reference, explanation = _cycle(tmp_path, max_continuations=1)
    cycle.reference(reference, now=0)
    assert cycle.wake_after(now=1, all_model_calls=None) is None
    assert cycle.wake_after(now=1, all_model_calls=1) > 0
    cycle.finished(explanation.request_id)
    packet = _reserve(cycle, identity, 1)
    cycle.failed(packet.pass_id)
    assert cycle.wake_after(now=2, all_model_calls=2) is None
    assert cycle.state_record()["started"] == 1
