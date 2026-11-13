"""An answer-row bound cannot hide conflicting replies outside its prefix."""
import pytest

from core.concepts.model import StudyItem
from core.concepts.subject_study import StudySubject, StudySubjects


def _case():
    subjects = StudySubjects((StudySubject("owned-request", "foo_t", "role", "identifier", "owned.c"),))
    item = StudyItem("owned-item", "struct", "foo_t", "owned.c", line=1,
                     definition="typedef struct { unsigned length; } foo_t;")
    packet = subjects.prepare([item], [])
    owned = {"request_id": "owned-request", "status": "answered", "explanation": "Length carrier",
             "reason": "", "material_ids": ["material-0"]}
    foreign = [{"request_id": "foreign-" + str(i), "status": "unavailable", "explanation": "",
                "reason": "", "material_ids": []} for i in range(32)]
    return subjects, packet, owned, foreign


def test_overflow_cannot_hide_conflicting_duplicate_after_inspected_prefix():
    subjects, packet, owned, foreign = _case()
    duplicate = {**owned, "status": "partial", "explanation": "Conflicting explanation"}
    rows = [owned, *foreign[:31], duplicate]
    assert len(rows) == 33 and rows[0]["request_id"] == rows[-1]["request_id"]
    answers = subjects.record(packet, {"subject_answers": rows})
    assert len(answers) == 1 and answers[0].request_id == "owned-request"
    assert answers[0].status == "unavailable"
    assert answers[0].reason == "subject_answer_limit_exceeded"
    assert answers[0].inputs == packet.materials and not answers[0].materials
    assert subjects.snapshot() == answers


@pytest.mark.parametrize("row_count", [31, 32, 33])
def test_existing_answer_bound_preserves_complete_in_bound_responses(row_count):
    subjects, packet, owned, foreign = _case()
    rows = [owned, *foreign[:row_count - 1]]
    assert len(rows) == row_count
    answer, = subjects.record(packet, {"subject_answers": rows})
    assert answer.request_id == "owned-request" and answer.inputs == packet.materials
    if row_count <= 32:
        assert answer.status == "answered" and answer.explanation == owned["explanation"]
        assert answer.materials == packet.materials
        assert subjects.rejections() == ("answer_for_unsubmitted_request",) * (row_count - 1)
    else:
        assert answer.status == "unavailable" and not answer.materials
        assert answer.reason == "subject_answer_limit_exceeded"
        assert subjects.rejections() == ("subject_answer_limit_exceeded",)


def test_duplicate_at_last_in_bound_row_stays_a_duplicate_failure():
    subjects, packet, owned, foreign = _case()
    rows = [owned, *foreign[:30], {**owned, "explanation": "Competing explanation"}]
    assert len(rows) == 32
    answer, = subjects.record(packet, {"subject_answers": rows})
    assert answer.status == "unavailable" and answer.reason == "duplicate_subject_answer"
    assert subjects.rejections() == ("answer_for_unsubmitted_request",) * 30


def test_overflow_refusal_does_not_scan_or_copy_unvalidated_rows():
    subjects, packet, owned, _foreign = _case()

    class OverflowRows(list):
        def __iter__(self):
            raise AssertionError("overflow rows must not be scanned")

        def __getitem__(self, key):
            raise AssertionError("overflow prefix must not be copied")

    answer, = subjects.record(packet, {"subject_answers": OverflowRows([owned] * 33)})
    assert answer.status == "unavailable" and answer.reason == "subject_answer_limit_exceeded"
    assert answer.inputs == packet.materials


def test_overflow_retains_earlier_partial_and_original_material_history():
    subjects, packet, owned, foreign = _case()
    first = subjects.record(packet, {"subject_answers": [{**owned, "status": "partial"}]})
    assert subjects.drain_updates() == first
    second = subjects.record(packet, {"subject_answers": [owned, *foreign]})
    assert subjects.snapshot() == (*first, *second)
    assert first[0].status == "partial" and first[0].materials == packet.materials
    assert second[0].status == "unavailable" and second[0].inputs == packet.materials
    assert subjects.drain_updates() == second
    assert not subjects.drain_updates()


def test_overflow_emits_per_request_failure_without_forging_answered_material():
    subjects, packet, owned, _foreign = _case()
    second = StudySubject("second-request", "bar_t", "role", "identifier", "owned.c")
    multiple = StudySubjects((*subjects.subjects, second))
    item = StudyItem("owned-item", "struct", "foo_t", "owned.c", line=1,
                     definition=packet.materials[0].text)
    second_item = StudyItem("second-item", "struct", "bar_t", "owned.c", line=2,
                            definition="typedef struct { unsigned capacity; } bar_t;")
    supplied = multiple.prepare([item, second_item], [])
    assert {s.request_id for s in supplied.subjects} == {"owned-request", "second-request"}
    answers = multiple.record(supplied, {"subject_answers": [owned] * 33})
    assert {answer.request_id for answer in answers} == {"owned-request", "second-request"}
    assert all(answer.status == "unavailable" and answer.reason == "subject_answer_limit_exceeded"
               and answer.inputs == supplied.materials and not answer.materials for answer in answers)
    assert multiple.snapshot() == answers


def test_in_bound_response_uses_existing_bounded_snapshot():
    subjects, packet, owned, foreign = _case()

    class InBoundRows(list):
        def __iter__(self):
            raise AssertionError("borrowed answer list must be snapshotted before parsing")

    answer, = subjects.record(packet, {"subject_answers": InBoundRows([owned, *foreign[:31]])})
    assert answer.status == "answered" and answer.materials == packet.materials
    assert subjects.rejections() == ("answer_for_unsubmitted_request",) * 31
