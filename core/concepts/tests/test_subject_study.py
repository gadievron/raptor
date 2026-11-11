"""Explicit subjects are explained by the existing study call, without proof."""

import pytest

from core.concepts.model import StudyItem
from core.concepts.study import _RESPONSE_SCHEMA, _run_one_batch
from core.concepts.subject_study import StudySubject, StudySubjects


def _subjects():
    return StudySubjects((StudySubject("owned-request", "foo_t", "role in the containing value",
                                       "identifier", "owned.c"),))


def _items():
    return [StudyItem("owned-item", "struct", "foo_t", "owned.c", line=1,
                      definition="typedef struct { unsigned length; } foo_t;")]


def test_existing_study_call_returns_linked_explanation_without_invariants(caplog):
    subjects = _subjects()
    calls = []

    class Client:
        def generate_structured(self, prompt, schema, **kwargs):
            calls.append((prompt, schema, kwargs))
            return {
                "subject_answers": [{"request_id": "owned-request", "status": "partial",
                    "explanation": "The structure carries a length; ownership is not shown.",
                    "reason": "Only the type definition was supplied.", "material_ids": ["material-0"]}],
            }

    result = _run_one_batch(0, 1, _items(), [], "owned", "", Client(), None, None,
                            max_tokens=2048, subjects=subjects)
    assert result == ([], [], [], [], [])
    assert len(calls) == 1
    prompt, schema, kwargs = calls[0]
    assert '"subject": "foo_t"' in prompt
    assert "role in the containing value" in prompt
    assert "typedef struct" in prompt
    assert "subject_answers" in schema["properties"]
    assert schema["required"] == ["subject_answers"]
    assert "subject_answers" not in _RESPONSE_SCHEMA["properties"]
    assert "subject_answers" not in _RESPONSE_SCHEMA["required"]
    assert kwargs["task_type"] == "study"
    assert not any("LLM returned empty result" in record.getMessage() for record in caplog.records)
    answers = subjects.snapshot()
    assert len(answers) == 1
    assert answers[0].request_id == "owned-request"
    assert answers[0].status == "partial"
    assert answers[0].materials[0].text == _items()[0].definition
    assert not subjects.pending_ids()


def test_foreign_and_duplicate_answers_cannot_replace_requested_explanation():
    subjects = _subjects()
    packet = subjects.prepare(_items(), [])
    row = {"request_id": "owned-request", "status": "answered",
           "explanation": "Source explanation", "reason": "", "material_ids": ["material-0"]}
    subjects.record(packet, {"subject_answers": [row, row, {**row, "request_id": "other-pass"}]})
    assert subjects.snapshot()[0].status == "unavailable"
    assert subjects.snapshot()[0].reason == "duplicate_subject_answer"
    assert subjects.rejections() == ("answer_for_unsubmitted_request",)


def test_unknown_material_is_not_grounding_and_unselected_subject_stays_pending():
    subjects = _subjects()
    packet = subjects.prepare(_items(), [])
    subjects.record(packet, {"subject_answers": [{"request_id": "owned-request", "status": "answered",
        "explanation": "Claim without the supplied material", "reason": "", "material_ids": ["forged"]}]})
    assert subjects.snapshot()[0].reason == "invalid_subject_answer_or_materials"
    unseen = _subjects()
    empty = unseen.prepare([], [])
    unseen.record(empty, {"subject_answers": []})
    assert unseen.pending_ids() == ("owned-request",)


def test_each_batch_retains_its_material_snapshot_and_competing_answer():
    subjects = _subjects()
    items = _items()
    first = subjects.prepare(items, [])
    items[0].definition = "typedef struct { unsigned other; } foo_t;"
    second = subjects.prepare(items, [])
    for packet, explanation in ((first, "length carrier"), (second, "other field carrier")):
        subjects.record(packet, {"subject_answers": [{"request_id": "owned-request", "status": "partial",
            "explanation": explanation, "reason": "", "material_ids": ["material-0"]}]})
    answers = subjects.snapshot()
    assert len(answers) == 2
    assert "length" in answers[0].materials[0].text
    assert "other" in answers[1].materials[0].text


def test_source_fragment_truncation_is_disclosed():
    subjects = _subjects()
    items = _items()
    items[0].definition += " " * 900
    packet = subjects.prepare(items, [])
    assert packet.materials[0].truncated
    assert len(packet.materials[0].text) == 800
    assert '"truncated": true' in packet.prompt()


def test_phase_dispatch_carries_subjects_without_buying_an_explanation_call():
    from core.concepts.study import run_phase2

    subjects = _subjects()
    calls = []

    class Client:
        def generate_structured(self, prompt, schema, **kwargs):
            calls.append(prompt)
            return {"concepts": [], "invariants": [], "contracts": [], "bug_patterns": [],
                    "subject_answers": [{"request_id": "owned-request", "status": "partial",
                        "explanation": "The definition carries length; no users were supplied.",
                        "reason": "Incomplete usage context", "material_ids": ["material-0"]}]}

    result = run_phase2(_items(), "owned", Client(), batch_target=1, subjects=subjects)
    assert len(calls) == 1
    assert result == ([], [], [], [], [])
    assert subjects.snapshot()[0].status == "partial"
    assert not subjects.pending_ids()


def test_phase_stop_keeps_requests_pending_without_a_new_call():
    from core.concepts.study import run_phase2

    subjects = _subjects()

    class Client:
        def generate_structured(self, *args, **kwargs):
            raise AssertionError("stopped study dispatched")

    result = run_phase2(_items(), "owned", Client(), batch_target=1,
                        subjects=subjects, should_stop=lambda: True)
    assert result == ([], [], [], [], [])
    assert not subjects.snapshot()
    assert subjects.pending_ids() == ("owned-request",)


def test_explanation_is_available_while_another_study_batch_is_inflight(monkeypatch):
    import threading

    from core.concepts import study

    subjects = StudySubjects((
        StudySubject("owned-request", "foo_t", "role", "identifier", "owned.c"),
        StudySubject("other-request", "bar_t", "role", "identifier", "owned.c"),
    ))
    second_started = threading.Event()
    release_second = threading.Event()
    errors = []
    calls = []

    def forbidden_derived_processing(*args, **kwargs):
        raise AssertionError("targeted explanation entered invariant processing")

    monkeypatch.setattr(study, "_parse_batch_response", forbidden_derived_processing)

    class Client:
        def generate_structured(self, prompt, schema, **kwargs):
            calls.append(prompt)
            second = len(calls) == 2
            if second:
                second_started.set()
                if not release_second.wait(5):
                    raise AssertionError("test did not release second study batch")
            return {"subject_answers": [{"request_id": "other-request" if second else "owned-request",
                "status": "partial", "explanation": "The type carries a value; callers are absent.",
                "reason": "Usage is not supplied", "material_ids": ["material-0"]}]}

    def work():
        try:
            other = StudyItem("bar", "struct", "bar_t", "owned.c", line=2,
                             definition="typedef struct { unsigned value; } bar_t;")
            # Explicit batches isolate update delivery from the independent
            # clustering heuristic. Public phase dispatch is covered above.
            study._run_phase2_serial([(_items(), []), ([other], [])],
                                     "owned", "", Client(), None, None, subjects=subjects)
        except BaseException as exc:
            errors.append(exc)

    worker = threading.Thread(target=work)
    worker.start()
    try:
        assert second_started.wait(5)
        assert subjects.ready_event.is_set()
        assert worker.is_alive()
        updates = subjects.drain_updates()
        assert len(updates) == 1 and updates[0].status == "partial"
        assert updates[0].request_id == "owned-request"
        assert subjects.drain_updates() == ()
        assert not subjects.ready_event.is_set()
        assert len(subjects.snapshot()) == 1
        assert len(calls) == 2
    finally:
        release_second.set()
        worker.join(timeout=5)
    assert not worker.is_alive()
    assert not errors
    assert len(subjects.drain_updates()) == 1
    assert len(subjects.snapshot()) == 2


def test_targeted_call_does_not_receive_unbound_background_or_derived_fields():
    from core.concepts.study import _run_one_batch

    subjects = _subjects()
    items = _items()
    items[0].doc_comment = "UNBOUND_COMMENT"
    items[0].fields = ["UNBOUND_DERIVED_FIELD"]
    calls = []

    class Client:
        def generate_structured(self, prompt, schema, **kwargs):
            calls.append(prompt)
            assert "UNBOUND_BACKGROUND" not in prompt
            assert "UNBOUND_COMMENT" not in prompt
            assert "UNBOUND_DERIVED_FIELD" not in prompt
            assert items[0].definition in prompt
            assert set(schema["properties"]) == {"subject_answers"}
            return {"subject_answers": [{"request_id": "owned-request", "status": "partial",
                "explanation": "Only the supplied declaration is known.", "reason": "No usage supplied",
                "material_ids": ["material-0"]}]}

    result = _run_one_batch(0, 1, items, [], "owned", "", Client(), None, None,
                            doc_context="UNBOUND_BACKGROUND", subjects=subjects)
    assert result == ([], [], [], [], [])
    assert len(calls) == 1
    assert subjects.snapshot()[0].extra_context_excluded


def test_unrelated_targeted_batch_keeps_request_pending_without_a_model_call():
    from core.concepts.study import run_phase2

    subjects = _subjects()

    class Client:
        def generate_structured(self, *args, **kwargs):
            raise AssertionError("unrelated batch bought generic extraction")

    other = StudyItem("bar", "struct", "bar_t", "owned.c", definition="struct bar_t { unsigned x; };")
    result = run_phase2([other], "owned", Client(), batch_target=1, subjects=subjects)
    assert result == ([], [], [], [], [])
    assert subjects.pending_ids() == ("owned-request",)
    assert not subjects.snapshot()


def test_worker_refusal_uses_own_packet_without_retry_and_resets_context():
    from core.concepts.subject_study import SubjectDispatchRefused
    subjects = _subjects()
    calls = []

    class Client:
        def generate_structured(self, *args, **kwargs):
            packet = subjects.current_packet()
            assert packet is not None
            calls.append(tuple(s.request_id for s in packet.subjects))
            raise SubjectDispatchRefused("source_changed_before_attempt")

    result = _run_one_batch(0, 1, _items(), [], "owned", "", Client(), None, None,
                            max_tokens=2048, subjects=subjects)
    assert result == ([], [], [], [], [])
    assert calls == [("owned-request",)]
    assert subjects.current_packet() is None
    assert subjects.snapshot()[0].reason == "source_changed_before_attempt"
    assert subjects.snapshot()[0].producer == "pipeline"


def test_update_callback_runs_after_answer_lock_and_keeps_committed_result():
    observations = []
    subjects = StudySubjects((StudySubject("r", "foo_t", "role", "identifier", "owned.c"),),
                             on_update=lambda: observations.append(subjects.drain_updates()))
    packet = subjects.prepare(_items(), [])
    subjects.unavailable(packet, "no_source")
    assert observations[0][0].request_id == "r"
    assert subjects.snapshot()[0].reason == "no_source"


def test_split_batches_expose_only_actual_submitted_waiter_packet():
    from core.concepts.study import run_phase2
    subjects = StudySubjects((StudySubject("a", "One.run", "first receiver", "identifier", "one.py"),
                              StudySubject("b", "Two.run", "second receiver", "identifier", "two.py")),
                             request_items={"a": frozenset({"one"}), "b": frozenset({"two"})})
    items = [StudyItem("one", "function", "run", "one.py", line=2, definition="def run(self): pass"),
             StudyItem("two", "function", "run", "two.py", line=2, definition="def run(self): pass")]
    submitted = []

    class Client:
        def generate_structured(self, prompt, schema, **kwargs):
            packet = subjects.current_packet()
            assert packet is not None and len(packet.subjects) == 1
            submitted.append(packet.subjects[0].request_id)
            return {"subject_answers": [{"request_id": packet.subjects[0].request_id,
                "status": "partial", "explanation": "Method body only", "reason": "limited source",
                "material_ids": [packet.materials[0].material_id]}]}

    run_phase2(items, "owned", Client(), batch_target=1, subjects=subjects)
    assert sorted(submitted) == ["a", "b"]
    assert {a.request_id for a in subjects.snapshot()} == {"a", "b"}
    assert subjects.current_packet() is None


@pytest.mark.parametrize("field", ["explanation", "reason"])
@pytest.mark.parametrize("invalid", [chr(0xD800), chr(0xDFFF)], ids=["high-surrogate", "low-surrogate"])
def test_non_utf8_answer_text_is_unavailable_without_discarding_valid_sibling(field, invalid):
    subjects = StudySubjects(tuple(
        StudySubject(request_id, "foo_t", "role", "identifier", "owned.c")
        for request_id in ("invalid-request", "valid-request")))
    packet = subjects.prepare(_items(), [])
    valid = {"request_id": "valid-request", "status": "partial",
             "explanation": "café 東京 😀\nThe type carries a length.",
             "reason": "Only this definition is supplied.\nOther uses are unknown.",
             "material_ids": ["material-0"]}
    invalid_row = {**valid, "request_id": "invalid-request", field: valid[field] + invalid}
    rejected, accepted = subjects.record(packet, {"subject_answers": [invalid_row, valid]})
    assert rejected.request_id == "invalid-request"
    assert (rejected.status, rejected.explanation, rejected.reason, rejected.materials) == (
        "unavailable", "", "invalid_subject_answer_or_materials", ())
    assert rejected.inputs == packet.materials
    assert accepted.request_id == "valid-request" and accepted.status == "partial"
    assert accepted.explanation == valid["explanation"] and accepted.reason == valid["reason"]
    assert accepted.materials == packet.materials
    assert subjects.snapshot() == (rejected, accepted)
    assert not subjects.pending_ids()


@pytest.mark.parametrize("status", ["partial", "unavailable"])
@pytest.mark.parametrize("reason", ["", "café 東京 😀\nLimited supplied source."])
def test_utf8_answer_text_preserves_blank_reason_and_unavailable_semantics(status, reason):
    subjects = _subjects()
    packet = subjects.prepare(_items(), [])
    explanation = "café 東京 😀\nThe type carries length." if status == "partial" else ""
    answer, = subjects.record(packet, {"subject_answers": [{
        "request_id": "owned-request", "status": status, "explanation": explanation,
        "reason": reason, "material_ids": ["material-0"] if status == "partial" else []}]})
    assert (answer.status, answer.explanation, answer.reason) == (status, explanation, reason)
    assert answer.materials == (packet.materials if status == "partial" else ())
