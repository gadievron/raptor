"""Source-study inputs stay current across multi-file and multi-answer checks."""

from core.audit import study_inputs
from core.audit.knowledge_runtime import AuditKnowledgeRuntime
from core.audit.orchestrator import StudyQueue
from core.concepts.subject_study import SubjectExplanation, SubjectMaterial, SubjectPacket


def _files(tmp_path):
    (tmp_path / "a.h").write_text("typedef unsigned first_t;\n")
    (tmp_path / "b.h").write_text("typedef unsigned second_t;\n")
    return (SubjectMaterial("a", "a.h", 1, "first_t", "typedef unsigned first_t;", False),
            SubjectMaterial("b", "b.h", 1, "second_t", "typedef unsigned second_t;", False))


def test_later_input_read_cannot_invalidate_an_earlier_input(tmp_path, monkeypatch):
    owner = study_inputs.StudyInputBindings(tmp_path)
    packet = owner.bind(SubjectPacket((), _files(tmp_path)))
    assert len(packet.materials) == 2
    original = study_inputs.capture_source_identity
    changed = False

    def read_then_change_first(root, file, **kwargs):
        nonlocal changed
        identity = original(root, file, **kwargs)
        if file == "b.h" and not changed:
            changed = True
            (tmp_path / "a.h").write_text("typedef unsigned long first_t;\n")
        return identity

    with monkeypatch.context() as patch:
        patch.setattr(study_inputs, "capture_source_identity", read_then_change_first)
        admitted, reason = owner.admit_inputs(packet.materials)
    assert changed
    assert not admitted and reason == "study_material_changed"


def test_later_explanation_cannot_invalidate_an_earlier_explanation(tmp_path, monkeypatch):
    materials = _files(tmp_path)
    (tmp_path / "unit.c").write_text("int f(void) { return 1; }\n")
    runtime = AuditKnowledgeRuntime(tmp_path, StudyQueue(), deadline=float("inf"), window=0)
    ctx = {"file": "unit.c", "function": "f", "line_start": 1,
           "source": "int f(void) { return 1; }", "language": "c"}
    runtime._register(runtime._origin(ctx), ctx, {"reading_list": [
        {"subject": "first_t", "context": "target type role"},
        {"subject": "second_t", "context": "target type role"},
    ]})
    requests = runtime.requests()
    assert len(requests) == 2
    answers = []
    for request, material in zip(requests, materials):
        bound = runtime.bindings.bind(SubjectPacket((), (material,))).materials
        assert len(bound) == 1
        answers.append(SubjectExplanation(request.request_id, "answered", "Target declaration", "",
                                          bound, inputs=bound))
    runtime.record_source_answers(tuple(answers))
    reservation, = runtime.ready_continuations(admission=lambda: True)
    assert len(reservation.packet.explanations) == 2 and runtime.can_publish(reservation)
    original = runtime.bindings.admit
    changed = False

    def admit_then_change_first(answer):
        nonlocal changed
        verdict = original(answer)
        if answer.request_id == answers[1].request_id and not changed:
            changed = True
            (tmp_path / "a.h").write_text("typedef unsigned long first_t;\n")
        return verdict

    monkeypatch.setattr(runtime.bindings, "admit", admit_then_change_first)
    assert not runtime.can_publish(reservation)
    assert changed
    assert any(event.get("reason") == "study_material_changed" for event in runtime.events())
    assert runtime.fail(reservation, "input_set_changed")
