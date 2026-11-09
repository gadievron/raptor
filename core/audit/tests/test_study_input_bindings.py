"""Study explanations retain the inputs of their own dispatched batch."""

from dataclasses import replace

from core.audit.study_inputs import StudyInputBindings
from core.concepts.model import StudyItem
from core.concepts.study import run_phase2
from core.concepts.subject_study import StudySubject, StudySubjects


DECLARATION = "typedef struct { unsigned length; } foo_t;"


def _job(root):
    bindings = StudyInputBindings(root)
    subjects = StudySubjects((StudySubject("r", "foo_t", "role", "identifier", "owned.c"),),
                             bind_packet=bindings.bind)
    item = StudyItem("type", "struct", "foo_t", "types.h", line=1, definition=DECLARATION)
    return bindings, subjects, item


def _response():
    return {"subject_answers": [{"request_id": "r", "status": "partial", "explanation": "A length carrier.",
                                "reason": "Uses not shown", "material_ids": ["material-0"]}]}


def test_later_identical_snippet_cannot_refresh_prior_explanation(tmp_path):
    path = tmp_path / "types.h"
    path.write_text(DECLARATION + "\n/* first surrounding revision */\n")
    bindings, subjects, item = _job(tmp_path)
    first = subjects.prepare([item], [])
    subjects.record(first, _response())
    old = subjects.snapshot()[0]
    assert bindings.admit(old)[0]
    path.write_text(DECLARATION + "\n/* second surrounding revision */\n")
    second = subjects.prepare([item], [])
    subjects.record(second, _response())
    fresh = subjects.snapshot()[1]
    assert first.materials[0].binding_id != second.materials[0].binding_id
    assert bindings.admit(old) == (False, "study_material_changed")
    assert bindings.admit(fresh)[0]
    assert len(bindings.records()) == 2


def test_changed_input_during_existing_study_call_is_not_delivered_as_fresh(tmp_path):
    path = tmp_path / "types.h"
    path.write_text(DECLARATION + "\n")
    bindings, subjects, item = _job(tmp_path)
    calls = []

    class Client:
        def generate_structured(self, prompt, schema, **kwargs):
            calls.append(prompt)
            path.write_text(DECLARATION + "\n/* changed during study */\n")
            return {"concepts": [], "invariants": [], "contracts": [], "bug_patterns": [], **_response()}

    run_phase2([item], "owned", Client(), batch_target=1, subjects=subjects)
    assert len(calls) == 1
    answer = subjects.snapshot()[0]
    assert answer.explanation == "A length carrier."
    assert bindings.admit(answer) == (False, "study_material_changed")


def test_unknown_binding_and_substituted_material_do_not_gain_freshness(tmp_path):
    (tmp_path / "types.h").write_text(DECLARATION + "\n")
    bindings, subjects, item = _job(tmp_path)
    packet = subjects.prepare([item], [])
    subjects.record(packet, _response())
    answer = subjects.snapshot()[0]
    modified = replace(answer.materials[0], text="other source")
    assert bindings.admit(replace(answer, materials=(modified,))) == (False, "material_not_bound_at_dispatch")
    unknown = replace(answer.materials[0], binding_id="")
    assert bindings.admit(replace(answer, materials=(unknown,))) == (False, "material_not_bound_at_dispatch")


def test_stale_prep_definition_is_unbound_before_the_call(tmp_path):
    (tmp_path / "types.h").write_text("typedef struct { unsigned other; } foo_t;\n")
    bindings, subjects, item = _job(tmp_path)
    packet = subjects.prepare([item], [])
    assert not packet.materials
    assert len(packet.excluded_materials) == 1
    assert DECLARATION not in packet.prompt()

    class Client:
        def generate_structured(self, *args, **kwargs):
            raise AssertionError("stale-only material bought a model call")

    run_phase2([item], "owned", Client(), batch_target=1, subjects=subjects)
    answer = subjects.snapshot()[0]
    assert answer.producer == "pipeline"
    assert answer.reason == "no_bound_source_material"
    assert answer.excluded_inputs
    assert bindings.admit(answer) == (False, "no_source_material")


def test_bare_cr_does_not_move_scanner_line_numbers(tmp_path):
    (tmp_path / "types.h").write_bytes(("/* first\rstill first */\n" + DECLARATION + "\n").encode())
    bindings, subjects, item = _job(tmp_path)
    item.line = 2
    packet = subjects.prepare([item], [])
    subjects.record(packet, _response())
    assert bindings.admit(subjects.snapshot()[0])[0]


def test_material_snapshot_is_the_definition_the_prompt_actually_sent(tmp_path, monkeypatch):
    from core.concepts.subject_study import SubjectPacket

    path = tmp_path / "types.h"
    path.write_text(DECLARATION + "\n")
    bindings, subjects, item = _job(tmp_path)
    new_definition = "typedef struct { unsigned other; } foo_t;"
    build_prompt = SubjectPacket.prompt

    def race_after_render(*args, **kwargs):
        prompt = build_prompt(*args, **kwargs)
        # A producer still holds the original prep object. Changing it after
        # rendering must not rebind the explanation to newer source text.
        item.definition = new_definition
        path.write_text(new_definition + "\n")
        return prompt

    monkeypatch.setattr(SubjectPacket, "prompt", race_after_render)
    calls = []

    class Client:
        def generate_structured(self, prompt, schema, **kwargs):
            calls.append(prompt)
            return {"concepts": [], "invariants": [], "contracts": [], "bug_patterns": [], **_response()}

    run_phase2([item], "owned", Client(), batch_target=1, subjects=subjects)
    assert len(calls) == 1
    assert DECLARATION in calls[0]
    assert new_definition not in calls[0]
    answer = subjects.snapshot()[0]
    assert answer.materials[0].text == DECLARATION
    assert bindings.admit(answer) == (False, "study_material_changed")


def test_uncited_material_still_binds_the_explanation_to_its_dispatch_inputs(tmp_path):
    (tmp_path / "types.h").write_text(DECLARATION + "\n")
    context_path = tmp_path / "context.h"
    context_source = "struct related { unsigned flags; };"
    context_path.write_text(context_source + "\n")
    bindings, subjects, item = _job(tmp_path)
    context = StudyItem("related", "struct", "related", "context.h", line=1, definition=context_source)
    packet = subjects.prepare([item], [context])
    subjects.record(packet, _response())  # the model cites only material-0
    answer = subjects.snapshot()[0]
    assert len(answer.materials) == 1
    assert len(answer.inputs) == 2
    assert bindings.admit(answer)[0]
    context_path.write_text(context_source + "\n/* an uncited dependency changed */\n")
    assert bindings.admit(answer) == (False, "study_material_changed")


def test_root_owned_inputs_and_uncited_dependency_remain_bound(tmp_path):
    from core.concepts.subject_study import SubjectMaterial, SubjectPacket
    target, study = tmp_path / "target", tmp_path / "study"
    target.mkdir()
    study.mkdir()
    for root in (target, study):
        (root / "same.h").write_text(DECLARATION + "\n")
    bindings = StudyInputBindings(target)
    bindings.register_root("study", study)
    packet = bindings.bind(SubjectPacket((), (
        SubjectMaterial("target", "same.h", 1, "foo_t", DECLARATION, False),
        SubjectMaterial("study", "same.h", 1, "foo_t", DECLARATION, False, source_root="study"))))
    assert len(packet.materials) == 2
    assert bindings.admit_inputs(packet.materials)[0]
    (study / "same.h").write_text(DECLARATION + "\n/* dependency edit */\n")
    assert bindings.admit_inputs(packet.materials) == (False, "study_material_changed")
    assert bindings.admit_inputs(packet.materials[:1])[0]
    assert not bindings.admit_inputs((replace(packet.materials[1], source_root="target"),))[0]


def test_expected_resolver_identity_cannot_be_refreshed_by_binding(tmp_path):
    from core.audit.refutation_source import capture_source_identity
    from core.concepts.subject_study import SubjectMaterial, SubjectPacket
    path = tmp_path / "types.h"
    path.write_text(DECLARATION + "\n/* original scope */\n")
    expected = capture_source_identity(tmp_path, "types.h")
    path.write_text(DECLARATION + "\n/* different scope */\n")
    bindings = StudyInputBindings(tmp_path)
    packet = bindings.bind(SubjectPacket((), (SubjectMaterial("m", "types.h", 1, "foo_t", DECLARATION, False),)),
                           expected={"m": expected})
    assert not packet.materials
