"""Live physical admission and portable reuse have separate input identities."""

from dataclasses import replace

from core.audit.knowledge_requests import KnowledgeOrigin
from core.audit.refutation_source import capture_source_identity
from core.audit.review_context_inputs import (
    context_inputs_digest, context_inputs_from_sources, context_inputs_record_digest,
)
from core.audit.review_input_scope import CapturedReviewInput, ReviewInputScope, MAX_LIVE_INPUTS


def _scope(tmp_path, *, complete=True):
    target, study = tmp_path / "target", tmp_path / "study"
    target.mkdir(); study.mkdir()
    (target / "unit.c").write_text("int f(void) { return 1; }\n")
    (study / "defs.h").write_text("typedef unsigned foo_t;\n")
    primary = capture_source_identity(target, "unit.c")
    definition = capture_source_identity(study, "defs.h")
    origin = KnowledgeOrigin("pass", "unit.c", "f", 1, 1, primary)
    sources = (CapturedReviewInput("target", target, "unit.c", primary),
               CapturedReviewInput("study", study, "defs.h", definition))
    manifest = context_inputs_from_sources(((source.root_label, source.file, source.source_identity.sha256)
                                            for source in sources), complete=complete)
    scope = ReviewInputScope(origin, context_inputs_record_digest(manifest), sources)
    return scope, manifest, target, study


def test_live_scope_checks_original_registered_roots_and_exact_record(tmp_path):
    scope, manifest, target, study = _scope(tmp_path)
    assert scope.current(target)
    assert scope.roots() == {"target": target, "study": study}
    assert scope.matches(file="unit.c", function="f", line_start=1, source_inputs=manifest)
    assert not scope.matches(file="unit.c", function="other", line_start=1, source_inputs=manifest)
    assert not scope.matches(file="unit.c", function="f", line_start=2, source_inputs=manifest)
    assert not scope.matches(file="unit.c", function="f", line_start=1,
                             source_inputs={**manifest, "complete": False})
    (study / "defs.h").write_text("typedef signed foo_t;\n")
    assert not scope.current(target)


def test_nonreusable_record_can_still_have_a_current_live_input_scope(tmp_path):
    scope, manifest, target, _ = _scope(tmp_path, complete=False)
    assert context_inputs_digest(manifest) is None
    assert context_inputs_record_digest(manifest)
    assert scope.matches(file="unit.c", function="f", line_start=1, source_inputs=manifest)
    assert scope.current(target), "portable loss is not a stale live source stamp"


def test_identical_bytes_after_mutation_do_not_refresh_live_stamps(tmp_path):
    scope, _, target, study = _scope(tmp_path)
    path = study / "defs.h"
    original = path.read_text()
    path.write_text("typedef unsigned long foo_t;\n")
    path.write_text(original)
    current = capture_source_identity(study, "defs.h")
    assert current.sha256 == scope.inputs[1].source_identity.sha256
    assert current != scope.inputs[1].source_identity
    assert not scope.current(target)


def test_scope_refuses_target_override_conflicts_and_input_caps(tmp_path):
    scope, _, target, study = _scope(tmp_path)
    assert not scope.current(study)
    assert not replace(scope, inputs=scope.inputs * (MAX_LIVE_INPUTS + 1)).current(target)
    conflicting = replace(scope.inputs[1], root_label="target")
    assert not replace(scope, inputs=(*scope.inputs, conflicting)).current(target)
    invalid = replace(scope.inputs[1], file="../defs.h")
    assert not replace(scope, inputs=(scope.inputs[0], invalid)).current(target)


def test_panel_scope_caps_distinct_original_bindings_not_repeated_deliveries(tmp_path, monkeypatch):
    from threading import Lock
    from types import SimpleNamespace
    from core.audit.knowledge_runtime import AuditKnowledgeRuntime

    original, manifest, target, _ = _scope(tmp_path)
    runtime = AuditKnowledgeRuntime.__new__(AuditKnowledgeRuntime)
    runtime._lock = Lock()
    runtime._live_input_errors = set()
    runtime._live_input_sets = {"pass": [original.inputs * 256, original.inputs * 256]}
    monkeypatch.setattr(runtime, "_owned_reservation", lambda reservation: True)
    reservation = SimpleNamespace(packet=SimpleNamespace(pass_id="pass"), origin=original.origin)
    candidate = SimpleNamespace(review_result={"review_claims": {
        "version": 1, "role": "review-history-only", "review": None,
        "intakes": [], "complete": False, "omissions": [], "source_inputs": manifest}})
    combined = runtime.publication_input_scope(reservation, candidate)
    assert combined is not None and combined.inputs == original.inputs
    assert combined.current(target)
    # A different original version must remain distinct and reject admission.
    changed = replace(original.inputs[1], source_identity=replace(original.inputs[1].source_identity, version=(0,)))
    runtime._live_input_sets["pass"].append((changed,))
    conflicting = runtime.publication_input_scope(reservation, candidate)
    assert conflicting is not None and not conflicting.current(target)
