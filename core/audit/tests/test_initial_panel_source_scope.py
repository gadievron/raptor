"""Initial source panels retain original live input bindings through publication."""
from functools import wraps
import json

import pytest

from core.audit import collector as collector_mod, orchestrator as orch
from core.audit.knowledge_runtime import AuditKnowledgeRuntime
from core.audit.llm_review import make_review_fn
from core.audit.review_input_scope import ReviewInputScope
from core.audit.refutation_source import capture_source_identity
from core.audit.shared_state import SharedState
from core.audit.tests.test_study_claim_retention import _owned_review_caches as _owned_review_caches
from core.llm.providers import StructuredResponse
from core.testing.audit_shutdown import isolated_audit_shutdown
from core.testing.module_views import module_function_view


@pytest.mark.parametrize("mode", ["self", "cross"])
@pytest.mark.parametrize("change", ["none", "rewrite_restore"])
def test_fresh_initial_source_panel_keeps_original_scopes_through_actual_publication(tmp_path, monkeypatch, mode, change):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    target, out = tmp_path / "target", tmp_path / "out"
    target.mkdir()
    out.mkdir()
    source = "unsigned short f(unsigned value) { return value; }\n"
    (target / "unit.c").write_text(source)
    original_identity = capture_source_identity(target, "unit.c")
    gap = {"file": "unit.c", "name": "f", "kind": "function", "line_start": 1,
           "line_end": 1, "pinned": True, "force_review": True}
    checklist = {"files": [{"path": "unit.c", "items": [dict(gap)]}]}
    (out / "checklist.json").write_text(json.dumps(checklist))
    calls, samples, acknowledgements, proposed = [], [], [], []

    class Client:
        _attempt_admission_protocol = 1
        _call_cost_history = None

        def is_budget_exhausted(self):
            return False

        def generate_structured(self, prompt, schema, **kwargs):
            assert kwargs.pop("accounting_attempt_admission")() is True
            calls.append(prompt)
            return StructuredResponse(result={"status": "clean", "body": "Owned fresh proposal",
                "reading_list": [], "language_reference_requests": []}, raw="", cost=.125, model="scripted")

    class ObservedRuntime(AuditKnowledgeRuntime):
        def wrap_review(self, fn):
            wrapped = super().wrap_review(fn)
            if getattr(wrapped, "_owned_panel_observer", None) is self:
                return wrapped

            @wraps(wrapped)
            def observed(*args, **kwargs):
                outcome = wrapped(*args, **kwargs)
                if not any(outcome is prior for prior in samples):
                    samples.append(outcome)
                    if len(samples) == 1 and change == "rewrite_restore":
                        (target / "unit.c").write_text(source + "/* owned between-sample change */\n")
                        (target / "unit.c").write_text(source)
                return outcome

            observed._owned_panel_observer = self
            return observed

    class ObservedCollector(collector_mod.Collector):
        def _append_journal_entry(self, outcome, actual_gap):
            acknowledgement = super()._append_journal_entry(outcome, actual_gap)
            acknowledgements.append(acknowledgement)
            proposed.append(outcome)
            return acknowledgement

    client = Client()
    config = orch.OrchestratorConfig(target_path=target, out_dir=out, prefilter=False,
        validate=False, max_refinements=0, immediate_verify=False,
        review_passes=2 if mode == "self" else 1, multi_model=mode == "cross",
        models=["scripted"] if mode == "self" else ["scripted-a", "scripted-b"],
        sweep_validate_findings=False, sage_recall=False, propagate_constraints=False,
        deepen_suspicious=False, open_discovery=False, iris=False,
        joern_overrides={"enabled": False}, no_binary_oracle=True,
        enable_session_context=False, llm_budget_client=client)
    private = module_function_view(orch, bindings={
        "_correlated_mech_detector_tool": lambda *a, **k: None,
        "_gather_library_candidates": lambda *a, **k: [],
        "_get_llm_client": lambda *a, **k: None,
        "_proactive_validate": lambda outcome, *a, **k: outcome,
    })
    result, reviewed = orch.OrchestratorResult(), {}
    collector = ObservedCollector(out_dir=out, target_path=target, run_id=out.name)
    runtime = ObservedRuntime(target, orch.StudyQueue(), deadline=float("inf"), window=0)
    try:
        with isolated_audit_shutdown(private):
            final = runtime.wrap_unit(private.review_one_function)(gap, SharedState(checklist=checklist),
                config, make_review_fn(client, escalate_clean=False), result,
                reviewed_outcomes=reviewed, collector=collector, knowledge_runtime=runtime)
        assert len(calls) == len(samples) == 2
        assert all("c.integer-promotion v1:" in prompt for prompt in calls)
        assert all(sample.review_result["language_reference_delivery"]
                   and all(row["delivered"] is True for row in sample.review_result["language_reference_delivery"])
                   and "source_inputs" in sample.review_result["review_claims"] for sample in samples)
        assert all(isinstance(sample.review_input_scope, ReviewInputScope) for sample in samples)
        assert samples[0].review_input_scope.origin.source_identity == original_identity
        assert len(acknowledgements) == len(proposed) == 1 and acknowledgements[0] is not None
        if change == "none":
            assert all(sample.review_input_scope.origin.source_identity == original_identity
                       and sample.review_input_scope.current(target) for sample in samples)
            assert final.status == "clean"
            assert final is proposed[0] and reviewed["unit.c:f"] is final and result.outcomes == [final]
            assert isinstance(final.review_input_scope, ReviewInputScope) and final.review_input_scope.current(target)
            assert not result.publication_failures
        else:
            assert not samples[0].review_input_scope.current(target)
            # The full caller keeps the original context binding for both
            # samples; it must not refresh either one after identical bytes return.
            assert not samples[1].review_input_scope.current(target)
            assert samples[1].review_input_scope.origin.source_identity == original_identity
            assert final.status == "error" and final.error_class == "publication"
            assert result.outcomes == [final] and not reviewed
            assert result.clean == 0 and result.errors == 1 and len(result.publication_failures) == 1
    finally:
        runtime.close("test_complete")



def _scope_members(tmp_path, *, full_primary=False):
    """Pure binding fixtures with actual owned-file stamps, not model reviews."""
    from copy import deepcopy
    from dataclasses import replace
    from core.audit.review_claims import begin_review
    from core.audit.review_context_inputs import context_inputs_from_sources, context_inputs_record_digest, merge_context_inputs
    from core.audit.tests.test_review_input_scope import _scope

    full, full_manifest, target, study = _scope(tmp_path)
    first_manifest = full_manifest if full_primary else context_inputs_from_sources([
        ("target", "unit.c", full.origin.source_identity.sha256)])
    first = full if full_primary else replace(full, inputs=(full.inputs[0],),
        record_digest=context_inputs_record_digest(first_manifest))
    second = replace(full, origin=replace(full.origin, pass_id="second-pass"))
    histories = [begin_review(first.origin, "first-attempt"), begin_review(second.origin, "second-attempt")]
    histories[0]["source_inputs"], histories[1]["source_inputs"] = first_manifest, full_manifest
    members = [{"status": "clean", "review_claims": h} for h in histories]
    aggregate = deepcopy(histories[0])
    aggregate["source_inputs"] = merge_context_inputs(first_manifest, full_manifest)
    outcome = orch.ReviewOutcome("unit.c", "f", "clean", "Owned binding metadata", line=1,
        review_result={"review_claims": aggregate})
    owned = {(first.origin.pass_id, "first-attempt"): first,
             (second.origin.pass_id, "second-attempt"): second}
    return outcome, members, owned, target, study


def test_nonselected_member_dependency_remains_in_original_live_scope(tmp_path):
    from core.audit.source_panel_scope import combine_source_panel_scope

    outcome, members, owned, target, study = _scope_members(tmp_path)
    combined = combine_source_panel_scope(outcome, members=members, owned=owned.get, target_root=target)
    assert combined is not None and combined.current(target)
    assert combined.roots() == {"target": target, "study": study}
    assert len(combined.inputs) == 2
    path = study / "defs.h"
    original = path.read_text()
    path.write_text("typedef signed foo_t;\n")
    path.write_text(original)
    assert owned[("pass", "first-attempt")].current(target)
    assert not owned[("second-pass", "second-attempt")].current(target)
    assert combine_source_panel_scope(outcome, members=members, owned=owned.get, target_root=target) is None


@pytest.mark.parametrize("change", ["unowned", "member_origin", "member_pass_list", "member_digest",
                                   "aggregate_omission", "aggregate_origin", "aggregate_pass_list",
                                   "missing_member", "error_member", "foreign_owner", "false_line"])
def test_source_panel_binding_refuses_unowned_or_changed_members(tmp_path, change):
    from core.audit.source_panel_scope import combine_source_panel_scope

    outcome, members, owned, target, _ = _scope_members(tmp_path)
    if change == "unowned":
        members[1]["review_claims"]["review"]["attempt_id"] = "unowned"
    elif change == "member_origin":
        members[1]["review_claims"]["review"]["origin"]["line_start"] = 1.0
    elif change == "member_pass_list":
        members[1]["review_claims"]["review"]["origin"]["pass_id"] = []
    elif change == "member_digest":
        members[1]["review_claims"]["source_inputs"]["complete"] = False
    elif change == "aggregate_omission":
        outcome.review_result["review_claims"]["source_inputs"] = members[0]["review_claims"]["source_inputs"]
    elif change == "aggregate_origin":
        outcome.review_result["review_claims"]["review"]["origin"]["file"] = "foreign.c"
    elif change == "aggregate_pass_list":
        outcome.review_result["review_claims"]["review"]["origin"]["pass_id"] = []
    elif change == "missing_member":
        members.append({"status": "error"})
    elif change == "error_member":
        members[1]["status"] = "error"
    elif change == "foreign_owner":
        owned = {}
    else:
        outcome.line = False
    assert combine_source_panel_scope(outcome, members=members, owned=owned.get, target_root=target) is None


def test_rejected_explicit_members_clear_a_preattached_scope(tmp_path):
    outcome, members, owned, target, _ = _scope_members(tmp_path)
    original = owned[("pass", "first-attempt")]
    outcome.review_input_scope = original
    outcome.line = 0
    outcome.review_result["review_claims"]["review"] = None
    runtime = AuditKnowledgeRuntime(target, orch.StudyQueue(), deadline=float("inf"), window=0)
    try:
        runtime.bind_review_input_scope(outcome, members=members)
        assert outcome.review_input_scope is None
    finally:
        runtime.close("test_complete")


def test_conflicting_original_dependency_versions_are_not_collapsed(tmp_path):
    from dataclasses import replace
    from core.audit.refutation_source import capture_source_identity
    from core.audit.source_panel_scope import combine_source_panel_scope

    outcome, members, owned, target, study = _scope_members(tmp_path, full_primary=True)
    original = owned[("pass", "first-attempt")]
    path = study / "defs.h"
    text = path.read_text()
    path.write_text("typedef signed foo_t;\n")
    path.write_text(text)
    current = capture_source_identity(study, "defs.h")
    assert current.sha256 == original.inputs[1].source_identity.sha256
    assert current != original.inputs[1].source_identity
    owned[("second-pass", "second-attempt")] = replace(owned[("second-pass", "second-attempt")],
        inputs=(original.inputs[0], replace(original.inputs[1], source_identity=current)))
    assert owned[("second-pass", "second-attempt")].current(target)
    assert not original.current(target)
    assert combine_source_panel_scope(outcome, members=members, owned=owned.get, target_root=target) is None


def test_conflicting_original_roots_cannot_borrow_primary_root(tmp_path):
    from dataclasses import replace
    from core.audit.refutation_source import capture_source_identity
    from core.audit.source_panel_scope import combine_source_panel_scope

    outcome, members, owned, target, study = _scope_members(tmp_path, full_primary=True)
    other = tmp_path / "other-study"
    other.mkdir()
    (other / "defs.h").write_bytes((study / "defs.h").read_bytes())
    original = owned[("second-pass", "second-attempt")]
    dependency = replace(original.inputs[1], root=other,
        source_identity=capture_source_identity(other, "defs.h"))
    owned[("second-pass", "second-attempt")] = replace(original, inputs=(original.inputs[0], dependency))
    assert all(scope.current(target) for scope in owned.values())
    assert combine_source_panel_scope(outcome, members=members, owned=owned.get, target_root=target) is None


def test_combined_scope_retains_existing_live_input_bound(tmp_path):
    from dataclasses import replace
    from core.audit.review_claims import begin_review
    from core.audit.review_context_inputs import context_inputs_from_sources, context_inputs_record_digest, merge_context_inputs
    from core.audit.review_input_scope import CapturedReviewInput, MAX_LIVE_INPUTS
    from core.audit.source_panel_scope import combine_source_panel_scope

    outcome, _, owned, target, _ = _scope_members(tmp_path)
    first = owned[("pass", "first-attempt")]
    primary = first.inputs[0]
    inputs = []
    for index in range(MAX_LIVE_INPUTS):
        file = f"extra{index}.h"
        (target / file).write_text("/* owned metadata source */\n")
        inputs.append(CapturedReviewInput("target", target, file, capture_source_identity(target, file)))
    scopes, members = [], []
    for index, group in enumerate((inputs[:MAX_LIVE_INPUTS // 2], inputs[MAX_LIVE_INPUTS // 2:])):
        live = (primary, *group)
        manifest = context_inputs_from_sources([(s.root_label, s.file, s.source_identity.sha256) for s in live])
        scope = replace(first, origin=replace(first.origin, pass_id=f"cap-pass{index}"),
                        inputs=live, record_digest=context_inputs_record_digest(manifest))
        assert scope.current(target)
        scopes.append(scope)
        history = begin_review(scope.origin, f"cap-attempt{index}")
        history["source_inputs"] = manifest
        members.append({"status": "clean", "review_claims": history})
    outcome.review_result["review_claims"] = {**members[0]["review_claims"], "source_inputs": merge_context_inputs(
        *(member["review_claims"]["source_inputs"] for member in members))}
    registry = {(scope.origin.pass_id, f"cap-attempt{index}"): scope for index, scope in enumerate(scopes)}
    assert combine_source_panel_scope(outcome, members=members, owned=registry.get, target_root=target) is None
