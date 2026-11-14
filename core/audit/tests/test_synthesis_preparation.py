"""Synthesis preparation retains the exact original live source scope."""

from core.audit import orchestrator as orch, synthesis_preparation as preparation_mod
from core.audit import synthesis_review_context as synthesis
from core.audit.review_claims import begin_review
from core.audit.tests.test_review_input_scope import _scope


def test_preparation_retains_original_scope_and_dependency_epoch(tmp_path):
    preparation = vars(preparation_mod)
    prepare = preparation["prepare_synthesis_frame"]
    scope, manifest, target, study = _scope(tmp_path)
    history = begin_review(scope.origin, "owned-attempt")
    history["source_inputs"] = manifest
    prior = orch.ReviewOutcome(file="unit.c", function="f", line=1, status="clean",
        body="Earlier owned review", review_result={"review_claims": history}, review_input_scope=scope)
    gap = {"file": "unit.c", "name": "f", "line_start": 1, "line_end": 1,
           "synthesis_hit_line": 1, "synthesis_rule_id": "owned-rule"}
    context = {"file": "unit.c", "function": "f", "line_start": 1, "line_end": 1,
               "source": (target / "unit.c").read_text()}
    ready = prepare(gap=gap, context=context, prior=prior, target_root=target)
    assert isinstance(ready, preparation["PreparedSynthesisFrame"])
    assert ready.frame.scopes == (scope,) and ready.frame.scopes[0] is scope
    assert ready.frame.current([prior], target)
    assert "synthesis_review_context" not in context
    copied = ready.frame.context()["synthesis_review_context"]
    assert copied.version == ready.payload.version
    assert synthesis.render_synthesis_review_context(copied) == synthesis.render_synthesis_review_context(ready.payload)
    refused = prepare(gap=gap, context={**context, "source": "int f(void) { return 9; }\n"},
                      prior=prior, target_root=target)
    assert refused.reason == "synthesis_source_context_changed"
    path = study / "defs.h"
    before = path.read_text()
    path.write_text("typedef signed foo_t;\n")
    path.write_text(before)
    assert not ready.frame.current([prior], target)
    refused = prepare(gap=gap, context=context, prior=prior, target_root=target)
    assert refused.reason == "synthesis_original_source_scope_unavailable"


def test_matching_prefix_cannot_claim_the_original_full_source_span(tmp_path):
    from core.audit.knowledge_requests import KnowledgeOrigin
    from core.audit.refutation_source import capture_source_identity
    from core.audit.review_context_inputs import context_inputs_from_sources, context_inputs_record_digest
    from core.audit.review_input_scope import CapturedReviewInput, ReviewInputScope

    preparation = vars(preparation_mod)
    target = tmp_path / "target"
    target.mkdir()
    source = "int g(void) {\n    return 1;\n}\n"
    (target / "unit.c").write_text(source)
    identity = capture_source_identity(target, "unit.c")
    origin = KnowledgeOrigin("original-pass", "unit.c", "g", 1, 3, identity)
    manifest = context_inputs_from_sources([("target", "unit.c", identity.sha256)])
    scope = ReviewInputScope(origin, context_inputs_record_digest(manifest),
        (CapturedReviewInput("target", target, "unit.c", identity),))
    history = begin_review(origin, "original-attempt")
    history["source_inputs"] = manifest
    prior = orch.ReviewOutcome(file="unit.c", function="g", line=1, status="clean",
        body="Original full function", review_result={"review_claims": history}, review_input_scope=scope)
    gap = {"file": "unit.c", "name": "g", "line_start": 1, "line_end": 3,
           "synthesis_hit_line": 2, "synthesis_rule_id": "owned-rule"}
    context = {"file": "unit.c", "function": "g", "line_start": 1, "line_end": 3, "source": source}
    prepare = preparation["prepare_synthesis_frame"]
    assert isinstance(prepare(gap=gap, context=context, prior=prior, target_root=target),
                      preparation["PreparedSynthesisFrame"])
    refused = prepare(gap=gap, context={**context, "source": "int g(void) {\n"},
                      prior=prior, target_root=target)
    assert refused.reason == "synthesis_source_span_unavailable"
