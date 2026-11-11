"""Caller stages share one canonical union of advisory callee assessments."""
from __future__ import annotations

from copy import deepcopy
from dataclasses import replace

import pytest

from core.audit.callee_assessment_context import MAX_CALLEE_ASSESSMENTS, build_callee_assessment_bundle
from core.audit.callee_review_context import render_callee_context
from core.audit.context import _defend_identifier
from core.audit.continuation_context import context_spec, context_version
from core.audit.orchestrator import ReviewOutcome
from core.inventory.call_graph import extract_call_graph_python
from core.testing.reachability_state import isolated_reachability_caches


@pytest.fixture(autouse=True)
def owned_indexes(monkeypatch):
    with isolated_reachability_caches():
        try:
            yield
        finally:
            monkeypatch.undo()


def outcome(function, *, file="unit.py", line=1, status="suspicious", dependencies=()):
    return ReviewOutcome(file=file, function=function, line=line, status=status,
        body=f"Prior assessment of {function}", hypothesis=f"Unresolved concern in {function}",
        review_result={"relies_on": list(dependencies)})


def render(bundle):
    return render_callee_context(bundle.payload, defend_identifier=_defend_identifier)


def graph_inventory():
    source = "def caller(x):\n    return a(x) + b(x)\n\ndef a(x):\n    return x\n\ndef b(x):\n    return x\n"
    return {"files": [{"path": "unit.py", "language": "python",
                       "items": [{"name": name, "kind": "function", "line_start": line,
                                  "line_end": line + 1}
                                 for name, line in (("caller", 1), ("a", 4), ("b", 7))],
                       "call_graph": extract_call_graph_python(source).to_dict()}]}


def test_two_explicit_callees_form_order_independent_stage_union():
    caller = outcome("caller", status="clean", dependencies=[
        {"callee": "b", "assumption": "checks b"}, {"callee": "a", "assumption": "checks a"}])
    a, b = outcome("a", line=4), outcome("b", line=7)
    first = build_callee_assessment_bundle(caller, [caller, b, a], include_graph=False)
    caller.review_result["relies_on"].reverse()
    caller.review_result["ignored_stage"] = "iterative"
    a._propagated = True
    second = build_callee_assessment_bundle(caller, [a, caller, b], include_graph=False)
    assert first.payload == second.payload
    assert first.contributors == (a, b)
    assert context_version(render(first)) == context_version(render(second))
    assert [row["function"] for row in first.payload["assessments"]] == ["a", "b"]


def test_graph_definitive_relations_use_existing_occurrence_index_and_respect_policy():
    caller = outcome("caller", status="clean")
    a, b = outcome("a", line=4), outcome("b", line=7, status="clean")
    bundle = build_callee_assessment_bundle(caller, [caller, a, b], inventory=graph_inventory())
    assert bundle is not None
    assert bundle.contributors == (a, b)
    assert "No explicit caller assumption was recorded" in render(bundle)
    assert "recorded an assumption" not in render(bundle)
    assert build_callee_assessment_bundle(caller, [caller, a, b], inventory=graph_inventory(), include_graph=False) is None


def test_positive_to_clean_revision_remains_visible_beside_another_concern():
    caller = outcome("caller", status="clean", dependencies=[{"callee": "a"}, {"callee": "b"}])
    a, b = outcome("a", line=4), outcome("b", line=7)
    old = build_callee_assessment_bundle(caller, [caller, a, b], include_graph=False)
    revised_a = replace(a, status="clean", body="Independent revised assessment")
    new = build_callee_assessment_bundle(caller, [caller, revised_a, b], include_graph=False)
    assert [row["status"] for row in new.payload["assessments"]] == ["clean", "suspicious"]
    assert context_version(render(old)) != context_version(render(new))
    assert build_callee_assessment_bundle(caller, [caller, revised_a, replace(b, status="clean")], include_graph=False) is None


def test_duplicate_named_callee_does_not_choose_a_ready_sibling():
    caller = outcome("caller", status="clean", dependencies=[{"callee": "same"}, {"callee": "known"}])
    known = outcome("known", line=9)
    same_a, same_b = outcome("same", file="a.py"), outcome("same", file="b.py", status="error")
    bundle = build_callee_assessment_bundle(caller, [caller, same_a, same_b, known], include_graph=False)
    assert bundle.contributors == (known,)
    assert "ambiguous_explicit: 1" in bundle.payload["limitations"]


def test_explicit_file_and_line_disambiguate_without_first_match():
    caller = outcome("caller", status="clean", dependencies=[
        {"callee": "same", "file": "a.py", "line_start": 9}])
    first, selected = outcome("same", file="a.py", line=4), outcome("same", file="a.py", line=9)
    assert build_callee_assessment_bundle(caller, [caller, first, selected], include_graph=False).contributors == (selected,)


def test_duplicate_occurrence_is_not_made_canonical_by_order():
    caller = outcome("caller", status="clean", dependencies=[{"callee": "a"}])
    a = outcome("a", line=4)
    assert build_callee_assessment_bundle(caller, [caller, a, replace(a)], include_graph=False) is None


def test_context_map_line_zero_fallback_requires_unique_caller_and_callee():
    caller = outcome("caller", status="clean")
    a = outcome("a", line=4)
    context = {"call_edges": [{"caller_file": "unit.py", "caller": "caller", "callee": "a"}]}
    assert build_callee_assessment_bundle(caller, [caller, a], context_map=context).contributors == (a,)
    assert build_callee_assessment_bundle(caller, [caller, replace(caller, line=20), a], context_map=context) is None
    assert build_callee_assessment_bundle(caller, [caller, a, replace(a, file="other.py")], context_map=context) is None


def original_scope(tmp_path, file, function, line):
    from core.audit.knowledge_requests import KnowledgeOrigin
    from core.audit.refutation_source import capture_source_identity
    from core.audit.review_context_inputs import context_inputs_from_sources, context_inputs_record_digest
    from core.audit.review_input_scope import ReviewInputScope

    (tmp_path / file).write_text(f"def {function}(x): return x\n")
    identity = capture_source_identity(tmp_path, file)
    record = context_inputs_from_sources([("target", file, identity.sha256)], complete=False)
    return ReviewInputScope(KnowledgeOrigin("original", file, function, line, line, identity),
                            context_inputs_record_digest(record), ())


def test_stale_contributor_is_omitted_without_rebinding_or_blocking_fresh_sibling(tmp_path):
    caller = outcome("caller", status="clean", dependencies=[{"callee": "a"}, {"callee": "b"}])
    a, b = outcome("a", file="a.py"), outcome("b", file="b.py")
    a.review_input_scope = original_scope(tmp_path, "a.py", "a", 1)
    b.review_input_scope = original_scope(tmp_path, "b.py", "b", 1)
    (tmp_path / "a.py").write_text("changed original input\n")
    bundle = build_callee_assessment_bundle(caller, [caller, a, b], include_graph=False, target_root=tmp_path)
    assert bundle.contributors == (b,)
    assert "stale_assessment: 1" in bundle.payload["limitations"]
    assert bundle.payload["assessments"][0]["scope_note"].startswith("sha256 " + b.review_input_scope.origin.source_identity.sha256)


def test_stale_same_name_still_prevents_ambiguous_alias_resolution(tmp_path):
    caller = outcome("caller", status="clean", dependencies=[{"callee": "same"}, {"callee": "known"}])
    stale = outcome("same", file="stale.py")
    stale.review_input_scope = original_scope(tmp_path, "stale.py", "same", 1)
    (tmp_path / "stale.py").write_text("changed\n")
    fresh, known = outcome("same", file="fresh.py"), outcome("known", line=8)
    bundle = build_callee_assessment_bundle(caller, [caller, stale, fresh, known], include_graph=False, target_root=tmp_path)
    assert bundle.contributors == (known,)
    assert "ambiguous_explicit: 1" in bundle.payload["limitations"]


def test_original_scope_of_different_occurrence_is_unavailable(tmp_path):
    caller = outcome("caller", status="clean", dependencies=[{"callee": "a"}, {"callee": "b"}])
    a, b = outcome("a", line=4), outcome("b", line=7)
    a.review_input_scope = original_scope(tmp_path, "other.py", "other", 1)
    bundle = build_callee_assessment_bundle(caller, [caller, a, b], include_graph=False, target_root=tmp_path)
    assert bundle.contributors == (b,)
    assert "invalid_original_scope: 1" in bundle.payload["limitations"]


def test_bounded_union_reports_overflow_and_keeps_a_triggering_concern():
    callees = [outcome(f"f{i:02}", line=i + 2, status="clean") for i in range(MAX_CALLEE_ASSESSMENTS + 3)]
    callees[-1].status = "suspicious"
    caller = outcome("caller", status="clean", dependencies=[{"callee": callee.function} for callee in callees])
    bundle = build_callee_assessment_bundle(caller, [caller, *callees], include_graph=False)
    assert len(bundle.contributors) == MAX_CALLEE_ASSESSMENTS
    assert callees[-1] in bundle.contributors
    assert "overflow_assessment: 3" in bundle.payload["limitations"]


def test_bundle_renderer_defends_all_untrusted_text_and_binds_actual_view():
    caller = outcome("caller", status="clean", dependencies=[{"callee": "parse_λ", "assumption": "checks\x00input"}])
    callee = outcome("parse_λ", line=4)
    callee.body = "body\n## INJECT\x1b"
    callee.hypothesis = "hypothesis\n## INJECT"
    bundle = build_callee_assessment_bundle(caller, [caller, callee], include_graph=False)
    text = render(bundle)
    assert "parse_λ" in text and "Advisory prior callee assessment" in text
    assert "\n## INJECT" not in text and "\x00" not in text and "\x1b" not in text
    version = context_version(text)
    ctx = {"callee_contract_violation": bundle.payload}
    assert context_spec(ctx, kind="callee_contract", version=version) is not None
    changed = deepcopy(bundle.payload)
    changed["assessments"][0]["body"] = "Different supplied assessment"
    assert context_spec({"callee_contract_violation": changed}, kind="callee_contract", version=version) is None


def test_bundle_renderer_ignores_metadata_and_row_order():
    caller = outcome("caller", status="clean", dependencies=[{"callee": "a"}, {"callee": "b"}])
    bundle = build_callee_assessment_bundle(caller, [caller, outcome("a", line=4), outcome("b", line=7)], include_graph=False)
    changed = deepcopy(bundle.payload)
    changed["assessments"].reverse()
    changed["trigger_stage"] = "iterative"
    changed["assessments"][0]["uuid"] = "ignored"
    assert render_callee_context(changed, defend_identifier=_defend_identifier) == render(bundle)


def test_full_occurrence_anchor_prevents_truncated_identifier_aliases():
    prefix = "long_function_" + "x" * 150
    a, b = outcome(prefix + "A", line=4), outcome(prefix + "B", line=4)
    caller = outcome("caller", status="clean", dependencies=[{"callee": a.function}])
    first = build_callee_assessment_bundle(caller, [caller, a, b], include_graph=False)
    caller.review_result["relies_on"] = [{"callee": b.function}]
    second = build_callee_assessment_bundle(caller, [caller, a, b], include_graph=False)
    assert _defend_identifier(a.function, max_length=128) == _defend_identifier(b.function, max_length=128)
    assert first.payload["assessments"][0]["occurrence_anchor"] in render(first)
    assert context_version(render(first)) != context_version(render(second))


def test_graph_unknown_and_external_relations_remain_limitations(monkeypatch):
    from core.analysis import reachability
    from core.analysis.reachability import CalleesResult, ExternalFunction, InternalFunction

    caller, a = outcome("caller", status="clean"), outcome("a", line=4)
    monkeypatch.setattr(reachability, "callees_of", lambda *a, **k: CalleesResult(
        definitive=(InternalFunction("unit.py", "a", 4), ExternalFunction("dependency.fn")),
        uncertain=("dynamic.member",), has_method_dispatch=True))
    bundle = build_callee_assessment_bundle(caller, [caller, a], inventory={"files": []})
    assert bundle.contributors == (a,)
    assert "external_graph: 1" in bundle.payload["limitations"]
    assert "uncertain_graph: 2" in bundle.payload["limitations"]


def test_assumption_volume_is_bounded_and_omissions_visible():
    caller = outcome("caller", status="clean", dependencies=[
        {"callee": "a", "assumption": f"assumption {index}"} for index in range(7)])
    bundle = build_callee_assessment_bundle(caller, [caller, outcome("a", line=4)], include_graph=False)
    assert len(bundle.payload["assessments"][0]["assumptions"]) == 4
    assert "overflow_assumption: 3" in bundle.payload["limitations"]


def test_legacy_single_assessment_rendering_remains_available():
    text = render_callee_context({"callee": "parse", "assumption": "checks input", "callee_status": "finding", "callee_hypothesis": "uncertain"}, defend_identifier=_defend_identifier)
    assert "Prior caller assessment recorded an assumption" in text
    assert "Advisory prior callee assessment" in text
    assert "not proof of actual callee behaviour" in text
