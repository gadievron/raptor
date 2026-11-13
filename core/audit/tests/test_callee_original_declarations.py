"""Original unreviewed declarations cannot heal a bare callee relation."""
import pytest

from core.audit import orchestrator as orch
from core.audit.knowledge_runtime import AuditKnowledgeRuntime
from core.orchestration.context_map_callgraph import enrich_with_call_edges
from core.testing.module_views import module_function_view


def test_active_callee_stage_keeps_unreviewed_duplicate_ambiguous(tmp_path):
    (tmp_path / "unit.c").write_text("#ifdef FIRST\nunsigned f(unsigned n) { return n; }\n#else\nunsigned f(unsigned n) { return n + 1; }\n#endif\nunsigned g(unsigned n) { return f(n); }\n")
    checklist = {"files": [{"path": "unit.c", "items": [
        {"name": "f", "line_start": 2, "line_end": 2},
        {"name": "f", "line_start": 4, "line_end": 4},
        {"name": "g", "line_start": 6, "line_end": 6}],
        "call_graph": {"calls": [{"caller": "g", "chain": ["f"]}]}}]}
    context_map = {}
    assert enrich_with_call_edges(context_map, checklist=checklist) == 1
    caller = orch.ReviewOutcome("unit.c", "g", "clean", "Owned caller assessment", line=6)
    callee = orch.ReviewOutcome("unit.c", "f", "suspicious", "Owned f4 concern", line=4)
    result = orch.OrchestratorResult(outcomes=[caller, callee], clean=1, suspicious=1)
    config = orch.OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path / "out",
                                     propagate_constraints=True, inventory=None)
    prepared_batches = []

    def retain_prepared(result, config, review_fn, prepared, runtime, **kwargs):
        prepared_batches.append(prepared)
        return len(prepared)

    private = module_function_view(orch, bindings={
        "_build_context": lambda config, gap, *args, **kwargs: {"file": gap["file"],
            "function": gap["name"], "line_start": gap["line_start"], "line_end": gap["line_end"]},
        "_make_dispatch_gate": lambda config: None,
        "_run_callee_continuations": retain_prepared,
    })
    runtime = AuditKnowledgeRuntime(tmp_path, orch.StudyQueue(), deadline=float("inf"), window=0)
    try:
        count = private._callee_contract_requeue(result, config, None,
            checklist=checklist, context_map=context_map, fuzz_coverage=None,
            evidence_index={}, knowledge_runtime=runtime)
        assert len(prepared_batches) == 1
        assert not runtime._calls and not runtime._active
        assert result.outcomes[0] is caller and result.outcomes[1] is callee
        assert not prepared_batches[0]
        assert count == 0
    finally:
        runtime.close("test_complete")


@pytest.mark.parametrize("mode", ["bare_callee", "bare_caller", "bare_explicit", "qualified_explicit",
                                 "full_alias", "healthy", "unreviewed_only", "invalid_original_line"])
def test_original_declarations_do_not_create_or_heal_advisory_relations(mode):
    from core.audit.callee_assessment_context import build_callee_assessment_bundle, snapshot_callee_declarations

    items = [{"name": "f", "line_start": 4}, {"name": "g", "line_start": 6}]
    if mode in {"bare_callee", "bare_explicit", "qualified_explicit", "full_alias", "unreviewed_only"}:
        items.insert(0, {"name": "f", "line_start": 2})
    elif mode == "bare_caller":
        items.append({"name": "g", "line_start": 8})
    elif mode == "invalid_original_line":
        items[0]["line_start"] = True
    declarations = snapshot_callee_declarations({"files": [{"path": "unit.c", "items": items}]})
    dependency = {"callee": "unit.c:f:4" if mode == "full_alias" else "f", "assumption": "validates values"}
    if mode == "qualified_explicit":
        dependency.update(file="unit.c", line_start=4)
    explicit = mode in {"bare_explicit", "qualified_explicit", "full_alias"}
    caller = orch.ReviewOutcome("unit.c", "g", "clean", "Owned caller", line=6,
                               review_result={"relies_on": [dependency]} if explicit else {})
    callee = orch.ReviewOutcome("unit.c", "f", "suspicious", "Owned f4 concern", line=4)
    outcomes = [caller] if mode == "unreviewed_only" else [caller, callee]
    context_map = {"call_edges": [{"caller_file": "unit.c", "caller": "g", "callee_file": "unit.c", "callee": "f"}]}
    bundle = build_callee_assessment_bundle(caller, outcomes, context_map=context_map,
        include_graph=not explicit, original_declarations=declarations)
    eligible = mode in {"qualified_explicit", "full_alias", "healthy"}
    assert (bundle is not None) is eligible
    if eligible:
        assert bundle.contributors == (callee,)
        assert bundle.payload["assessments"][0]["line_start"] == 4


@pytest.mark.parametrize("owner", ["active_stage", "ready_frames"])
def test_both_pipeline_bundle_owners_forward_original_declarations(owner):
    import ast
    import inspect

    from core.audit.ready_review_context import collect_ready_review_frames

    function = orch._requeue_ready_callee_assessments if owner == "active_stage" else collect_ready_review_frames
    body = ast.parse(inspect.getsource(function))
    calls = [node for node in ast.walk(body) if isinstance(node, ast.Call)
             and isinstance(node.func, ast.Name) and node.func.id == "build_callee_assessment_bundle"]
    assert len(calls) == 1
    keyword = next(item.value for item in calls[0].keywords if item.arg == "original_declarations")
    assert isinstance(keyword, ast.Name) and keyword.id == "original_declarations"
    captures = [node for node in ast.walk(body) if isinstance(node, ast.Assign)
                and any(isinstance(target, ast.Name) and target.id == "original_declarations" for target in node.targets)]
    assert len(captures) == 1
    assert isinstance(captures[0].value, ast.Call) and captures[0].value.func.id == "snapshot_callee_declarations"
    assert isinstance(captures[0].value.args[0], ast.Name) and captures[0].value.args[0].id == "checklist"


def test_declaration_index_owns_primitives_and_bundle_uses_name_lookups_only():
    from collections.abc import Mapping

    from core.audit.callee_assessment_context import (
        CalleeDeclarationIndex, build_callee_assessment_bundle, snapshot_callee_declarations,
    )

    items = [{"name": "g", "line_start": 6}, {"name": "f", "line_start": 4}]
    original = snapshot_callee_declarations({"files": [{"path": "unit.c", "items": items}]})
    items.append({"name": "f", "line_start": 2})
    assert original.aliases["f"] == frozenset({("unit.c", "f", 4)})
    with pytest.raises(TypeError):
        original.aliases["f"] = frozenset()

    class LookupOnly(Mapping):
        def __init__(self, values):
            self.values = values

        def __getitem__(self, key):
            return self.values[key]

        def __len__(self):
            return len(self.values)

        def __iter__(self):
            raise AssertionError("bundle walked all original declarations again")

    declarations = CalleeDeclarationIndex(LookupOnly(original.aliases), LookupOnly(original.occurrences))
    caller = orch.ReviewOutcome("unit.c", "g", "clean", "Owned caller", line=6,
                               review_result={"relies_on": [{"callee": "f", "assumption": "validates values"}]})
    callee = orch.ReviewOutcome("unit.c", "f", "suspicious", "Owned f4 concern", line=4)
    for _ in range(3):
        bundle = build_callee_assessment_bundle(caller, [caller, callee], include_graph=False,
                                               original_declarations=declarations)
        assert bundle.contributors == (callee,)
