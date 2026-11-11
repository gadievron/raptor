"""Ready payload preparation is bounded to owners and retains original stamps."""

import json

import pytest

from core.audit import orchestrator as orch
from core.audit.knowledge_runtime import AuditKnowledgeRuntime
from core.audit.llm_review import make_review_fn
from core.llm.providers import StructuredResponse
from core.audit.ready_review_context import collect_ready_review_frames


@pytest.fixture
def owned(tmp_path):
    caller_source = "int caller(int value) {\n    return value + 1;\n}\n"
    callee_source = "int callee(int value) {\n    return value;\n}\n"
    (tmp_path / "caller.c").write_text(caller_source)
    (tmp_path / "callee.c").write_text(callee_source)
    checklist = {"files": [{"path": f"{name}.c", "items": [
        {"name": name, "kind": "function", "line_start": 1, "line_end": 3}]}
        for name in ("caller", "callee")]}
    config = orch.OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path / "out",
        inventory=checklist, propagate_constraints=False)
    runtime = AuditKnowledgeRuntime(tmp_path, orch.StudyQueue(), deadline=float("inf"))
    caller = orch.ReviewOutcome(file="caller.c", function="caller", line=1,
        status="clean", body="Prior caller", review_result={
            "language_reference_requests": [{"topic": "integer arithmetic", "entry_id": "c.integer-definedness"}],
            "relies_on": [{"callee": "callee", "assumption": "validates values"}],
        })
    callee = orch.ReviewOutcome(file="callee.c", function="callee", line=1,
        status="suspicious", body="Original advisory", review_result={})
    class Client:
        response = None

        def generate_structured(self, prompt, schema, **kwargs):
            return StructuredResponse(result=dict(self.response), raw="", cost=0, model="scripted")

    client = Client()
    render = make_review_fn(client, escalate_clean=False)
    prepared = []
    for outcome, source in ((caller, caller_source), (callee, callee_source)):
        ctx = {"file": outcome.file, "function": outcome.function,
            "line_start": 1, "line_end": 3, "source": source, "language": "c"}
        client.response = {"status": outcome.status, "body": outcome.body, **outcome.review_result}
        returned = runtime.wrap_review(render)(ctx, config)
        returned.line = 1
        assert returned.review_input_scope is not None
        prepared.append(returned)
    caller, callee = prepared
    assert runtime.requests()
    result = orch.OrchestratorResult(outcomes=[caller, callee], clean=1, suspicious=1)
    assemblies = []

    def assemble(gap):
        assemblies.append(gap["name"])
        return {"file": gap["file"], "function": gap["name"],
            "line_start": 1, "line_end": 3, "source": caller_source, "language": "c"}

    cache = {}

    def collect(builder=assemble):
        return collect_ready_review_frames(runtime, result, config, checklist, {}, {},
            ready_joern_gaps=(), call_edges=(), classifications=None, disagreements=(),
            cache=cache, assemble=builder)

    yield tmp_path, caller, callee, result, assemblies, collect, checklist
    runtime.close("test_complete")


def test_ready_context_cache_reuses_only_unchanged_payload_and_copies_for_dispatch(owned):
    _, _, _, _, assemblies, collect, _ = owned
    first = collect()[("caller.c", "caller", 1)]
    mutated = first.context()
    mutated["source"] = "not the original source"
    mutated["callee_contract_violation"]["sentinel"] = "not shared"
    second = collect()[("caller.c", "caller", 1)]
    assert second is first and assemblies == ["caller"]
    assert second.context()["source"].startswith("int caller")
    assert "sentinel" not in second.context()["callee_contract_violation"]


def test_in_place_advisory_change_invalidates_preparation_cache(owned):
    _, _, callee, _, assemblies, collect, _ = owned
    first = collect()[("caller.c", "caller", 1)]
    callee.body = "Changed advisory"
    second = collect()[("caller.c", "caller", 1)]
    assert second is not first and assemblies == ["caller", "caller"]
    assert "Original advisory" in json.dumps(first.context()["callee_contract_violation"])
    assert "Changed advisory" in json.dumps(second.context()["callee_contract_violation"])


def test_original_contributor_drift_does_not_rebind_old_assessment(owned):
    root, _, _, result, _, collect, _ = owned
    first = collect()[("caller.c", "caller", 1)]
    assert first.current(tuple(result.outcomes), root)
    path = root / "callee.c"
    before = path.read_text()
    path.write_text(before + "# changed\n")
    path.write_text(before)
    assert not first.current(tuple(result.outcomes), root)
    next_frame = collect()[("caller.c", "caller", 1)]
    assert "callee_contract_violation" not in next_frame.context()


def test_ambiguous_canonical_caller_does_not_prepare_a_frame(owned):
    _, caller, _, result, assemblies, collect, _ = owned
    result.outcomes.append(caller)
    assert collect() == {} and not assemblies


def test_unavailable_preparation_does_not_abort_unrelated_reviews(owned):
    _, _, _, _, _, collect, _ = owned

    def unavailable(gap):
        raise OSError("scripted unavailable context")

    assert collect(unavailable) == {}


def test_binary_geometry_never_enters_source_context_preparation(owned):
    _, _, _, _, assemblies, collect, checklist = owned
    checklist["target_kind"] = "binary"
    assert collect() == {} and not assemblies
