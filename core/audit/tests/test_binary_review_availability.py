"""Actual reviewer dispatch requires an available binary implementation view.

Owned bytes and model-shaped JSON objects exercise context and dispatch only.
No binary backend, instruction decoding, provider, or target process executes;
these controls make no claim about durable publication or checker semantics.
"""
from __future__ import annotations

import pytest

import core.audit.binary_context as binary_context
from core.audit.knowledge_calls import KnowledgeCallRefused
from core.audit.llm_review import make_review_fn
from core.audit.orchestrator import OrchestratorConfig
from core.inventory.binary_builder import binary_path_key
from core.llm.providers import StructuredResponse
from packages.ghidra.model import REDatabase, REFunction


@pytest.fixture
def binary_view(tmp_path, monkeypatch):
    target = tmp_path / "owned.bin"
    target.write_bytes(b"owned context fixture, not an executable artefact")
    # Missing decompilation remains a measured unavailable view. Do not boot
    # a decompiler or infer an instruction view from the name/address alone.
    monkeypatch.setattr(binary_context, "_lazy_decompile", lambda *args, **kwargs: None)

    def assemble(representation):
        functions = []
        if representation != "unknown":
            functions.append(REFunction(name="f", address=4096, size=32, source_tool="ghidra",
                decompilation="unsigned f(unsigned n) { return n + 1; }" if representation == "decompilation" else None))
        database = REDatabase(source_tool="ghidra", binary_path=str(target), functions=functions)
        context = binary_context.assemble_binary_context(target_path=target,
            file_path=binary_path_key(target), function_name="f", db=database)
        assert context["representation"] == representation
        assert context["is_binary"] is True
        return context

    return assemble


def _reviewer():
    calls = []

    class Client:
        def generate_structured(self, prompt, schema, **kwargs):
            calls.append((prompt, schema, kwargs))
            return StructuredResponse(result={"status": "clean", "body": "Captured reviewer judgement."},
                                      raw="", cost=.1, model="captured")

    review = make_review_fn(Client(), system_prompt="Review the supplied implementation view.",
        schema={"type": "object", "properties": {"status": {"type": "string"},
            "body": {"type": "string"}}, "required": ["status", "body"]},
        escalate_clean=False)
    return review, calls


@pytest.mark.parametrize("representation", ["unknown", "stub"])
def test_missing_binary_view_never_reaches_actual_structured_client(tmp_path, binary_view, representation):
    context = binary_view(representation)
    # Both actual assembler fallbacks carry nonempty placeholder strings;
    # merely checking for a truthy source value would admit them.
    assert isinstance(context["source"], str) and context["source"].strip()
    review, calls = _reviewer()
    config = OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path / "out")
    refusal = None
    try:
        review(context, config)
    except KnowledgeCallRefused as exc:
        refusal = exc
    assert calls == [], "binary placeholder reached the actual structured client"
    assert refusal is not None and refusal.reason == "binary_implementation_unavailable"


def test_available_decompilation_still_reaches_actual_structured_client(tmp_path, binary_view):
    context = binary_view("decompilation")
    review, calls = _reviewer()
    outcome = review(context, OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path / "out"))
    assert len(calls) == 1
    assert context["source"] in calls[0][0]
    assert outcome.status == "clean" and outcome.cost_usd == .1


def test_nonbinary_source_review_dispatch_is_unchanged(tmp_path):
    review, calls = _reviewer()
    context = {"file": "unit.c", "function": "f", "line_start": 1, "line_end": 1,
               "source": "unsigned f(unsigned n) { return n + 1; }", "language": "c"}
    outcome = review(context, OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path / "out"))
    assert len(calls) == 1 and context["source"] in calls[0][0]
    assert outcome.status == "clean"


def test_binary_path_cannot_hide_missing_view_by_omitting_the_mode_flag(tmp_path, binary_view):
    context = binary_view("unknown")
    del context["is_binary"]
    review, calls = _reviewer()
    with pytest.raises(KnowledgeCallRefused) as caught:
        review(context, OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path / "out"))
    assert caught.value.reason == "binary_implementation_unavailable" and calls == []


@pytest.mark.parametrize("change", [
    {"representation": None}, {"representation": {}}, {"representation": "unregistered"},
    {"source": ""}, {"source": "  \n\t"}, {"source": None}, {"source": {}},
])
def test_binary_view_shape_cannot_consume_a_reviewer_attempt(tmp_path, binary_view, change):
    context = binary_view("decompilation")
    context.update(change)
    review, calls = _reviewer()
    with pytest.raises(KnowledgeCallRefused) as caught:
        review(context, OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path / "out"))
    assert caught.value.reason == "binary_implementation_unavailable" and calls == []


def test_review_one_refuses_missing_binary_view_before_callback_and_coverage(tmp_path, monkeypatch):
    from core.audit import orchestrator as orch
    from core.audit.journal import load_entries
    from core.audit.knowledge_runtime import AuditKnowledgeRuntime
    from core.audit.shared_state import SharedState
    from core.llm.budget_errors import is_budget_exceeded_error
    target, out = tmp_path / "target.bin", tmp_path / "run"
    target.write_bytes(b"owned missing-view fixture, not executable")
    out.mkdir()
    monkeypatch.setenv("RAPTOR_DIR", str(tmp_path / "private-raptor"))
    gap = {"file": binary_path_key(target), "name": "f", "kind": "function",
           "line_start": 0, "line_end": 0, "pinned": True, "force_review": True}
    checklist = {"files": [{"path": gap["file"], "items": [dict(gap)]}]}
    config = orch.OrchestratorConfig(target_path=target, out_dir=out, prefilter=False,
        max_refinements=0, immediate_verify=False, sweep_validate_findings=False,
        sage_recall=False, propagate_constraints=False, no_binary_oracle=True,
        enable_session_context=False, joern_overrides={"enabled": False})
    monkeypatch.setattr(orch, "_correlated_mech_detector_tool", lambda *args: None)
    monkeypatch.setattr(orch, "_gather_library_candidates", lambda *args: [])
    monkeypatch.setattr(orch, "_get_llm_client", lambda *args: None)
    monkeypatch.setattr(orch, "_proactive_validate", lambda outcome, *args, **kwargs: outcome)
    calls = []
    def callback(context, cfg):
        calls.append(context)
        return orch.ReviewOutcome(gap["file"], "f", "clean", "Captured callback proposal", cost_usd=.1)
    runtime = AuditKnowledgeRuntime(target, orch.StudyQueue(), deadline=float("inf"), window=0)
    result = orch.OrchestratorResult()
    failure = None
    try:
        wrapped = runtime.wrap_review(callback)
        def run(unit):
            return orch.review_one_function(unit, SharedState(checklist=checklist), config,
                                            wrapped, result, knowledge_runtime=runtime)
        try:
            runtime.wrap_unit(run)(gap)
        except Exception as exc:
            failure = exc
        assert calls == [], "unavailable binary implementation reached the review callback"
        assert isinstance(failure, KnowledgeCallRefused)
        assert failure.reason == "binary_implementation_unavailable" and not is_budget_exceeded_error(failure)
        assert result.reviewed == 0 and result.total_cost_usd == 0 and result.clean == 0
        assert load_entries(out, fresh=True) == []
        assert sum(runtime._calls.values()) == 0
        assert not any(event["event"] == "review_assessment" for event in runtime.events())
    finally:
        runtime.close("test_complete")
