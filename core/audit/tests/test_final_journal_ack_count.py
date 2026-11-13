"""Corrective row counts require the actual owned writer acknowledgement."""
import pytest

from core.audit import orchestrator as orch
from core.audit.collector import append_journal_for_outcome
from core.audit.knowledge_runtime import AuditKnowledgeRuntime
from core.audit.llm_review import make_review_fn
from core.coverage.journal import load_entries
from core.llm.providers import StructuredResponse


@pytest.mark.parametrize("change_source", [True, False], ids=["changed", "fresh"])
def test_corrective_count_matches_actual_source_scope_admission(tmp_path, monkeypatch, change_source):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    target, out = tmp_path / "target", tmp_path / "out"
    target.mkdir()
    out.mkdir()
    source = "unsigned f(unsigned n) { return n; }\n"
    path = target / "unit.c"
    path.write_text(source)
    gap = {"file": "unit.c", "name": "f", "line_start": 1, "line_end": 1}
    prior = orch.ReviewOutcome("unit.c", "f", "clean", "Owned prior status", line=1)
    assert append_journal_for_outcome(out_dir=out, target_path=target, run_id=out.name,
                                     outcome=prior, gap=gap) is not None
    calls = []

    class Client:
        _attempt_admission_protocol = 1
        _call_cost_history = None

        def is_budget_exhausted(self):
            return False

        def generate_structured(self, prompt, schema, **kwargs):
            assert kwargs.pop("accounting_attempt_admission")() is True
            calls.append(prompt)
            return StructuredResponse(result={"status": "suspicious", "body": "Owned final status",
                "reading_list": [], "language_reference_requests": []}, raw="", cost=0, model="scripted")

    client = Client()
    config = orch.OrchestratorConfig(target_path=target, out_dir=out, max_refinements=0)
    config.llm_budget_client = client
    runtime = AuditKnowledgeRuntime(target, orch.StudyQueue(), deadline=float("inf"), window=0)
    try:
        outcome = runtime.wrap_review(make_review_fn(client, escalate_clean=False))({
            "file": "unit.c", "function": "f", "line_start": 1, "line_end": 1,
            "source": source, "language": "c"}, config)
        outcome.line = 1
        assert outcome.review_input_scope is not None and outcome.review_input_scope.current(target)
        assert len(calls) == 1
        if change_source:
            path.write_text("unsigned f(unsigned n) { return n + 1; }\n")
        assert outcome.review_input_scope.current(target) is (not change_source)
        result = orch.OrchestratorResult(outcomes=[outcome], suspicious=1)
        updated = orch._rejournal_final_statuses(result, config)
        assert result.outcomes[0] is outcome and outcome.status == "suspicious"
        rows = load_entries(out, fresh=True)
        assert len(rows) == (1 if change_source else 2) and rows[0].verdict == "clean"
        assert updated == (0 if change_source else 1)
        if not change_source:
            assert rows[-1].verdict == "suspicious" and rows[-1].line_start == 1
    finally:
        runtime.close("test_complete")


def test_actual_writer_append_failure_stays_nonraising_and_counts_zero(tmp_path, monkeypatch):
    import builtins
    from types import ModuleType

    from core.audit import collector
    from core.testing.module_views import module_function_view

    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    target, out = tmp_path / "target", tmp_path / "out"
    target.mkdir()
    out.mkdir()
    (target / "unit.c").write_text("unsigned f(unsigned n) { return n; }\n")
    prior = orch.ReviewOutcome("unit.c", "f", "clean", "Owned prior", line=1)
    assert append_journal_for_outcome(out_dir=out, target_path=target, run_id=out.name,
        outcome=prior, gap={"line_start": 1, "line_end": 1}) is not None
    attempts = []

    def fail_append(*args, **kwargs):
        attempts.append(True)
        raise OSError("owned append failure")

    owned_writer = module_function_view(collector, bindings={"append_entry": fail_append})
    owned_collector = ModuleType(collector.__name__)
    vars(owned_collector).update(vars(collector))
    owned_collector.append_journal_for_outcome = owned_writer.append_journal_for_outcome

    def import_local(name, globals=None, locals=None, fromlist=(), level=0):
        if level == 1 and name == "collector":
            return owned_collector
        return builtins.__import__(name, globals, locals, fromlist, level)

    private = module_function_view(orch, import_hook=import_local)
    final = orch.ReviewOutcome("unit.c", "f", "suspicious", "Owned final", line=1)
    updated = private._rejournal_final_statuses(orch.OrchestratorResult(outcomes=[final], suspicious=1),
        orch.OrchestratorConfig(target_path=target, out_dir=out))
    assert attempts == [True]
    assert updated == 0
    rows = load_entries(out, fresh=True)
    assert len(rows) == 1 and rows[0].verdict == "clean"
