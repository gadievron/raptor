"""Owner reservations retain full-unit exclusion and bounded knowledge work."""

from core.audit.knowledge_runtime import AuditKnowledgeRuntime
from core.audit.orchestrator import StudyQueue


def _runtime(tmp_path, **policy):
    (tmp_path / "unit.c").write_text("int f(void) { return 1; }\n")
    runtime = AuditKnowledgeRuntime(tmp_path, StudyQueue(), deadline=float("inf"), window=0, **policy)
    ctx = {"file": "unit.c", "function": "f", "line_start": 1,
           "source": "int f(void) { return 1; }", "language": "c"}
    origin = runtime._origin(ctx)
    runtime._register(origin, ctx, {"language_reference_requests": [{"topic": "integer promotion"}]})
    return runtime, ctx


def test_owner_does_not_reserve_before_full_unit_finishes(tmp_path):
    runtime, ctx = _runtime(tmp_path)
    seen = []

    @runtime.wrap_unit
    def review_and_commit(gap):
        seen.append(runtime.ready_continuations(admission=lambda: True))
        assert runtime.has_pending_work() is False

    review_and_commit({"file": ctx["file"], "name": ctx["function"], "line_start": 1})
    assert seen == [()]
    reserved = runtime.ready_continuations(admission=lambda: True)
    assert len(reserved) == 1
    assert runtime.enrich_context(dict(ctx), reserved[0])
    assert runtime.fail(reserved[0], "scripted_failure")
    assert not runtime.ready_continuations(admission=lambda: True)


def test_duplicate_request_identity_cannot_renew_information_delta(tmp_path):
    runtime, ctx = _runtime(tmp_path)
    first = runtime.ready_continuations(admission=lambda: True)[0]
    runtime.complete(first, ctx)
    runtime._register(runtime._origin(ctx), ctx, {
        "language_reference_requests": [{"topic": "integer promotion"}]})
    assert not runtime.ready_continuations(admission=lambda: True)
    assert any(e["event"] == "request_duplicate" for e in runtime.events())


def test_unknown_attempt_counts_defer_additional_review(tmp_path):
    runtime, ctx = _runtime(tmp_path)
    runtime.mark_call_count_unknown({"file": ctx["file"], "name": ctx["function"], "line_start": 1})
    assert not runtime.ready_continuations(admission=lambda: True)
    assert runtime.wake_interval() is None


def test_panel_allowance_exhaustion_ends_waiting(tmp_path):
    runtime, ctx = _runtime(tmp_path, max_model_calls=18)
    key = (ctx["file"], ctx["function"], ctx["line_start"])
    runtime._calls[key] = 16
    assert not runtime.ready_continuations(admission=lambda: True, required_calls=3)
    assert runtime.wake_interval() is None
    assert not runtime.has_pending_work()
