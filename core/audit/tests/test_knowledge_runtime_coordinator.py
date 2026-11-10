"""Owner reservations retain full-unit exclusion and bounded knowledge work."""

from dataclasses import replace

import pytest

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


@pytest.mark.parametrize("action", ["complete", "fail"])
@pytest.mark.parametrize("unowned", ["retired", "copied"])
def test_unowned_completion_cannot_release_newer_reservation(tmp_path, action, unowned):
    runtime, ctx = _runtime(tmp_path)
    try:
        first, = runtime.ready_continuations(admission=lambda: True)
        assert runtime.fail(first, "first_attempt_failed")
        runtime._register(runtime._origin(ctx), ctx, {
            "language_reference_requests": [{"topic": "integer conversion"}]})
        second, = runtime.ready_continuations(admission=lambda: True)
        assert second.packet.pass_id != first.packet.pass_id
        candidate = first if unowned == "retired" else replace(second)
        if unowned == "copied":
            assert candidate == second and candidate is not second
        before = runtime.events()
        if action == "complete":
            assert runtime.complete(candidate, dict(ctx)) is False
        else:
            assert runtime.fail(candidate, "late_failure") is False
        assert runtime.events() == before
        assert not runtime.ready_continuations(admission=lambda: True)
        assert runtime.enrich_context(dict(ctx), second)
        assert runtime.complete(second, dict(ctx))
        completed = [event for event in runtime.events() if event["event"] == "continuation_completed"]
        assert len(completed) == 1 and completed[0]["pass_id"] == second.packet.pass_id
        assert not runtime.ready_continuations(admission=lambda: True)
    finally:
        runtime.close()
