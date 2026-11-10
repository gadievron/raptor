"""Runtime readiness uses absolute windows and refuses expired continuations."""

import json

import pytest

from core.audit import knowledge_runtime as runtime_module
from core.audit.orchestrator import StudyQueue


@pytest.fixture
def runtime_clock(tmp_path, monkeypatch):
    clock = [100.125]
    monkeypatch.setattr(runtime_module, "monotonic", lambda: clock[0])
    owned = []

    def create(*, window=10.0, deadline=float("inf"), useful=True):
        target = tmp_path / str(len(owned))
        target.mkdir()
        source = "typedef int foo_t;\nint f(foo_t x) { return x; }\n"
        (target / "unit.c").write_text(source)
        runtime = runtime_module.AuditKnowledgeRuntime(
            target, StudyQueue(), deadline=deadline, window=window)
        owned.append(runtime)
        ctx = {"file": "unit.c", "function": "f", "line_start": 2,
               "source": source.splitlines()[1], "language": "c"}
        result = {"reading_list": [{"subject": "foo_t", "resolution": "identifier"}]}
        if useful:
            result["language_reference_requests"] = [{"topic": "integer promotion"}]
        runtime._register(runtime._origin(ctx), ctx, result)
        assert len(runtime.requests()) == (2 if useful else 1)
        return runtime, ctx

    try:
        yield clock, create
    finally:
        for runtime in owned:
            runtime.close("test_complete")


@pytest.mark.parametrize("window", [0.75, 10.0], ids=["short_fractional", "ten_seconds"])
def test_new_results_and_notifications_do_not_extend_first_ready_window(runtime_clock, window):
    clock, create = runtime_clock
    runtime, ctx = create(window=window)
    first_ready = clock[0]
    assert runtime.ready_continuations(admission=lambda: True) == ()
    assert runtime.wake_interval() > 0

    clock[0] = first_ready + window - 0.125
    runtime.notify()
    # A different useful answer also joins the original absolute window.
    runtime._register(runtime._origin(ctx), ctx, {
        "language_reference_requests": [{"topic": "integer conversion", "entry_id": "c.integer-conversion"}]})
    clock[0] = first_ready + window - 0.001
    assert runtime.ready_continuations(admission=lambda: True) == ()
    assert runtime.wake_interval() > 0

    clock[0] = first_ready + window
    reservation, = runtime.ready_continuations(admission=lambda: True)
    assert len(reservation.packet.references) == 2
    assert len(reservation.packet.pending_ids) == 1
    assert {r.request_id for r in runtime.requests() if r.kind == "language_reference"} == {
        answer.request_id for answer in reservation.packet.references}
    assert runtime.ready_continuations(admission=lambda: True) == ()
    assert runtime.wake_interval() is None


def test_finished_source_work_releases_useful_partial_packet_before_window_expires(runtime_clock):
    clock, create = runtime_clock
    runtime, _ = create()
    clock[0] += 0.25
    assert runtime.ready_continuations(admission=lambda: True) == ()
    runtime.close_sources("source_finished_without_answer")
    reservation, = runtime.ready_continuations(admission=lambda: True)
    assert len(reservation.packet.references) == 1
    assert reservation.packet.pending_ids == ()
    assert reservation.packet.explanations == ()
    source_request, = (r for r in runtime.requests() if r.kind == "target_study")
    source_answer, = (event["answer"] for event in runtime.events()
                      if event["event"] == "source_answer"
                      and event["answer"]["request_id"] == source_request.request_id)
    assert source_answer["status"] == "unavailable"
    assert source_answer["reason"] == "source_finished_without_answer"


def test_deadline_refuses_otherwise_ready_packet_and_persists_cycle_disposition(runtime_clock, tmp_path):
    clock, create = runtime_clock
    deadline = clock[0] + 5
    runtime, _ = create(deadline=deadline)
    clock[0] = deadline - 0.001
    assert runtime.ready_continuations(admission=lambda: True) == ()
    # Finishing the source job makes this packet ready before the ten-second
    # window. The absolute deadline must still veto its later reservation.
    runtime.close_sources("source_finished_without_answer")
    clock[0] = deadline
    assert runtime.ready_continuations(admission=lambda: True) == ()
    runtime.write_artifacts(tmp_path / "artifacts")
    data = json.loads((tmp_path / "artifacts/knowledge-results.json").read_text())
    unit, = data["units"]
    assert unit["cycle"]["started"] == 0
    assert unit["cycle"]["active_pass_id"] is None
    assert any(event["event"] == "continuation_deferred" and event["reason"] == "deadline"
               for event in unit["cycle"]["events"])
    assert not any(event["event"] == "continuation_reserved" for event in data["events"])


def test_waiting_without_useful_information_never_buys_a_review(runtime_clock):
    clock, create = runtime_clock
    runtime, _ = create(useful=False)
    clock[0] += 50
    runtime.notify()
    assert runtime.ready_continuations(admission=lambda: True) == ()
    runtime.close_sources("source_unavailable")
    assert runtime.ready_continuations(admission=lambda: True) == ()
    assert runtime.wake_interval() is None
    assert not any(event["event"] == "continuation_reserved" for event in runtime.events())
