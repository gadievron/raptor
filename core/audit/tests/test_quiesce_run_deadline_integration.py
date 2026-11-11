"""Actual checkpoint drains respect run deadlines without restarting reviews."""

import json
import threading
import time

import pytest

from core.audit import executor as executor_mod
from core.audit import orchestrator as orch
from core.audit.executor import ExecutorConfig, run_executor_sync
from core.audit.journal_quiesce import JournalCheckpointQuiescer
from core.audit.shared_state import SharedState
from core.audit.task_graph import TaskGraph
from core.audit.tests.test_journal_quiesce import _arm, _compressible_journal
from core.coverage.journal import JOURNAL_FILENAME, load_entries
from core.testing.audit_shutdown import isolated_audit_shutdown


@pytest.mark.parametrize("expire", [False, True], ids=["quiescent", "deadline"])
def test_actual_quiesce_run_deadline_preserves_committed_work(tmp_path, monkeypatch, expire):
    out = tmp_path / "out"
    out.mkdir()
    _compressible_journal(out)
    _arm(out, monkeypatch)
    journal = out / JOURNAL_FILENAME
    before = journal.read_bytes()
    committed = {(e.file, e.function, e.verdict) for e in load_entries(out)}
    gaps = [
        {"file": "owned.py", "name": name, "line_start": line, "priority_score": .9}
        for name, line in [("blocked", 1), ("dependent", 4)]
    ]
    graph = TaskGraph.from_workqueue(
        gaps,
        [{"caller_file": "owned.py", "caller": "dependent",
          "callee_file": "owned.py", "callee": "blocked"}],
        max_workers=2,
    )
    config = orch.OrchestratorConfig(target_path=tmp_path, out_dir=out)
    shared = SharedState(checklist={"files": []})
    result = orch.OrchestratorResult()
    started, release, draining, expired = (threading.Event() for _ in range(4))
    calls, checkpoint_inflight, drain_deadlines = [], [], []
    box = {}
    started_at = time.monotonic()
    config.max_seconds = 1.0
    deadline = started_at + config.max_seconds
    config.run_deadline_monotonic = deadline
    quiescer = JournalCheckpointQuiescer(out, deadline_monotonic=deadline)
    original_bound = quiescer.drain_bound_s
    actual_deadline = quiescer.drain_deadline
    actual_checkpoint = quiescer.run_quiesced

    def observe_deadline():
        value = actual_deadline()
        drain_deadlines.append(value)
        draining.set()
        return value

    def observe_checkpoint(boundary="quiesce"):
        checkpoint_inflight.append(executor_mod.review_work_inflight())
        return actual_checkpoint(boundary)

    monkeypatch.setattr(quiescer, "drain_deadline", observe_deadline)
    monkeypatch.setattr(quiescer, "run_quiesced", observe_checkpoint)

    def budget_check():
        reached = orch._check_budget(config, started_at, result)
        if reached:
            expired.set()
        return reached

    def owned_review(gap, shared, config, review_fn, result, **kwargs):
        calls.append(gap["name"])
        if gap["name"] == "blocked":
            started.set()
            assert release.wait(8), "owned outer rescue must release the review"
        return orch.ReviewOutcome(
            file=gap["file"], function=gap["name"], line=gap["line_start"],
            status="clean", body="Owned executor transport result",
        )

    def run():
        try:
            box["stats"] = run_executor_sync(
                graph, None, shared, config, result,
                ExecutorConfig(max_workers=2), review_one_fn=owned_review,
                budget_check=budget_check, quiescer=quiescer,
                on_idle=lambda: .01,
            )
        except BaseException as error:
            box["error"] = error

    worker = threading.Thread(target=run, name="owned-deadline-executor")
    waited_for_owned_completion = False
    with isolated_audit_shutdown(orch):
        worker.start()
        try:
            assert started.wait(3), "owned task did not enter the real executor"
            assert draining.wait(3), "actual quiescer drain was not entered"
            assert drain_deadlines and drain_deadlines[0] <= deadline
            assert quiescer.drain_bound_s == original_bound == 900
            if expire:
                assert expired.wait(3), "actual capped drain did not observe run expiry"
                waited_for_owned_completion = worker.is_alive()
                assert waited_for_owned_completion
                assert calls == ["blocked"]
                assert not checkpoint_inflight
                assert journal.read_bytes() == before
            release.set()
            worker.join(5)
        finally:
            release.set()
            worker.join(5)
    assert not worker.is_alive(), "owned executor thread survived unconditional cleanup"
    if "error" in box:
        raise box["error"]
    stats = box["stats"]
    stop_reports = []
    orch._announce_budget_stop(
        result, stats, graph, lambda index, total, outcome: stop_reports.append(outcome.body),
    )
    trace = {
        "expiry_requested": expire, "stats": stats.to_dict(),
        "calls": calls, "pending": graph.pending,
        "drain_deadlines": drain_deadlines,
        "checkpoint_inflight": checkpoint_inflight,
        "waited_for_owned_completion": waited_for_owned_completion,
        "terminated_by": result.terminated_by,
        "stop_reports": stop_reports,
    }
    (out / "quiesce-deadline-trace.json").write_text(json.dumps(trace, indent=2))
    if expire:
        outcome = quiescer.run_at_boundary("after_owned_drain")
        trace["checkpoint_outcome"] = {
            "aborted": outcome.aborted, "reason": outcome.reason,
        }
        (out / "quiesce-deadline-trace.json").write_text(json.dumps(trace, indent=2))
        assert outcome.aborted and outcome.reason == "run deadline reached"
        assert stats.budget_stopped
        assert result.terminated_by == "max_seconds"
        assert len(stop_reports) == 1
        assert "time budget exhausted after 1/2 reviews" in stop_reports[0]
        assert "1 functions left unreviewed" in stop_reports[0]
        assert stats.dispatched == stats.completed == 1 and stats.failed == 0
        assert calls == ["blocked"] and graph.pending == 1
        assert journal.read_bytes() == before
        assert not (out / f"{JOURNAL_FILENAME}.pre-supersede").exists()
    else:
        assert not stats.budget_stopped
        assert result.terminated_by == "complete" and not stop_reports
        assert stats.dispatched == stats.completed == 2 and stats.failed == 0
        assert calls == ["blocked", "dependent"] and graph.pending == 0
        assert checkpoint_inflight and all(n == 0 for n in checkpoint_inflight)
        assert (out / f"{JOURNAL_FILENAME}.pre-supersede").exists()
        assert committed <= {(e.file, e.function, e.verdict) for e in load_entries(out)}
    (out / "quiesce-deadline-trace.json").write_text(json.dumps(trace, indent=2))
