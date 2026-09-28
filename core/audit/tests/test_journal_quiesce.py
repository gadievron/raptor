"""Audit-side journal-checkpoint quiesce: the StudyQueue park
protocol, the quiescer's cadence/cooldowns, the executor quiesce
points (serial + async, drain timeout), the run's own-worker
self-permit, and the NO-RESTART property (spy suite + filesystem
delta + import census + prep-cache survival).

Charter safety requirements pinned here:

1. synchronous, never submitted to the executor — the async quiesce
   runs the checkpoint on the driving thread with inflight provably
   zero at call time (captured by the spy wrapper);
7. bounded — a drain that cannot reach inflight → 0 within the bound
   abandons the attempt, dispatch resumes, the journal stands;
8. no-restart — a fired checkpoint touches nothing beyond the
   journal, its archive, and its state record: the Joern lifecycle,
   the LLM dispatcher, and the prep caches are untouched (spies),
   the run dir's other files are byte-stable (delta), the checkpoint
   modules cannot even name those subsystems (import census), and a
   prep-cache entry written before the checkpoint still HITS after it
   (the journal is not among any prep fingerprint's inputs —
   ``core.audit.prep_cache``'s doctrine, pinned below).
"""

from __future__ import annotations

import ast
import json
import logging
import os
import threading
import time
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

import core.audit.executor as executor_mod
import core.audit.journal_quiesce as quiesce_mod
import core.coverage.journal as journal_mod
from core.audit.executor import ExecutorConfig, run_executor_sync
from core.audit.journal_quiesce import JournalCheckpointQuiescer
from core.audit.orchestrator import StudyQueue, StudyRequest
from core.audit.task_graph import TaskGraph
from core.audit.tests.test_executor import (
    _FakeResult,
    _gap,
    _mock_review_fn,
)
from core.coverage.journal import (
    JOURNAL_FILENAME,
    ReviewJournalEntry,
    append_entry,
    now_iso,
)
from core.coverage.journal_checkpoint import (
    CHECKPOINT_STATE_FILENAME,
    CheckpointBusy,
)

_JOIN_TIMEOUT_S = 60.0
_BACKUP_NAME = f"{JOURNAL_FILENAME}.pre-supersede"


def _entry(i: int, **over) -> ReviewJournalEntry:
    fields = dict(
        ts=now_iso(),
        run_id="audit-run",
        file=f"src/f{i % 5}.c",
        function=f"fn{i}",
        verdict="clean",
        source_hash=f"{i:08x}",
        strategies=["bounds"],
        body="review body " * 20,
    )
    fields.update(over)
    return ReviewJournalEntry(**fields)


def _compressible_journal(out: Path, n: int = 8, segments: int = 3) -> None:
    for i in range(n):
        append_entry(out, _entry(i, cost_usd=0.25 + i / 100))
    for _seg in range(segments - 1):
        for i in range(n):
            append_entry(out, _entry(
                i, reused=True, reused_from_run="audit-run",
                cost_usd=0.0, body="[reused: verdict imported]",
            ))


def _incompressible_journal(out: Path, n: int = 24) -> None:
    for i in range(n):
        append_entry(out, _entry(i, cost_usd=0.1))


def _arm(out: Path, monkeypatch) -> None:
    """Journal over the 65% trigger with loader headroom, and a zero
    evaluation interval so every dispatch point evaluates."""
    size = (out / JOURNAL_FILENAME).stat().st_size
    monkeypatch.setattr(
        journal_mod, "_MAX_JOURNAL_BYTES", int(size * 1.4))
    monkeypatch.setattr(quiesce_mod, "_QUIESCE_EVAL_INTERVAL_S", 0.0)


def _request() -> StudyRequest:
    return StudyRequest(
        question="what is concept_x?",
        source_file="a.py",
        source_function="producer",
    )


class TestStudyQueuePauseProtocol:
    def test_pause_gates_dequeue_and_resume_lifts(self) -> None:
        sq = StudyQueue()
        sq.enqueue(_request())
        sq.request_pause()
        assert sq.dequeue_batch(timeout=0.01) == []
        sq.resume_from_pause()
        assert len(sq.dequeue_batch(timeout=0.01)) == 1

    def test_wait_quiescent_true_when_parked_idle(self) -> None:
        sq = StudyQueue()
        sq.request_pause()
        assert sq.wait_quiescent(0.1) is True

    def test_wait_quiescent_times_out_mid_batch(self) -> None:
        sq = StudyQueue()
        sq.set_working(True)
        sq.request_pause()
        assert sq.wait_quiescent(0.05) is False

    def test_wait_quiescent_wakes_on_working_to_idle(self) -> None:
        sq = StudyQueue()
        sq.set_working(True)
        sq.request_pause()

        def _finish_batch() -> None:
            time.sleep(0.1)
            sq.set_working(False)

        t = threading.Thread(target=_finish_batch, daemon=True)
        start = time.monotonic()
        t.start()
        assert sq.wait_quiescent(10.0) is True
        assert time.monotonic() - start < 5.0
        t.join(timeout=5.0)

    def test_consumer_done_is_quiescent_without_pause(self) -> None:
        sq = StudyQueue()
        sq.set_working(True)  # stale flag from a dead consumer
        sq.signal_consumer_done()
        assert sq.wait_quiescent(0.05) is True

    def test_dequeue_marks_working_atomically(self) -> None:
        # The quiescer's parked proof must never observe a dequeued-
        # but-not-yet-working batch: the dequeue itself sets working.
        sq = StudyQueue()
        sq.enqueue(_request())
        batch = sq.dequeue_batch(timeout=0.01)
        assert batch
        _progress, _empty, working = sq.drain_state()
        assert working is True


class TestQuiescerCadence:
    def test_disabled_never_attempts_or_runs(
        self, tmp_path: Path, monkeypatch,
    ) -> None:
        _compressible_journal(tmp_path)
        _arm(tmp_path, monkeypatch)
        q = JournalCheckpointQuiescer(tmp_path, enabled=False)
        assert q.should_attempt() is False
        assert q.run_quiesced() is None
        assert not (tmp_path / _BACKUP_NAME).exists()

    def test_no_out_dir_disables(self) -> None:
        q = JournalCheckpointQuiescer(None)
        assert q.enabled is False
        assert q.should_attempt() is False

    def test_rate_limit_spaces_evaluations(
        self, tmp_path: Path, monkeypatch,
    ) -> None:
        from core.coverage.journal_checkpoint import (
            evaluate_trigger as _real,
        )
        _incompressible_journal(tmp_path, n=4)
        monkeypatch.setattr(
            quiesce_mod, "_QUIESCE_EVAL_INTERVAL_S", 3600.0)
        calls: list[Path] = []

        def _counting(out_dir):
            calls.append(out_dir)
            return _real(out_dir)

        monkeypatch.setattr(quiesce_mod, "evaluate_trigger", _counting)
        q = JournalCheckpointQuiescer(tmp_path)
        assert q.should_attempt() is False  # evaluates: under threshold
        assert q.should_attempt() is False  # rate-limited: no evaluation
        assert len(calls) == 1

    def test_fires_over_threshold(
        self, tmp_path: Path, monkeypatch,
    ) -> None:
        _compressible_journal(tmp_path)
        _arm(tmp_path, monkeypatch)
        q = JournalCheckpointQuiescer(tmp_path)
        assert q.should_attempt() is True

    def test_should_abort_blocks_attempt(
        self, tmp_path: Path, monkeypatch,
    ) -> None:
        _compressible_journal(tmp_path)
        _arm(tmp_path, monkeypatch)
        q = JournalCheckpointQuiescer(
            tmp_path, should_abort=lambda: True)
        assert q.should_attempt() is False

    def test_drain_timeout_cooldown_blocks_then_expires(
        self, tmp_path: Path, monkeypatch,
    ) -> None:
        _compressible_journal(tmp_path)
        _arm(tmp_path, monkeypatch)
        q = JournalCheckpointQuiescer(tmp_path)
        assert q.should_attempt() is True
        q.note_drain_timeout(2)
        # Cooldown direction: no re-attempt while it runs.
        assert q.should_attempt() is False
        # Expiry direction: a zero cooldown re-attempts immediately.
        monkeypatch.setattr(
            quiesce_mod, "_QUIESCE_RETRY_COOLDOWN_S", 0.0)
        q.note_drain_timeout(2)
        assert q.should_attempt() is True

    def test_evaluation_failure_contained_with_cooldown(
        self, tmp_path: Path, monkeypatch, caplog,
    ) -> None:
        # should_attempt is the executors' bare loop-head call: an
        # evaluation failure (state record and run metadata are
        # run-dir content any writer can corrupt) must resolve to
        # "no checkpoint this cycle" + warning + cooldown — never an
        # exception into the paid run.
        from core.coverage.journal_checkpoint import (
            evaluate_trigger as _real,
        )
        _compressible_journal(tmp_path)
        _arm(tmp_path, monkeypatch)

        def _boom(out_dir: Path):
            raise TypeError("synthetic hostile-state failure")

        monkeypatch.setattr(quiesce_mod, "evaluate_trigger", _boom)
        q = JournalCheckpointQuiescer(tmp_path)
        with caplog.at_level(
                logging.WARNING, logger="core.audit.journal_quiesce"):
            assert q.should_attempt() is False
        assert any(
            "trigger evaluation failed" in r.getMessage()
            for r in caplog.records
        )
        # The failure armed the retry cooldown: a now-healthy
        # evaluation stays suppressed until it expires.
        monkeypatch.setattr(quiesce_mod, "evaluate_trigger", _real)
        assert q.should_attempt() is False
        q._cooldown_until = 0.0
        assert q.should_attempt() is True

    def test_persistent_refusal_preflight_skips_drain(
        self, tmp_path: Path, monkeypatch, caplog,
    ) -> None:
        # A fired trigger whose compaction the compactor would refuse
        # (unreadable run metadata — the guard fails closed) must not
        # convert every evaluation interval into a quiesce drain: the
        # preflight reports the refusal BEFORE any drain and arms the
        # retry cooldown.
        from core.run.metadata import RUN_METADATA_FILE
        _compressible_journal(tmp_path)
        _arm(tmp_path, monkeypatch)
        (tmp_path / RUN_METADATA_FILE).write_text("{ not json !!!")
        q = JournalCheckpointQuiescer(tmp_path)
        with caplog.at_level(
                logging.WARNING, logger="core.audit.journal_quiesce"):
            fired = sum(q.should_attempt() for _ in range(5))
        assert fired == 0
        assert q._cooldown_until > 0
        assert any(
            "would refuse" in r.getMessage() for r in caplog.records)
        # Recovery direction: once the refusal condition clears and
        # the cooldown expires, the attempt proceeds again.
        (tmp_path / RUN_METADATA_FILE).unlink()
        q._cooldown_until = 0.0
        assert q.should_attempt() is True

    def test_advisory_logged_once_then_spaced(
        self, tmp_path: Path, monkeypatch, caplog,
    ) -> None:
        # An incompressible journal's first checkpoint is ineffective
        # (hysteresis armed); the quiesce poll then logs the advisory
        # once and stays silent within the repeat window.
        _incompressible_journal(tmp_path)
        _arm(tmp_path, monkeypatch)
        q = JournalCheckpointQuiescer(tmp_path)
        outcome = q.run_quiesced()
        assert outcome is not None and outcome.fired
        assert outcome.freed_fraction < 0.10
        with caplog.at_level(
                logging.WARNING, logger="core.audit.journal_quiesce"):
            assert q.should_attempt() is False
            assert q.should_attempt() is False
        advisories = [
            r for r in caplog.records
            if r.name == "core.audit.journal_quiesce"
            and "legitimately large" in r.getMessage()
        ]
        assert len(advisories) == 1


class TestQuiescerConstants:
    """Two-direction regression tests for the quiesce-side cadence
    constants: each bound names the failure mode crossing it would
    reintroduce (see the constants' inline rationale comments in
    ``core.audit.journal_quiesce``)."""

    def test_eval_interval_bounds(self) -> None:
        # Lower: below this the loop-head poll stats the shard set at
        # effectively per-dispatch cadence of a hot serial loop — the
        # cost the interval exists to amortise.
        assert quiesce_mod._QUIESCE_EVAL_INTERVAL_S >= 10.0
        # Upper: the journal overshoots a fired trigger by one whole
        # interval of appends; the trigger's margin below the roll
        # threshold is sized to absorb only a bounded interval.
        assert quiesce_mod._QUIESCE_EVAL_INTERVAL_S <= 300.0

    def test_drain_bound_bounds(self) -> None:
        # Lower: must outlast the longest sanctioned single review
        # (a full-context review with tool chains runs minutes) — a
        # shorter bound abandons the quiesce whenever one
        # slow-but-live review is in flight, pushing every checkpoint
        # back to segment boundaries (the mid-segment wall this
        # exists to remove).
        assert quiesce_mod._QUIESCE_DRAIN_BOUND_S >= 600.0
        # Upper: dispatch stays stopped behind a wedged review for
        # the whole bound (workers idle, spend paused) — the cap
        # keeps a wedge's cost to one review-length pause.
        assert quiesce_mod._QUIESCE_DRAIN_BOUND_S <= 1800.0
        # Consumers read the class attribute; it mirrors the module
        # constant.
        assert (JournalCheckpointQuiescer.drain_bound_s
                == quiesce_mod._QUIESCE_DRAIN_BOUND_S)

    def test_retry_cooldown_bounds(self) -> None:
        # Lower: a cooldown under the evaluation cadence re-runs the
        # drain dance straight into the same slow review (stop-start
        # dispatch thrash).
        assert (quiesce_mod._QUIESCE_RETRY_COOLDOWN_S
                >= quiesce_mod._QUIESCE_EVAL_INTERVAL_S)
        # Upper: past the drain bound the journal keeps growing past
        # an already-fired trigger with the roll threshold
        # approaching.
        assert (quiesce_mod._QUIESCE_RETRY_COOLDOWN_S
                <= quiesce_mod._QUIESCE_DRAIN_BOUND_S)

    def test_advisory_repeat_bounds(self) -> None:
        # Lower: at or near the evaluation cadence a standing
        # hysteresis state turns into a log flood — the spacing must
        # cover many evaluations per advisory line.
        assert (quiesce_mod._ADVISORY_REPEAT_S
                >= 10 * quiesce_mod._QUIESCE_EVAL_INTERVAL_S)
        # Upper: past an hour a live tail loses sight of a journal
        # pinned over threshold.
        assert quiesce_mod._ADVISORY_REPEAT_S <= 3600.0


class _FakeStudyQueue:
    """Records the park-protocol calls the quiescer makes."""

    def __init__(self, *, parks: bool = True, done: bool = False) -> None:
        self.calls: list[str] = []
        self._parks = parks
        self.consumer_done = done

    def request_pause(self) -> None:
        self.calls.append("pause")

    def wait_quiescent(self, timeout: float) -> bool:
        self.calls.append("wait")
        return self._parks

    def resume_from_pause(self) -> None:
        self.calls.append("resume")

    def drain_state(self) -> tuple[int, bool, bool]:
        return (0, True, False)


class TestRunQuiesced:
    def test_park_checkpoint_resume_ordering(
        self, tmp_path: Path, monkeypatch,
    ) -> None:
        _compressible_journal(tmp_path)
        _arm(tmp_path, monkeypatch)
        sq = _FakeStudyQueue()
        q = JournalCheckpointQuiescer(tmp_path, study_queue=sq)
        outcome = q.run_quiesced("segment-boundary")
        assert outcome is not None and outcome.fired
        assert sq.calls == ["pause", "wait", "resume"]
        assert (tmp_path / _BACKUP_NAME).exists()
        state = json.loads(
            (tmp_path / CHECKPOINT_STATE_FILENAME).read_text())
        assert state["boundary"] == "segment-boundary"

    def test_park_timeout_abandons_with_cooldown(
        self, tmp_path: Path, monkeypatch,
    ) -> None:
        _compressible_journal(tmp_path)
        _arm(tmp_path, monkeypatch)
        before = (tmp_path / JOURNAL_FILENAME).read_bytes()
        sq = _FakeStudyQueue(parks=False)
        q = JournalCheckpointQuiescer(tmp_path, study_queue=sq)
        assert q.run_quiesced() is None
        assert (tmp_path / JOURNAL_FILENAME).read_bytes() == before
        # The pause request is lifted on abandonment — a latched
        # pause with no checkpoint coming would starve the study
        # consumer — and the attempt cools down.
        assert sq.calls == ["pause", "wait", "resume"]
        assert q.should_attempt() is False

    def test_real_queue_mid_batch_blocks_park(
        self, tmp_path: Path, monkeypatch,
    ) -> None:
        _compressible_journal(tmp_path)
        _arm(tmp_path, monkeypatch)
        before = (tmp_path / JOURNAL_FILENAME).read_bytes()
        sq = StudyQueue()
        sq.set_working(True)  # consumer mid-batch, never finishes
        q = JournalCheckpointQuiescer(tmp_path, study_queue=sq)
        q.drain_bound_s = 0.05
        assert q.run_quiesced() is None
        assert (tmp_path / JOURNAL_FILENAME).read_bytes() == before
        # The pause request is lifted even on abandonment: a paused
        # consumer with no checkpoint coming would starve the study
        # lane for the rest of the segment.
        assert sq._pause_requested is False

    def test_study_busy_probe_states(self) -> None:
        sq = StudyQueue()
        q = JournalCheckpointQuiescer(Path("."), study_queue=sq)
        sq.set_working(True)
        assert "mid-batch" in (q._study_busy_probe() or "")
        sq.set_working(False)
        assert q._study_busy_probe() is None
        sq.set_working(True)
        sq.signal_consumer_done()
        assert q._study_busy_probe() is None

    def test_checkpoint_busy_is_loud_skip_not_crash(
        self, tmp_path: Path, monkeypatch, caplog,
    ) -> None:
        _compressible_journal(tmp_path)
        _arm(tmp_path, monkeypatch)

        def _busy(*a, **k):
            raise CheckpointBusy("1 review(s) in flight")

        monkeypatch.setattr(quiesce_mod, "checkpoint_journal", _busy)
        q = JournalCheckpointQuiescer(tmp_path)
        with caplog.at_level(
                logging.ERROR, logger="core.audit.journal_quiesce"):
            assert q.run_quiesced() is None
        assert any(
            "precondition guard refused" in r.getMessage()
            for r in caplog.records
        )
        assert q.should_attempt() is False  # cooled down

    def test_unexpected_failure_never_raises(
        self, tmp_path: Path, monkeypatch, caplog,
    ) -> None:
        _compressible_journal(tmp_path)
        _arm(tmp_path, monkeypatch)
        before = (tmp_path / JOURNAL_FILENAME).read_bytes()

        def _boom(*a, **k):
            raise RuntimeError("synthetic")

        monkeypatch.setattr(quiesce_mod, "checkpoint_journal", _boom)
        sq = _FakeStudyQueue()
        q = JournalCheckpointQuiescer(tmp_path, study_queue=sq)
        with caplog.at_level(
                logging.WARNING, logger="core.audit.journal_quiesce"):
            assert q.run_quiesced() is None
        assert (tmp_path / JOURNAL_FILENAME).read_bytes() == before
        # The park is still released on the failure path.
        assert sq.calls[-1] == "resume"

    def test_refused_outcome_arms_cooldown(
        self, tmp_path: Path, monkeypatch,
    ) -> None:
        # A refusal that surfaces inside the compactor (past the
        # preflight — blinded here to model refusal classes the
        # preflight cannot see) still cools the quiescer down:
        # refusal conditions persist, and each async re-fire would
        # pay the full inflight drain just to be refused again.
        from core.run.metadata import RUN_METADATA_FILE
        _compressible_journal(tmp_path)
        _arm(tmp_path, monkeypatch)
        monkeypatch.setattr(
            quiesce_mod, "preflight_refusal", lambda *a, **k: None)
        (tmp_path / RUN_METADATA_FILE).write_text("{ not json !!!")
        q = JournalCheckpointQuiescer(tmp_path)
        assert q.should_attempt() is True
        outcome = q.run_quiesced()
        assert outcome is not None and outcome.refused
        # Cooldown direction: no re-attempt while it runs.
        assert q.should_attempt() is False
        # Expiry direction: a zero cooldown re-attempts immediately.
        monkeypatch.setattr(
            quiesce_mod, "_QUIESCE_RETRY_COOLDOWN_S", 0.0)
        q._cooldown_until = 0.0
        outcome2 = q.run_quiesced()
        assert outcome2 is not None and outcome2.refused
        assert q.should_attempt() is True

    def test_self_permit_own_live_run(
        self, tmp_path: Path, monkeypatch,
    ) -> None:
        """The run's OWN recorded worker may checkpoint its journal at
        a quiesced point; any other caller still refuses."""
        from core.coverage.journal_compact import (
            CompactRefused,
            compact_journal,
        )
        from core.project import sessions as _sessions
        from core.run.metadata import RUN_METADATA_FILE

        _compressible_journal(tmp_path)
        _arm(tmp_path, monkeypatch)
        meta: dict[str, Any] = {
            "command": "audit",
            "status": "running",
            "tool_pid": os.getpid(),
        }
        start = _sessions.proc_starttime(os.getpid())
        if start is not None:
            meta["tool_pid_start"] = start
        (tmp_path / RUN_METADATA_FILE).write_text(json.dumps(meta))
        # Without the self-permit the live-run guard refuses.
        with pytest.raises(CompactRefused):
            compact_journal(tmp_path, supersede=True)
        # The quiescer passes allow_worker_pid=os.getpid(): permitted.
        q = JournalCheckpointQuiescer(tmp_path)
        outcome = q.run_quiesced()
        assert outcome is not None and outcome.fired
        assert (tmp_path / _BACKUP_NAME).exists()


def _run_bounded(
    graph: TaskGraph,
    review_one_fn: Any,
    quiescer: JournalCheckpointQuiescer,
    max_workers: int,
) -> Any:
    """Run the executor on a worker thread with a hard join bound so a
    quiesce deadlock regression fails the test, not the session."""
    shared = MagicMock()
    shared.triage_results = {}
    config = MagicMock()
    config.llm_client = None
    result = _FakeResult()
    box: dict[str, Any] = {}

    def _run() -> None:
        box["stats"] = run_executor_sync(
            graph, MagicMock(), shared, config, result,
            ExecutorConfig(max_workers=max_workers),
            review_one_fn=review_one_fn,
            quiescer=quiescer,
        )

    worker = threading.Thread(target=_run, daemon=True)
    worker.start()
    worker.join(timeout=_JOIN_TIMEOUT_S)
    assert not worker.is_alive(), "executor wedged around the quiesce"
    return box["stats"]


def _spy_inflight_at_checkpoint(
    q: JournalCheckpointQuiescer,
) -> list[int]:
    """Wrap the instance's run_quiesced to record the executor's
    inflight review count at call time (charter: the checkpoint runs
    synchronously with review work provably drained)."""
    seen: list[int] = []
    orig = q.run_quiesced

    def _spy(boundary: str = "quiesce"):
        seen.append(executor_mod.review_work_inflight())
        return orig(boundary)

    q.run_quiesced = _spy  # type: ignore[method-assign]
    return seen


class TestExecutorQuiescePoints:
    def test_serial_loop_checkpoints_between_reviews(
        self, tmp_path: Path, monkeypatch,
    ) -> None:
        _compressible_journal(tmp_path)
        _arm(tmp_path, monkeypatch)
        before = (tmp_path / JOURNAL_FILENAME).stat().st_size
        q = JournalCheckpointQuiescer(tmp_path)
        seen = _spy_inflight_at_checkpoint(q)
        wq = [_gap("a.py", f"f{i}", 0.9) for i in range(3)]
        graph = TaskGraph.from_workqueue(wq, [])
        stats = _run_bounded(graph, _mock_review_fn, q, max_workers=1)
        assert stats.completed == 3
        assert graph.pending == 0
        assert (tmp_path / _BACKUP_NAME).exists()
        assert (tmp_path / JOURNAL_FILENAME).stat().st_size < before
        assert (tmp_path / CHECKPOINT_STATE_FILENAME).exists()
        assert seen and all(v == 0 for v in seen)

    def test_async_quiesce_drains_then_checkpoints(
        self, tmp_path: Path, monkeypatch,
    ) -> None:
        _compressible_journal(tmp_path)
        _arm(tmp_path, monkeypatch)
        q = JournalCheckpointQuiescer(tmp_path)
        seen = _spy_inflight_at_checkpoint(q)
        wq = [_gap("a.py", f"f{i}", 0.9) for i in range(4)]
        graph = TaskGraph.from_workqueue(wq, [], max_workers=2)
        stats = _run_bounded(graph, _mock_review_fn, q, max_workers=2)
        # Every task completed: dispatch was re-primed after the
        # quiesce (completions during the drain skip dispatch).
        assert stats.completed == 4
        assert graph.pending == 0
        assert (tmp_path / _BACKUP_NAME).exists()
        # The synchronous-checkpoint charter line: review inflight was
        # ZERO at every checkpoint call.
        assert seen and all(v == 0 for v in seen)

    def test_async_drain_timeout_abandons_and_run_completes(
        self, tmp_path: Path, monkeypatch, caplog,
    ) -> None:
        _compressible_journal(tmp_path)
        _arm(tmp_path, monkeypatch)
        before = (tmp_path / JOURNAL_FILENAME).read_bytes()
        q = JournalCheckpointQuiescer(tmp_path)
        q.drain_bound_s = 0.05

        def _slow_review(gap, shared, config, review_fn, result_obj, **kw):
            time.sleep(0.4)
            return _mock_review_fn(
                gap, shared, config, review_fn, result_obj, **kw)

        wq = [_gap("a.py", f"f{i}", 0.9) for i in range(2)]
        graph = TaskGraph.from_workqueue(wq, [], max_workers=2)
        with caplog.at_level(
                logging.WARNING, logger="core.audit.journal_quiesce"):
            stats = _run_bounded(graph, _slow_review, q, max_workers=2)
        # The attempt was abandoned (journal untouched, loud warning,
        # cooldown armed) and dispatch resumed — the run completed.
        assert stats.completed == 2
        assert (tmp_path / JOURNAL_FILENAME).read_bytes() == before
        assert not (tmp_path / _BACKUP_NAME).exists()
        assert any(
            "drain timed out" in r.getMessage()
            for r in caplog.records
        )

    def test_hostile_state_record_never_crashes_executor(
        self, tmp_path: Path, monkeypatch,
    ) -> None:
        # An over-trigger journal plus a state record whose
        # freed_fraction is unformattable (probe vector: it selects
        # the advisory branch's % format) used to escape the poll as
        # a TypeError out of run_executor_sync. Both layers must
        # hold: _load_state rejects the record (trigger fires), and
        # should_attempt contains anything else — the paid run
        # completes either way.
        _compressible_journal(tmp_path)
        _arm(tmp_path, monkeypatch)
        (tmp_path / CHECKPOINT_STATE_FILENAME).write_text(json.dumps({
            "schema_version": 1, "max_shard_bytes_after": 2**40,
            "bytes_before": 1, "bytes_after": 1, "effective": False,
            "freed_fraction": None,
        }))
        q = JournalCheckpointQuiescer(tmp_path)
        wq = [_gap("a.py", f"f{i}", 0.9) for i in range(2)]
        graph = TaskGraph.from_workqueue(wq, [])
        stats = _run_bounded(graph, _mock_review_fn, q, max_workers=1)
        assert stats.completed == 2
        assert graph.pending == 0


_FORBIDDEN_IMPORT_PREFIXES = (
    "core.llm",
    "core.audit.joern_backend",
    "core.audit.prep_cache",
    "core.audit.orchestrator",
)

# The one sanctioned core.audit.executor name: the precondition
# guard's read-only inflight counter. Anything else from the executor
# module (dispatch, task graph, loops) is restart-priced machinery.
_ALLOWED_EXECUTOR_NAMES = {"review_work_inflight"}


def _module_imports(path: Path) -> tuple[set[str], set[str]]:
    """(imported module names, names imported from
    core.audit.executor) — top-level and function-local alike."""
    tree = ast.parse(path.read_text())
    mods: set[str] = set()
    executor_names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            mods |= {alias.name for alias in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module:
            if node.module == "core.audit.executor":
                executor_names |= {a.name for a in node.names}
            else:
                mods.add(node.module)
    return mods, executor_names


class TestNoRestartProperty:
    """Charter requirement 8: callgraph inspection AND spies."""

    def _fire(self, out: Path, monkeypatch) -> None:
        _compressible_journal(out)
        _arm(out, monkeypatch)
        outcome = JournalCheckpointQuiescer(out).run_quiesced()
        assert outcome is not None and outcome.fired

    def test_spies_joern_dispatcher_prep_untouched(
        self, tmp_path: Path, monkeypatch,
    ) -> None:
        import core.audit.joern_backend as joern_mod
        import core.audit.prep_cache as prep_mod
        import core.llm.dispatcher.lifecycle as lifecycle_mod
        import core.llm.dispatcher.spawn as spawn_mod

        calls: list[str] = []

        def _spy(name: str):
            def _record(*a, **k):
                calls.append(name)
                raise AssertionError(
                    f"checkpoint touched {name} — no-restart violated")
            return _record

        monkeypatch.setattr(
            joern_mod, "start_joern_server", _spy("joern.start"))
        monkeypatch.setattr(
            joern_mod, "stop_joern_server", _spy("joern.stop"))
        monkeypatch.setattr(
            lifecycle_mod, "dispatcher_for_run",
            _spy("dispatcher.for_run"))
        monkeypatch.setattr(
            lifecycle_mod, "ensure_inprocess_dispatcher_env",
            _spy("dispatcher.env"))
        monkeypatch.setattr(
            spawn_mod, "spawn_worker", _spy("dispatcher.spawn"))
        monkeypatch.setattr(
            prep_mod, "load_prep_cache", _spy("prep.load"))
        monkeypatch.setattr(
            prep_mod, "write_prep_cache", _spy("prep.write"))

        self._fire(tmp_path, monkeypatch)
        assert calls == []

    def test_filesystem_delta_confined_to_journal_family(
        self, tmp_path: Path, monkeypatch,
    ) -> None:
        # Decoy run-dir artifacts a restart-shaped checkpoint would
        # touch: prep caches, checklist, attack surface.
        (tmp_path / "prep-cache").mkdir()
        (tmp_path / "prep-cache" / "detectors.json").write_text("{}")
        (tmp_path / "checklist.json").write_text('{"files": []}')
        (tmp_path / "attack-surface.json").write_text("{}")
        _compressible_journal(tmp_path)
        _arm(tmp_path, monkeypatch)

        def _snapshot() -> dict[str, tuple[int, int]]:
            return {
                str(p.relative_to(tmp_path)):
                    (p.stat().st_size, p.stat().st_mtime_ns)
                for p in tmp_path.rglob("*") if p.is_file()
            }

        before = _snapshot()
        outcome = JournalCheckpointQuiescer(tmp_path).run_quiesced()
        assert outcome is not None and outcome.fired
        after = _snapshot()

        assert set(before) <= set(after), "checkpoint deleted files"
        changed = {
            name for name, sig in before.items()
            if after[name] != sig
        }
        created = set(after) - set(before)
        assert changed <= {JOURNAL_FILENAME}
        assert created <= {_BACKUP_NAME, CHECKPOINT_STATE_FILENAME}

    def test_import_census_checkpoint_modules(self) -> None:
        # The checkpoint modules cannot even NAME the restart-priced
        # subsystems: no import (top-level or function-local) of the
        # Joern lifecycle, the LLM dispatcher, or the prep caches.
        import core.audit.journal_quiesce as jq
        import core.coverage.journal_checkpoint as jcp
        for mod in (jcp, jq):
            imports, executor_names = _module_imports(Path(mod.__file__))
            offenders = {
                name for name in imports
                if any(
                    name == p or name.startswith(p + ".")
                    for p in _FORBIDDEN_IMPORT_PREFIXES
                )
            }
            assert not offenders, (
                f"{mod.__name__} imports {sorted(offenders)}"
            )
            assert executor_names <= _ALLOWED_EXECUTOR_NAMES, (
                f"{mod.__name__} imports executor machinery beyond "
                f"the read-only guard counter: "
                f"{sorted(executor_names - _ALLOWED_EXECUTOR_NAMES)}"
            )

    def test_prep_cache_hits_across_checkpoint(
        self, tmp_path: Path, monkeypatch,
    ) -> None:
        # Functional side of "the journal is not among any prep
        # fingerprint's inputs": an entry cached before the checkpoint
        # still hits after the journal was rewritten underneath it.
        from core.audit.prep_cache import (
            load_prep_cache,
            write_prep_cache,
        )
        _compressible_journal(tmp_path)
        write_prep_cache(
            tmp_path, "detectors.json", "fp-1", {"rows": [1, 2]},
            label="detectors",
        )
        _arm(tmp_path, monkeypatch)
        outcome = JournalCheckpointQuiescer(tmp_path).run_quiesced()
        assert outcome is not None and outcome.fired
        assert load_prep_cache(
            tmp_path, "detectors.json", "fp-1", label="detectors",
        ) == {"rows": [1, 2]}

    def test_prep_cache_doctrine_names_the_boundary(self) -> None:
        # The boundary statement the charter asks for lives in
        # core.audit.prep_cache's module doctrine: nothing derived
        # from per-segment state — the JOURNAL included — may be
        # cached, so no prep fingerprint can have the journal as an
        # input. Pin the sentence so a doctrine rewrite that drops
        # the journal from the exclusion list fails here.
        import core.audit.prep_cache as prep_mod
        doc = prep_mod.__doc__ or ""
        assert "per-segment state" in doc
        assert "journal" in doc
