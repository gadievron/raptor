"""Study-suppression livelock regressions.

The async executor holds tasks whose concepts the study queue lists as
pending. A review completing AFTER the study consumer's exit could
re-populate that pending set with concepts nobody would ever study, and
the all-work-held wait then cycled forever: ``_release_held``'s
consumer-done branch released everything, ``_check_suppression``
re-held it against the zombie pending set — zero CPU, no dispatch, no
exit. Three independent guards close it (each proven here on its own
seam), plus a stall watchdog for hold/release variants the guards
don't know about:

* ``StudyQueue.enqueue`` latches after ``signal_consumer_done`` — a
  post-exit question can no longer create pending concepts;
* ``signal_consumer_done`` folds the still-pending concepts into the
  studied set — a later re-ask of a concept the consumer never
  resolved is dropped by the existing studied-check;
* ``_check_suppression`` never holds once the consumer is done —
  release is permanent even against an injected zombie pending set;
* the all-held stall watchdog force-releases an unchanged held set
  once the consumer provably cannot make progress.

Every executor-driving test runs the executor on a worker thread with
a hard join timeout, so a livelock regression fails the test instead
of wedging the pytest session.
"""

from __future__ import annotations

import threading
from typing import Any
from unittest.mock import MagicMock

import pytest

from core.audit.executor import ExecutorConfig, run_executor_sync
from core.audit.orchestrator import StudyQueue, StudyRequest
from core.audit.task_graph import TaskGraph
from core.audit.tests.test_executor import (
    _FakeResult,
    _gap,
    _mock_review_fn,
)

# Fast wait cycles: the production 30s all-held wait would make each
# watchdog cycle a wall-clock sleep.
_FAST_WAIT_S = 0.05
# Generous hard bound for "the executor completed" — a livelock
# regression parks forever, so any finite completion is decisive.
_JOIN_TIMEOUT_S = 30.0

_ZOMBIE_QUESTION = "what is zombie_concept?"
_ZOMBIE = "zombie_concept"


class _ConceptIndex:
    """Maps the held function to the zombie concept."""

    def __init__(self, mapping: dict[str, set[str]]) -> None:
        self._mapping = mapping

    def concepts_for(self, file: str, name: str) -> frozenset:
        return frozenset(self._mapping.get(f"{file}:{name}", set()))


def _request(question: str = _ZOMBIE_QUESTION) -> StudyRequest:
    return StudyRequest(
        question=question,
        source_file="a.py",
        source_function="producer",
    )


def _run_executor_bounded(
    graph: TaskGraph,
    study_queue: StudyQueue,
    concept_index: _ConceptIndex,
    review_one_fn: Any,
) -> Any:
    """Run the async executor on a worker thread with a join bound.

    Returns the ExecutorStats. Fails the test (rather than wedging the
    session) if the executor does not finish — the livelock's
    signature.
    """
    shared = MagicMock()
    shared.triage_results = {}
    config = MagicMock()
    config.llm_client = None
    result = _FakeResult()
    box: dict[str, Any] = {}

    def _run() -> None:
        box["stats"] = run_executor_sync(
            graph, MagicMock(), shared, config, result,
            ExecutorConfig(max_workers=2),
            review_one_fn=review_one_fn,
            study_queue=study_queue,
            concept_index_ref=[concept_index],
        )

    worker = threading.Thread(target=_run, daemon=True)
    worker.start()
    worker.join(timeout=_JOIN_TIMEOUT_S)
    assert not worker.is_alive(), (
        "executor did not complete — study-suppression livelock"
    )
    return box["stats"]


@pytest.fixture
def fast_wait(monkeypatch) -> None:
    import core.audit.executor as executor_mod
    monkeypatch.setattr(executor_mod, "_ALL_HELD_WAIT_S", _FAST_WAIT_S)


class TestStudyQueueTerminalStates:
    """Unit seams: the two StudyQueue-side guards."""

    def test_enqueue_latches_after_consumer_done(self) -> None:
        sq = StudyQueue()
        sq.signal_consumer_done()
        sq.enqueue(_request())
        assert sq.pending_concepts() == frozenset()
        assert sq.dequeue_batch(timeout=0.01) == []

    def test_consumer_done_folds_pending_into_studied(self) -> None:
        # A concept still pending at consumer exit is terminal: the
        # fold makes the studied-set drop-check refuse later re-asks
        # even if the consumer-done latch were bypassed (mutation
        # independence — reset the latch and re-ask).
        sq = StudyQueue()
        sq.enqueue(_request())
        assert _ZOMBIE in sq.pending_concepts()
        sq.signal_consumer_done()
        assert sq.pending_concepts() == frozenset()
        sq._consumer_done = False  # bypass the latch deliberately
        sq.enqueue(_request())
        assert sq.pending_concepts() == frozenset()
        # Only the pre-done item sits in the queue — the re-ask was
        # dropped by the studied-set check, not merely de-pended.
        assert len(sq.dequeue_batch(timeout=0.01)) == 1
        assert sq.dequeue_batch(timeout=0.01) == []

    def test_enqueue_before_done_still_queues(self) -> None:
        # Healthy direction: the latch must not affect a live consumer.
        sq = StudyQueue()
        sq.enqueue(_request())
        assert _ZOMBIE in sq.pending_concepts()
        batch = sq.dequeue_batch(timeout=0.01)
        assert len(batch) == 1
        assert batch[0].question == _ZOMBIE_QUESTION


class TestLivelockRepro:
    """The field sequence: consumer exits early, a still-running
    review enqueues a re-ask of a never-resolved concept, and a held
    task must not be re-held forever."""

    def test_post_done_reask_does_not_wedge_held_task(
        self, fast_wait,
    ) -> None:
        # producer completes normally; held references the zombie
        # concept and is suppressed at initial dispatch (pending is
        # non-empty from a prior segment's unresolved question).
        wq = [_gap("a.py", "producer", 0.9), _gap("a.py", "held", 0.5)]
        graph = TaskGraph.from_workqueue(wq, [], max_workers=2)
        sq = StudyQueue()
        sq.enqueue(_request())  # the never-resolved question
        ci = _ConceptIndex({"a.py:held": {_ZOMBIE}})
        reviewed: list[str] = []

        def review(gap, shared, config, review_fn, result_obj, **kw):
            reviewed.append(gap["name"])
            if gap["name"] == "producer":
                # The consumer's early exit (stale batches) races
                # ahead of this review's completion...
                sq.signal_consumer_done()
                # ...and the review's reading list re-asks the
                # never-resolved question afterwards.
                sq.enqueue(_request())
            return _mock_review_fn(
                gap, shared, config, review_fn, result_obj, **kw)

        stats = _run_executor_bounded(graph, sq, ci, review)
        assert stats.completed == 2
        assert sorted(reviewed) == ["held", "producer"]
        assert graph.pending == 0

    def test_injected_zombie_after_done_releases_permanently(
        self, fast_wait, caplog,
    ) -> None:
        # Mutation independence for the suppression-side guard: the
        # zombie pending set is injected PAST both StudyQueue guards
        # (directly into the pending set after consumer-done), so only
        # ``_check_suppression`` honouring consumer_done can finish the
        # run WITHOUT the stall watchdog firing — the watchdog-silence
        # assertion below is what pins this seam (a watchdog rescue
        # completes the run but logs its force-release at ERROR).
        wq = [_gap("a.py", "producer", 0.9), _gap("a.py", "held", 0.5)]
        graph = TaskGraph.from_workqueue(wq, [], max_workers=2)
        sq = StudyQueue()
        sq.enqueue(_request())
        ci = _ConceptIndex({"a.py:held": {_ZOMBIE}})

        def review(gap, shared, config, review_fn, result_obj, **kw):
            if gap["name"] == "producer":
                sq.signal_consumer_done()
                with sq._not_empty:
                    sq._pending_concepts.add(_ZOMBIE)
            return _mock_review_fn(
                gap, shared, config, review_fn, result_obj, **kw)

        with caplog.at_level("ERROR", logger="core.audit.executor"):
            stats = _run_executor_bounded(graph, sq, ci, review)
        assert stats.completed == 2
        assert graph.pending == 0
        assert not any(
            "force-releasing" in rec.message for rec in caplog.records
        )


class TestStallWatchdog:
    """The livelock breaker for hold variants the consumer-done guards
    don't cover: an idle consumer (alive, empty queue, no progress)
    with an unchanged held set force-releases after N wait cycles."""

    def test_idle_consumer_zombie_force_released(
        self, fast_wait, caplog,
    ) -> None:
        wq = [_gap("a.py", "producer", 0.9), _gap("a.py", "held", 0.5)]
        graph = TaskGraph.from_workqueue(wq, [], max_workers=2)
        sq = StudyQueue()
        # Zombie pending concept with NO queue item and NO consumer:
        # nothing will ever study it, and consumer_done is False so
        # the release path cannot fire.
        with sq._not_empty:
            sq._pending_concepts.add(_ZOMBIE)
        ci = _ConceptIndex({"a.py:held": {_ZOMBIE}})
        reviewed: list[str] = []

        def review(gap, shared, config, review_fn, result_obj, **kw):
            reviewed.append(gap["name"])
            return _mock_review_fn(
                gap, shared, config, review_fn, result_obj, **kw)

        with caplog.at_level("ERROR", logger="core.audit.executor"):
            stats = _run_executor_bounded(graph, sq, ci, review)
        assert stats.completed == 2
        assert "held" in reviewed
        assert any(
            "force-releasing" in rec.message for rec in caplog.records
        ), "stall watchdog did not announce the force-release"

    def test_watchdog_silent_on_healthy_study_release(
        self, fast_wait, caplog,
    ) -> None:
        # Healthy direction: a live consumer studying the concept
        # releases the held task through the normal path — no
        # force-release, no ERROR line.
        wq = [_gap("a.py", "producer", 0.9), _gap("a.py", "held", 0.5)]
        graph = TaskGraph.from_workqueue(wq, [], max_workers=2)
        sq = StudyQueue()
        sq.enqueue(_request())
        ci = _ConceptIndex({"a.py:held": {_ZOMBIE}})

        def review(gap, shared, config, review_fn, result_obj, **kw):
            if gap["name"] == "producer":
                # The consumer resolves the concept mid-run.
                batch = sq.dequeue_batch(timeout=0.01)
                assert batch
                sq.mark_studied({_ZOMBIE})
            return _mock_review_fn(
                gap, shared, config, review_fn, result_obj, **kw)

        with caplog.at_level("ERROR", logger="core.audit.executor"):
            stats = _run_executor_bounded(graph, sq, ci, review)
        assert stats.completed == 2
        assert graph.pending == 0
        assert not any(
            "force-releasing" in rec.message for rec in caplog.records
        ), "watchdog fired on a healthy study release"
