"""A failed checkpoint park retires the study queue's pause request."""

import time

import pytest

from core.audit import journal_quiesce as quiesce
from core.audit.orchestrator import StudyQueue
from core.audit.tests.test_journal_quiesce import (
    _arm, _compressible_journal, _request,
)
from core.coverage.journal import JOURNAL_FILENAME


@pytest.mark.parametrize("failure_type", [OSError, MemoryError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("resume_fails", [False, True])
def test_failed_wait_releases_pause_and_preserves_primary(
    tmp_path, monkeypatch, failure_type, resume_fails,
):
    _compressible_journal(tmp_path)
    _arm(tmp_path, monkeypatch)
    before = (tmp_path / JOURNAL_FILENAME).read_bytes()
    queue = StudyQueue()
    queue.set_working(True)
    failure = failure_type("owned condition-wait failure")
    reached = []
    resumes = []
    real_wait = queue._not_empty.wait
    real_resume = queue.resume_from_pause

    def fail_wait(*args, **kwargs):
        assert queue._pause_requested and queue._working
        real_wait(timeout=0)
        reached.append("condition_wait")
        raise failure

    def resume():
        real_resume()
        resumes.append("resume")
        if resume_fails:
            raise KeyboardInterrupt("secondary pause-retirement failure")

    def unexpected_checkpoint(*args, **kwargs):
        pytest.fail("checkpoint cannot start before the park succeeds")

    monkeypatch.setattr(queue._not_empty, "wait", fail_wait)
    monkeypatch.setattr(queue, "resume_from_pause", resume)
    monkeypatch.setattr(quiesce, "checkpoint_journal", unexpected_checkpoint)
    coordinator = quiesce.JournalCheckpointQuiescer(tmp_path, study_queue=queue)
    try:
        if issubclass(failure_type, Exception):
            assert coordinator.run_quiesced() is None
            assert coordinator._cooldown_until > time.monotonic()
        else:
            with pytest.raises(failure_type) as raised:
                coordinator.run_quiesced()
            assert raised.value is failure
        assert reached == ["condition_wait"] and resumes == ["resume"]
        assert not queue._pause_requested
        assert (tmp_path / JOURNAL_FILENAME).read_bytes() == before
        queue.set_working(False)
        request = _request()
        queue.enqueue(request)
        assert queue.dequeue_batch(timeout=0) == [request]
    finally:
        real_resume()
        queue.set_working(False)


@pytest.mark.parametrize("failure_type", [OSError, KeyboardInterrupt])
def test_pause_request_after_effect_failure_is_retired(tmp_path, monkeypatch, failure_type):
    _compressible_journal(tmp_path)
    _arm(tmp_path, monkeypatch)
    queue = StudyQueue()
    real_pause = queue.request_pause
    failure = failure_type("owned pause notification failure")
    reached = []

    def pause():
        real_pause()
        assert queue._pause_requested
        reached.append("pause")
        raise failure

    monkeypatch.setattr(queue, "request_pause", pause)
    coordinator = quiesce.JournalCheckpointQuiescer(tmp_path, study_queue=queue)
    try:
        if issubclass(failure_type, Exception):
            assert coordinator.run_quiesced() is None
        else:
            with pytest.raises(failure_type) as raised:
                coordinator.run_quiesced()
            assert raised.value is failure
        assert reached == ["pause"] and not queue._pause_requested
    finally:
        queue.resume_from_pause()
