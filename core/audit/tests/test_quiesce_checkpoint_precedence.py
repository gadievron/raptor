"""Checkpoint errors keep precedence over study-resume failures."""
import logging

import pytest

from core.audit import journal_quiesce as quiesce
from core.audit.orchestrator import StudyQueue
from core.audit.tests.test_journal_quiesce import _arm, _compressible_journal
from core.coverage.journal import JOURNAL_FILENAME
from core.coverage.journal_checkpoint import CHECKPOINT_STATE_FILENAME


@pytest.mark.parametrize("primary_type", [OSError, MemoryError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("cleanup_type", [OSError, SystemExit])
def test_checkpoint_failure_survives_resume_failure(
    tmp_path, monkeypatch, caplog, primary_type, cleanup_type,
):
    _compressible_journal(tmp_path)
    _arm(tmp_path, monkeypatch)
    before = (tmp_path / JOURNAL_FILENAME).read_bytes()
    queue = StudyQueue()
    real_resume = queue.resume_from_pause
    primary = primary_type("owned checkpoint failure")
    reached = []

    def abort():
        assert queue._pause_requested
        reached.append("checkpoint_abort")
        raise primary

    def resume():
        real_resume()
        reached.append("resumed")
        raise cleanup_type("secondary resume failure")

    monkeypatch.setattr(queue, "resume_from_pause", resume)
    coordinator = quiesce.JournalCheckpointQuiescer(
        tmp_path, study_queue=queue, should_abort=abort,
    )
    try:
        with caplog.at_level(logging.WARNING, logger="core.audit.journal_quiesce"):
            if issubclass(primary_type, Exception):
                assert coordinator.run_quiesced() is None
                errors = [r.exc_info[1] for r in caplog.records if r.exc_info]
                assert errors == [primary]
            else:
                with pytest.raises(primary_type) as raised:
                    coordinator.run_quiesced()
                assert raised.value is primary
        assert reached == ["checkpoint_abort", "resumed"]
        assert not queue._pause_requested
        assert (tmp_path / JOURNAL_FILENAME).read_bytes() == before
    finally:
        real_resume()


@pytest.mark.parametrize("cleanup_type", [OSError, KeyboardInterrupt])
def test_fresh_resume_failure_keeps_existing_policy(tmp_path, monkeypatch, caplog, cleanup_type):
    _compressible_journal(tmp_path)
    _arm(tmp_path, monkeypatch)
    queue = StudyQueue()
    real_resume = queue.resume_from_pause
    failure = cleanup_type("fresh resume failure")
    reached = []

    def resume():
        real_resume()
        reached.append("resumed")
        raise failure

    monkeypatch.setattr(queue, "resume_from_pause", resume)
    coordinator = quiesce.JournalCheckpointQuiescer(tmp_path, study_queue=queue)
    try:
        with caplog.at_level(logging.WARNING, logger="core.audit.journal_quiesce"):
            if issubclass(cleanup_type, Exception):
                assert coordinator.run_quiesced() is None
                errors = [r.exc_info[1] for r in caplog.records if r.exc_info]
                assert errors == [failure]
            else:
                with pytest.raises(cleanup_type) as raised:
                    coordinator.run_quiesced()
                assert raised.value is failure
        assert reached == ["resumed"] and not queue._pause_requested
        assert (tmp_path / CHECKPOINT_STATE_FILENAME).exists()
    finally:
        real_resume()
