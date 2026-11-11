"""Run deadlines bound checkpoint drain and study parking without rewriting journals."""
from types import SimpleNamespace

import pytest

from core.audit.journal_quiesce import JournalCheckpointQuiescer
from core.audit.tests.test_journal_quiesce import _arm, _compressible_journal
from core.coverage.journal import JOURNAL_FILENAME
import core.audit.journal_quiesce as module


def test_expired_run_preserves_journal(tmp_path, monkeypatch):
    _compressible_journal(tmp_path)
    _arm(tmp_path, monkeypatch)
    path = tmp_path / JOURNAL_FILENAME
    before = path.read_bytes()
    q = JournalCheckpointQuiescer(tmp_path)
    # Stamp the same absolute run deadline before entering the boundary.
    q.deadline_monotonic = module.time.monotonic() - 1
    result = q.run_at_boundary("run-expiry")
    assert result is not None and result.aborted
    assert result.reason == "run deadline reached"
    assert path.read_bytes() == before
    assert not list(tmp_path.glob("*.pre-supersede"))


def test_study_park_uses_remaining_run_budget_and_releases_pause(tmp_path, monkeypatch):
    _compressible_journal(tmp_path)
    _arm(tmp_path, monkeypatch)
    path = tmp_path / JOURNAL_FILENAME
    before = path.read_bytes()
    clock = [100.0]
    monkeypatch.setattr(module, "time", SimpleNamespace(monotonic=lambda: clock[0]))
    events = []
    class Study:
        consumer_done = False
        def request_pause(self):
            events.append("pause")
        def wait_quiescent(self, timeout):
            events.append(timeout)
            clock[0] += timeout
            return False
        def resume_from_pause(self):
            events.append("resume")
    q = JournalCheckpointQuiescer(tmp_path, study_queue=Study(), deadline_monotonic=100.25)
    assert q.drain_deadline() == 100.25
    result = q.run_quiesced()
    assert events == ["pause", pytest.approx(.25), "resume"]
    assert result is not None and result.aborted
    assert result.reason == "run deadline reached"
    assert path.read_bytes() == before


def test_unbounded_run_keeps_existing_drain_allowance(tmp_path, monkeypatch):
    monkeypatch.setattr(module, "time", SimpleNamespace(monotonic=lambda: 100.0))
    q = JournalCheckpointQuiescer(tmp_path)
    assert q.drain_deadline() == 100.0 + q.drain_bound_s
