"""In-flight denials cannot migrate into another active-run lifecycle."""
import json
import threading
from unittest.mock import Mock

import pytest

from core.sandbox import summary
from core.sandbox import state

from core.testing.sandbox_state_scope import isolated_summary_state


@pytest.fixture(autouse=True)
def isolated_state(monkeypatch):
    with isolated_summary_state():
        try:
            summary.set_active_run_dir(None)
            monkeypatch.setattr(state, '_cli_sandbox_disabled', False)
            monkeypatch.setattr(summary, '_log_security_event', Mock())
            yield
            summary.set_active_run_dir(None)
        finally:
            monkeypatch.undo()


@pytest.mark.parametrize('transition', ['different', 'same', 'clear'])
def test_transition_during_serialization_prevents_stale_append(tmp_path, monkeypatch, transition):
    first, second = tmp_path / 'first', tmp_path / 'second'
    first.mkdir()
    second.mkdir()
    summary.set_active_run_dir(first)
    destination = second if transition == 'different' else first if transition == 'same' else None
    original = summary.dumps_artifact

    def serialize(record, **kwargs):
        summary.set_active_run_dir(destination)
        return original(record, **kwargs)

    with monkeypatch.context() as scoped:
        scoped.setattr(summary, 'dumps_artifact', serialize)
        summary.record_denial('stale command', 1, 'write', path='/tmp/stale')
    assert summary._denial_count == 0
    assert summary._evidence_handle is None
    assert not list(tmp_path.rglob(summary.DENIALS_FILE))
    if destination is not None:
        summary.record_denial('current command', 1, 'write', path='/tmp/current')
        assert summary._denial_count == 1
        evidence = destination / '.audit' / summary.DENIALS_FILE
        records = [json.loads(line) for line in evidence.read_text().splitlines()]
        assert [record['cmd'] for record in records] == ['current command']


def test_threaded_transition_does_not_append_to_new_run_handle(tmp_path, monkeypatch):
    first, second = tmp_path / 'first', tmp_path / 'second'
    first.mkdir()
    second.mkdir()
    summary.set_active_run_dir(first)
    entered, release = threading.Event(), threading.Event()
    original = summary.dumps_artifact
    errors = []

    def serialize(record, **kwargs):
        if record['cmd'] == 'stale command':
            entered.set()
            assert release.wait(timeout=5)
        return original(record, **kwargs)

    def record():
        try:
            summary.record_denial('stale command', 1, 'write')
        except BaseException as exc:
            errors.append(exc)

    monkeypatch.setattr(summary, 'dumps_artifact', serialize)
    worker = threading.Thread(target=record)
    worker.start()
    try:
        assert entered.wait(timeout=5)
        summary.set_active_run_dir(second)
        summary.record_denial('current command', 1, 'write')
    finally:
        release.set()
        worker.join(timeout=5)
    assert not worker.is_alive()
    assert not errors
    assert summary._denial_count == 1
    evidence = second / '.audit' / summary.DENIALS_FILE
    records = [json.loads(line) for line in evidence.read_text().splitlines()]
    assert [record['cmd'] for record in records] == ['current command']
    assert not (first / '.audit' / summary.DENIALS_FILE).exists()
