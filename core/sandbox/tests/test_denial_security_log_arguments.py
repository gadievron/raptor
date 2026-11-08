"""Denial details cannot collide with the security logger's arguments."""
import json

import pytest

from core.sandbox import summary
from core.sandbox import state

from core.testing.sandbox_state_scope import isolated_summary_state


@pytest.fixture(autouse=True)
def active_run(tmp_path, monkeypatch):
    with isolated_summary_state():
        try:
            monkeypatch.setattr(state, '_cli_sandbox_disabled', False)
            summary.set_active_run_dir(tmp_path)
            yield
            summary.set_active_run_dir(None)
        finally:
            monkeypatch.undo()


@pytest.mark.parametrize('details', [
    {'message': 'detail message'},
    {'event_type': 'detail event'},
    {'message': 'detail message', 'event_type': 'detail event', 'path': '/tmp/file'},
])
def test_logger_argument_names_remain_in_evidence(tmp_path, monkeypatch, details):
    mirrored = []

    # Match the actual logger's signature so duplicate argument binding is tested.
    def log_security_event(event_type, message, **kwargs):
        mirrored.append((event_type, message, kwargs))

    monkeypatch.setattr(summary, '_log_security_event', log_security_event)
    summary.record_denial('command', 1, 'write', **details)
    evidence = tmp_path / '.audit' / summary.DENIALS_FILE
    record = json.loads(evidence.read_text())
    for key, value in details.items():
        assert record[key] == value
    assert record['type'] == 'write'
    assert len(mirrored) == 1
    event_type, message, fields = mirrored[0]
    assert event_type == 'sandbox_denial'
    assert message == 'sandbox denied write: command'
    assert fields['denial_type'] == 'write'
    assert fields['returncode'] == 1
    assert 'message' not in fields and 'event_type' not in fields
    if 'path' in details:
        assert fields['path'] == details['path']


def test_existing_reserved_evidence_fields_keep_authoritative_values(tmp_path, monkeypatch):
    mirrored = []

    def log_security_event(event_type, message, **kwargs):
        mirrored.append(kwargs)

    monkeypatch.setattr(summary, '_log_security_event', log_security_event)
    summary.record_denial('command', 1, 'write', type='wrong', cmd='wrong')
    record = json.loads((tmp_path / '.audit' / summary.DENIALS_FILE).read_text())
    assert record['type'] == 'write'
    assert record['cmd'] == 'command'
    assert 'type' not in mirrored[0] and 'cmd' not in mirrored[0]
