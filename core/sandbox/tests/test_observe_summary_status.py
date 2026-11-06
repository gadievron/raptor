"""Malformed capture-status metadata cannot attest a complete observation."""
import json

import pytest

from core.sandbox import evidence
from core.sandbox import observe_profile as observe
from core.testing.state_isolation import pin_user_state_dirs


@pytest.fixture(autouse=True)
def owned_state(tmp_path):
    with pytest.MonkeyPatch.context() as monkeypatch:
        pin_user_state_dirs(monkeypatch, tmp_path / 'state')
        monkeypatch.setenv('XDG_DATA_HOME', str(tmp_path / 'xdg'))
        yield


@pytest.fixture
def monkeypatch(owned_state):
    """Undo body patches before restoring the file-owned state."""
    with pytest.MonkeyPatch.context() as patch:
        yield patch


def tail(**fields):
    return {'type': 'audit_summary', 'nonce': 'trusted',
            'dropped_by_category': {'file-read': 2}, **fields}


def parse(run, summaries):
    path = evidence.evidence_write_path(run, observe.OBSERVE_FILENAME)
    path.parent.mkdir(mode=0o700, parents=True)
    events = [{'type': 'write', 'syscall': 'stat', 'path': '/first',
               'observe': True, 'nonce': 'trusted'},
              {'type': 'write', 'syscall': 'stat', 'path': '/last',
               'observe': True, 'nonce': 'trusted'}]
    path.write_text(''.join(json.dumps(row) + '\n' for row in [*events, *summaries]))
    return observe.parse_observe_log(run, expected_nonce='trusted', current_run=True)


BAD_STATUS = [
    (field, value) for field in ['reader_failed', 'reader_drained']
    for value in [None, 0, 1, 0.0, 'true', 'false', [], {}]
] + [('append_failures', value) for value in [
    None, False, True, -1, 0.0, 1.5, '0', '1', [], {}, float('nan'), float('inf')]]


@pytest.mark.parametrize('field,value', BAD_STATUS)
def test_malformed_status_preserves_data_but_marks_capture_incomplete(tmp_path, field, value):
    profile = parse(tmp_path / 'run', [tail(**{field: value})])
    assert profile.capture_incomplete is True
    assert profile.paths_stat == ['/first', '/last']
    assert profile.dropped_by_category == {'file-read': 2}
    assert profile.budget_truncated is True
    assert profile.nonce_trusted is True


@pytest.mark.parametrize('fields', [
    {}, {'reader_failed': False}, {'reader_drained': True}, {'append_failures': 0},
    {'reader_failed': False, 'reader_drained': True, 'append_failures': 0},
])
def test_legacy_omission_and_typed_clean_status_remain_complete(tmp_path, fields):
    profile = parse(tmp_path / 'run', [tail(**fields)])
    assert profile.capture_incomplete is False
    assert profile.paths_stat == ['/first', '/last']
    assert profile.dropped_by_category == {'file-read': 2}
    assert profile.budget_truncated is True


@pytest.mark.parametrize('field,value', [
    ('reader_failed', 'false'), ('reader_drained', 1), ('append_failures', -1),
])
def test_later_clean_tail_does_not_erase_invalid_status(tmp_path, field, value):
    profile = parse(tmp_path / 'run', [tail(**{field: value}),
                    tail(reader_failed=False, reader_drained=True, append_failures=0,
                         dropped_by_category={})])
    assert profile.capture_incomplete is True
    assert profile.dropped_by_category == {'file-read': 2}


@pytest.mark.parametrize('field,value', [
    ('reader_failed', 'false'), ('reader_drained', 1), ('append_failures', -1),
])
def test_unmatched_nonce_cannot_set_capture_state(tmp_path, field, value):
    profile = parse(tmp_path / 'run', [tail(nonce='wrong', **{field: value}),
                    tail(reader_failed=False, reader_drained=True, append_failures=0,
                         dropped_by_category={})])
    assert profile.capture_incomplete is False
    assert profile.dropped_by_category == {}
    assert profile.paths_stat == ['/first', '/last']


@pytest.mark.parametrize('fields', [
    {'reader_failed': True}, {'reader_drained': False}, {'append_failures': 2},
])
def test_explicit_capture_loss_stays_incomplete(tmp_path, fields):
    profile = parse(tmp_path / 'run', [tail(**fields)])
    assert profile.capture_incomplete is True
    assert profile.paths_stat == ['/first', '/last']
