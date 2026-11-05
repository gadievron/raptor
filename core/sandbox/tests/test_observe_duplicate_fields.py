"""Duplicate members remain capture loss instead of normalized observations."""
import json

import pytest

from core.sandbox import evidence
from core.sandbox import observe_profile as observe
from core.testing.state_isolation import pin_user_state_dirs


@pytest.fixture(autouse=True)
def owned_state(tmp_path, monkeypatch):
    pin_user_state_dirs(monkeypatch, tmp_path / 'state')
    monkeypatch.setenv('XDG_DATA_HOME', str(tmp_path / 'xdg'))


def record(path):
    return {'ts': '2026-11-05T00:00:00Z', 'cmd': '<sandbox audit: stat>',
            'returncode': 0, 'type': 'write', 'observe': True,
            'syscall': 'stat', 'syscall_nr': 4, 'target_pid': 1234,
            'args': [0, 0, 0, 0, 0, 0], 'path': path, 'nonce': 'trusted'}


def tail():
    return {'type': 'audit_summary', 'nonce': 'trusted', 'reader_failed': False,
            'reader_drained': True, 'append_failures': 0, 'dropped_by_category': {}}


def duplicate(value, field, earlier):
    return '{' + json.dumps(field) + ':' + json.dumps(earlier) + ',' + json.dumps(value)[1:]


def write_log(run, lines, canonical=True):
    path = (evidence.evidence_write_path(run, observe.OBSERVE_FILENAME) if canonical else
            evidence.legacy_read_path(run, observe.OBSERVE_FILENAME))
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.write_text('\n'.join(lines) + '\n')


@pytest.mark.parametrize('canonical', [False, True], ids=['legacy', 'canonical'])
@pytest.mark.parametrize('field', ['path', 'nonce', 'type', 'syscall', 'nested', 'escaped'])
def test_ambiguous_record_is_lost_without_hiding_neighbors(tmp_path, canonical, field):
    run = tmp_path / 'run'
    rec = record('/discard')
    if field == 'nested':
        bad = json.dumps(rec)[:-1] + ',"metadata":{"detail":1,"detail":1}}'
    elif field == 'escaped':
        bad = '{"pa\\u0074h":"/earlier",' + json.dumps(rec)[1:]
    else:
        earlier = {'path': '/earlier', 'nonce': 'wrong', 'type': 'audit_summary',
                   'syscall': 'openat'}[field]
        bad = duplicate(rec, field, earlier)
    write_log(run, [json.dumps(record('/first')), bad, json.dumps(record('/last')),
                    json.dumps(tail())], canonical=canonical)
    profile = observe.parse_observe_log(run, expected_nonce='trusted', current_run=True)
    assert profile.paths_stat == ['/first', '/last']
    assert profile.paths_read == []
    assert profile.capture_incomplete is True
    assert profile.nonce_trusted is True
    assert profile.budget_truncated is False


@pytest.mark.parametrize('field,earlier', [('reader_failed', True), ('nonce', 'wrong')])
def test_ambiguous_summary_cannot_attest_completion(tmp_path, field, earlier):
    run = tmp_path / 'run'
    write_log(run, [json.dumps(record('/first')), duplicate(tail(), field, earlier)])
    profile = observe.parse_observe_log(run, expected_nonce='trusted', current_run=True)
    assert profile.paths_stat == ['/first']
    assert profile.capture_incomplete is True
    assert profile.budget_truncated is False


@pytest.mark.parametrize('metadata', [
    {'left': {'detail': 1}, 'right': {'detail': 2}},
    {'items': [{'detail': 1}, {'detail': 2}]},
    {'\u00e9': 1, 'e\u0301': 2},
])
def test_unique_objects_stay_complete(tmp_path, metadata):
    run = tmp_path / 'run'
    rec = {**record('/valid'), 'metadata': metadata}
    write_log(run, [json.dumps(rec), json.dumps(tail())])
    profile = observe.parse_observe_log(run, expected_nonce='trusted', current_run=True)
    assert profile.paths_stat == ['/valid']
    assert profile.capture_incomplete is False


def test_unique_escaped_key_stays_complete(tmp_path):
    run = tmp_path / 'run'
    line = json.dumps(record('/valid')).replace('"path"', '"pa\\u0074h"')
    write_log(run, [line, json.dumps(tail())])
    profile = observe.parse_observe_log(run, expected_nonce='trusted', current_run=True)
    assert profile.paths_stat == ['/valid']
    assert profile.capture_incomplete is False
