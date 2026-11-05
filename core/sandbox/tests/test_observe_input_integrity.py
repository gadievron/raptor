"""Damaged observe inputs retain loss without rewriting accepted records."""
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
    return {
        'ts': '2026-05-04T00:00:00Z', 'cmd': '<sandbox audit: openat>',
        'returncode': 0, 'type': 'write', 'observe': True,
        'syscall': 'openat', 'syscall_nr': 257, 'target_pid': 1234,
        'args': [-100, 0, 0, 0, 0, 0], 'path': path,
        'nonce': 'trusted', 'metadata': 'bad-note',
    }


def encoded(value):
    return json.dumps(value, ensure_ascii=False).encode('utf-8') + b'\n'


def tail():
    return encoded({'type': 'audit_summary', 'nonce': 'trusted',
                    'reader_failed': False, 'reader_drained': True,
                    'dropped_by_category': {}})


@pytest.mark.parametrize('field', ['path', 'metadata'])
@pytest.mark.parametrize('damaged', [
    pytest.param(b'\xff', id='invalid-start'),
    pytest.param(b'\xc3', id='truncated-sequence'),
    pytest.param(b'\xed\xa0\x80', id='surrogate'),
])
def test_bad_utf8_is_loss_and_valid_neighbors_survive(tmp_path, field, damaged):
    run = tmp_path / 'run'
    path = evidence.evidence_write_path(run, observe.OBSERVE_FILENAME)
    path.parent.mkdir(parents=True)
    bad = encoded(record('/discard'))
    needle = b'/discard' if field == 'path' else b'bad-note'
    bad = bad.replace(needle, b'bad-' + damaged)
    path.write_bytes(encoded(record('/first')) + bad + encoded(record('/last')) + tail())
    profile = observe.parse_observe_log(run, expected_nonce='trusted', current_run=True)
    assert profile.paths_read == ['/first', '/last']
    assert profile.capture_incomplete is True
    assert profile.budget_truncated is False
    assert profile.nonce_trusted is True


@pytest.mark.parametrize('name', [
    pytest.param('snowman \u2603', id='unicode'),
    pytest.param('replacement \ufffd', id='literal-replacement'),
    pytest.param('separator \u2028', id='separator'),
])
def test_valid_unicode_remains_complete(tmp_path, name):
    run = tmp_path / 'run'
    path = evidence.evidence_write_path(run, observe.OBSERVE_FILENAME)
    path.parent.mkdir(parents=True)
    expected = '/' + name
    path.write_bytes(encoded(record(expected)) + tail())
    profile = observe.parse_observe_log(run, expected_nonce='trusted', current_run=True)
    assert profile.paths_read == [expected]
    assert profile.capture_incomplete is False
    assert profile.budget_truncated is False


@pytest.mark.parametrize('location', ['canonical', 'legacy'])
@pytest.mark.parametrize('shape', ['dangling', 'loop'])
def test_unreadable_link_is_incomplete_offline_input(tmp_path, location, shape):
    run = tmp_path / 'run'
    run.mkdir()
    canonical = evidence.evidence_write_path(run, observe.OBSERVE_FILENAME)
    legacy = evidence.legacy_read_path(run, observe.OBSERVE_FILENAME)
    path = canonical if location == 'canonical' else legacy
    path.parent.mkdir(parents=True, exist_ok=True)
    path.symlink_to(run / 'missing' if shape == 'dangling' else path)
    if location == 'canonical':
        legacy.write_bytes(encoded(record('/older')) + tail())
    profile = observe.parse_observe_log(run, expected_nonce='trusted')
    assert profile.paths_read == []
    assert profile.capture_incomplete is True
    assert profile.budget_truncated is False
    assert path.is_symlink()
