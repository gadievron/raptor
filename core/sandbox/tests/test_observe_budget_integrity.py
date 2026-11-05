"""Accepted summaries cannot turn malformed drop accounting into completeness."""
import json

import pytest

from core.sandbox import evidence
from core.sandbox import observe_profile as observe
from core.testing.state_isolation import pin_user_state_dirs


@pytest.fixture(autouse=True)
def owned_state(tmp_path, monkeypatch):
    pin_user_state_dirs(monkeypatch, tmp_path / 'state')
    monkeypatch.setenv('XDG_DATA_HOME', str(tmp_path / 'xdg'))


def tail(**fields):
    return {'type': 'audit_summary', 'nonce': 'trusted', **fields}


def load(tmp_path, summary):
    run = tmp_path / 'run'
    path = evidence.evidence_write_path(run, observe.OBSERVE_FILENAME)
    path.parent.mkdir(parents=True)

    def opened(name):
        return {
            'ts': '2026-05-04T00:00:00Z', 'cmd': '<sandbox audit: openat>',
            'returncode': 0, 'type': 'write', 'observe': True,
            'syscall': 'openat', 'syscall_nr': 257, 'target_pid': 1234,
            'args': [-100, 0, 0, 0, 0, 0], 'path': name, 'nonce': 'trusted',
        }

    # A later clean tail must preserve any earlier accepted loss.
    records = [opened('/first'), summary, opened('/last'),
               tail(dropped_by_category={})]
    path.write_text(''.join(json.dumps(record) + '\n' for record in records))
    profile = observe.parse_observe_log(run, expected_nonce='trusted', current_run=True)
    assert profile.paths_read == ['/first', '/last']
    assert profile.nonce_trusted is True
    return profile


@pytest.mark.parametrize('value', [
    pytest.param(None, id='null'),
    pytest.param(False, id='boolean'),
    pytest.param(0, id='integer'),
    pytest.param([], id='empty-list'),
    pytest.param(['bad'], id='list'),
    pytest.param('', id='empty-string'),
    pytest.param('bad', id='string'),
])
def test_invalid_accounting_shape_is_incomplete(tmp_path, value):
    profile = load(tmp_path, tail(dropped_by_category=value))
    assert profile.capture_incomplete is True
    assert profile.budget_truncated is False
    assert profile.dropped_by_category == {}


@pytest.mark.parametrize('count', [
    pytest.param(True, id='boolean'),
    pytest.param(-1, id='negative'),
    pytest.param(0.5, id='fraction'),
    pytest.param('1', id='string'),
    pytest.param(None, id='null'),
    pytest.param(float('nan'), id='nan'),
    pytest.param(float('inf'), id='infinity'),
])
def test_invalid_count_retains_valid_counts_and_incomplete_state(tmp_path, count):
    profile = load(tmp_path, tail(dropped_by_category={'valid': 2, 'zero': 0, 'bad': count}))
    assert profile.capture_incomplete is True
    assert profile.budget_truncated is True
    assert profile.dropped_by_category == {'valid': 2, 'zero': 0}


def test_invalid_count_does_not_manufacture_budget_drops(tmp_path):
    profile = load(tmp_path, tail(dropped_by_category={'bad': None}))
    assert profile.capture_incomplete is True
    assert profile.budget_truncated is False
    assert profile.dropped_by_category == {}


@pytest.mark.parametrize('fields', [{}, {'dropped_by_category': {}}], ids=['legacy', 'empty'])
def test_missing_and_empty_accounting_stay_complete(tmp_path, fields):
    profile = load(tmp_path, tail(**fields))
    assert profile.capture_incomplete is False
    assert profile.budget_truncated is False
    assert profile.dropped_by_category == {}


def test_unmatched_nonce_cannot_set_accounting_loss(tmp_path):
    profile = load(tmp_path, tail(nonce='wrong', dropped_by_category=None))
    assert profile.capture_incomplete is False
    assert profile.budget_truncated is False
    assert profile.dropped_by_category == {}
