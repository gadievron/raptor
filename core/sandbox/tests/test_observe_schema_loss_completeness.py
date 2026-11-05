"""Skipped malformed and unattributable records remain visible as losses."""
import json

import pytest

from core.sandbox import observe_profile as observe


def parse(tmp_path, record):
    records = [{'syscall': 'stat', 'path': '/tmp/valid', 'nonce': 'trusted'}, record,
               {'type': 'audit_summary', 'nonce': 'trusted'}]
    (tmp_path / observe.OBSERVE_FILENAME).write_text(''.join(json.dumps(r) + '\n' for r in records))
    return observe.parse_observe_log(tmp_path, expected_nonce='trusted', current_run=True)


@pytest.mark.parametrize('record', [None, [], 7, 'record'])
def test_nonobject_records_do_not_hide_valid_observations(tmp_path, record):
    profile = parse(tmp_path, record)
    assert profile.paths_stat == ['/tmp/valid']
    assert profile.capture_incomplete is True
    assert profile.budget_truncated is False


@pytest.mark.parametrize('name', [None, [], {}, 7, ''])
def test_explicit_invalid_syscall_field_marks_incomplete(tmp_path, name):
    profile = parse(tmp_path, {'syscall': name, 'path': '/tmp/bad', 'nonce': 'trusted'})
    assert profile.paths_stat == ['/tmp/valid']
    assert profile.capture_incomplete is True


@pytest.mark.parametrize('path', [[], {}, 7, True])
def test_invalid_path_field_marks_incomplete(tmp_path, path):
    profile = parse(tmp_path, {'syscall': 'stat', 'path': path, 'nonce': 'trusted'})
    assert profile.paths_stat == ['/tmp/valid']
    assert profile.capture_incomplete is True


@pytest.mark.parametrize('nonce,expected', [('trusted', True), ('foreign', False)])
def test_ambiguous_record_loss_survives_final_summary(tmp_path, nonce, expected):
    profile = parse(tmp_path, {'syscall': 'stat', 'path': '/tmp/ambiguous',
                               'nonce': nonce, 'parse_ambiguous': True})
    assert profile.paths_stat == ['/tmp/valid']
    assert profile.capture_incomplete is expected


def test_foreign_nonce_invalid_fields_do_not_mark_capture_loss(tmp_path):
    profile = parse(tmp_path, {'syscall': [], 'path': {}, 'nonce': 'foreign'})
    assert profile.capture_incomplete is False


def test_control_metadata_without_syscall_remains_supported(tmp_path):
    profile = parse(tmp_path, {'type': 'category_budget_exceeded', 'nonce': 'trusted'})
    assert profile.capture_incomplete is False
