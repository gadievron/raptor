"""An earlier summary cannot vouch for later accepted capture records."""
import json

import pytest

from core.sandbox import observe_profile as observe


def parse(tmp_path, records):
    (tmp_path / observe.OBSERVE_FILENAME).write_text(''.join(json.dumps(record) + '\n' for record in records))
    return observe.parse_observe_log(tmp_path, expected_nonce='trusted', current_run=True)


def summary():
    return {'type': 'audit_summary', 'nonce': 'trusted'}


def event(nonce='trusted', **fields):
    return {'syscall': 'stat', 'path': '/tmp/file', 'nonce': nonce, **fields}


def test_summary_followed_by_accepted_record_is_incomplete(tmp_path):
    profile = parse(tmp_path, [summary(), event()])
    assert profile.paths_stat == ['/tmp/file']
    assert profile.capture_incomplete is True


def test_final_summary_reestablishes_tail_completion(tmp_path):
    profile = parse(tmp_path, [summary(), event(), summary()])
    assert profile.paths_stat == ['/tmp/file']
    assert profile.capture_incomplete is False


def test_foreign_nonce_after_summary_does_not_change_tail(tmp_path):
    assert parse(tmp_path, [event(), summary(), event('wrong')]).capture_incomplete is False


@pytest.mark.parametrize('nonce,expected', [('trusted', True), ('wrong', False)])
def test_ambiguous_record_tail_is_tracked_after_nonce_gate(tmp_path, nonce, expected):
    profile = parse(tmp_path, [summary(), event(nonce, parse_ambiguous=True)])
    assert profile.paths_stat == []
    assert profile.capture_incomplete is expected


def test_unknown_accepted_record_after_summary_is_not_completion(tmp_path):
    profile = parse(tmp_path, [summary(), {'type': 'future_record', 'nonce': 'trusted'}])
    assert profile.capture_incomplete is True


def test_ambiguous_summary_cannot_establish_tail_completion(tmp_path):
    ambiguous = {**summary(), 'parse_ambiguous': True}
    assert parse(tmp_path, [summary(), ambiguous]).capture_incomplete is True
