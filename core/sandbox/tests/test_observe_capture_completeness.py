"""Reader loss stays visible independently of audit budget accounting."""
import json

import pytest

from core.sandbox import observe_cli as cli
from core.sandbox import observe_profile as observe


@pytest.mark.parametrize('flags,expected', [
    ({'reader_failed': True}, True),
    ({'reader_drained': False}, True),
    ({'reader_failed': True, 'reader_drained': True}, True),
    ({'reader_failed': False, 'reader_drained': True}, False),
    ({}, False),
    ({'reader_failed': 'true', 'reader_drained': 0}, True),
])
def test_summary_capture_state_is_typed_and_separate(tmp_path, flags, expected):
    record = {'type': 'audit_summary', 'nonce': 'trusted', 'dropped_by_category': {}, **flags}
    (tmp_path / observe.OBSERVE_FILENAME).write_text(json.dumps(record) + '\n')
    profile = observe.parse_observe_log(tmp_path, expected_nonce='trusted')
    assert profile.capture_incomplete is expected
    assert profile.budget_truncated is False
    assert profile.dropped_by_category == {}


def test_unmatched_nonce_cannot_set_capture_state(tmp_path):
    (tmp_path / observe.OBSERVE_FILENAME).write_text(json.dumps({
        'type': 'audit_summary', 'nonce': 'wrong', 'reader_failed': True}) + '\n')
    assert observe.parse_observe_log(tmp_path, expected_nonce='trusted').capture_incomplete is False


def test_clean_later_summary_does_not_erase_failure(tmp_path):
    records = [{'type': 'audit_summary', 'reader_failed': True},
               {'type': 'audit_summary', 'reader_drained': True}]
    (tmp_path / observe.OBSERVE_FILENAME).write_text(''.join(json.dumps(r) + '\n' for r in records))
    assert observe.parse_observe_log(tmp_path).capture_incomplete is True


@pytest.mark.parametrize('first,second', [(False, False), (True, False), (False, True), (True, True)])
def test_profile_merge_preserves_incomplete_state(first, second):
    left = observe.ObserveProfile(capture_incomplete=first)
    right = observe.ObserveProfile(capture_incomplete=second)
    left.merge(right)
    assert left.capture_incomplete is (first or second)
    assert right.capture_incomplete is second


@pytest.mark.parametrize('incomplete', [False, True])
def test_cli_text_and_json_expose_capture_state(tmp_path, incomplete):
    profile = observe.ObserveProfile(capture_incomplete=incomplete)
    text = cli._format_summary(profile, run_dir=tmp_path, kept=True, return_code=0)
    payload = json.loads(cli._profile_to_json(profile, run_dir=tmp_path, kept=True, return_code=0))
    assert ('audit capture INCOMPLETE' in text) is incomplete
    assert payload['capture_incomplete'] is incomplete
    assert payload['budget_truncated'] is False
