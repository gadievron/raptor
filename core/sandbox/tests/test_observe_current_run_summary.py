"""Current-run completeness requires an accepted end-of-capture summary."""
import json

import pytest

from core.sandbox import observe_profile as observe


def write_log(tmp_path, records):
    (tmp_path / observe.OBSERVE_FILENAME).write_text(''.join(json.dumps(r) + '\n' for r in records))


@pytest.mark.parametrize('current_run', [False, True])
def test_records_without_summary_preserve_data_and_report_current_loss(tmp_path, current_run):
    write_log(tmp_path, [{'syscall': 'stat', 'path': '/tmp/file', 'nonce': 'trusted'}])
    profile = observe.parse_observe_log(tmp_path, expected_nonce='trusted', current_run=current_run)
    assert profile.paths_stat == ['/tmp/file']
    assert profile.capture_incomplete is current_run
    assert profile.budget_truncated is False


@pytest.mark.parametrize('records', [[], [{'syscall': 'stat', 'path': '/tmp/file', 'nonce': 'trusted'}]])
def test_accepted_summary_establishes_completion(tmp_path, records):
    write_log(tmp_path, records + [{'type': 'audit_summary', 'nonce': 'trusted'}])
    profile = observe.parse_observe_log(tmp_path, expected_nonce='trusted', current_run=True)
    assert profile.capture_incomplete is False


def test_wrong_nonce_summary_cannot_establish_completion(tmp_path):
    write_log(tmp_path, [{'syscall': 'stat', 'path': '/tmp/file', 'nonce': 'trusted'},
                         {'type': 'audit_summary', 'nonce': 'wrong'}])
    profile = observe.parse_observe_log(tmp_path, expected_nonce='trusted', current_run=True)
    assert profile.paths_stat == ['/tmp/file']
    assert profile.capture_incomplete is True


@pytest.mark.parametrize('exists', [False, True])
def test_missing_or_empty_current_log_is_incomplete(tmp_path, exists):
    if exists:
        write_log(tmp_path, [])
    profile = observe.parse_observe_log(tmp_path, expected_nonce='trusted', current_run=True)
    assert profile.capture_incomplete is True
    assert observe.parse_observe_log(tmp_path).capture_incomplete is False


def test_summary_does_not_clear_existing_capture_failure(tmp_path):
    write_log(tmp_path, [{'type': 'audit_summary', 'nonce': 'trusted', 'reader_failed': True}])
    assert observe.parse_observe_log(tmp_path, expected_nonce='trusted', current_run=True).capture_incomplete is True
