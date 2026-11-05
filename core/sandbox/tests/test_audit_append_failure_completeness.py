"""Recovered storage errors remain visible in completed audit capture."""
import json

import pytest

from core.sandbox import observe_profile as observe
from core.sandbox import seatbelt_audit as audit


@pytest.mark.parametrize('failures', [1, 2])
def test_failed_records_are_counted_in_summary_and_profile(tmp_path, monkeypatch, failures):
    original = audit._evidence_mod.EvidenceFile.write_record
    attempts = []

    def write(handle, record):
        attempts.append(record)
        if len(attempts) <= failures:
            return False
        return original(handle, record)

    monkeypatch.setattr(audit._evidence_mod.EvidenceFile, 'write_record', write)
    owner = audit.LogStreamer(tmp_path, observe_mode=True, observe_nonce='trusted')
    for index in range(failures + 1):
        owner._filter_and_append({'syscall': 'file-read-data', 'target_pid': 123,
                                  'path': f'/tmp/file-{index}', 'nonce': 'trusted',
                                  'observe': True})
    owner.stop()
    records = [json.loads(line) for line in
               (tmp_path / '.audit' / observe.OBSERVE_FILENAME).read_text().splitlines()]
    assert records[-1]['type'] == 'audit_summary'
    assert records[-1]['append_failures'] == failures
    assert records[-1]['reader_drained'] is True
    profile = observe.parse_observe_log(tmp_path, expected_nonce='trusted')
    assert profile.paths_read == [f'/tmp/file-{failures}']
    assert profile.capture_incomplete is True
    assert profile.budget_truncated is False
    owner.stop()
    assert len(attempts) == failures + 2


def test_open_failure_is_counted_before_recovery(tmp_path, monkeypatch):
    original = audit._evidence_mod.EvidenceFile.open
    calls = []

    def open_file(*args, **kwargs):
        calls.append(args)
        if len(calls) == 1:
            raise OSError('temporary open failure')
        return original(*args, **kwargs)

    monkeypatch.setattr(audit._evidence_mod.EvidenceFile, 'open', open_file)
    owner = audit.LogStreamer(tmp_path, observe_mode=True)
    owner._filter_and_append({'syscall': 'file-read-data', 'target_pid': 123,
                              'path': '/tmp/file', 'observe': True})
    owner.stop()
    assert owner._append_failures == 1
    profile = observe.parse_observe_log(tmp_path)
    assert profile.capture_incomplete is True


@pytest.mark.parametrize('value,expected', [(0, False), (1, True), (-1, False),
                                           (True, False), ('1', False), (None, False)])
def test_summary_failure_count_requires_positive_integer(tmp_path, value, expected):
    (tmp_path / observe.OBSERVE_FILENAME).write_text(json.dumps({
        'type': 'audit_summary', 'append_failures': value}) + '\n')
    assert observe.parse_observe_log(tmp_path).capture_incomplete is expected
