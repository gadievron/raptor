"""Discarded JSONL records and failed reads remain visible in triage."""
import json
import os

import pytest

from core.sandbox import triage


pytestmark = pytest.mark.usefixtures('private_triage_readers')


GOOD = {'host': 'example.test', 'result': 'allowed'}


@pytest.mark.parametrize('bad,reason', [
    (b'{bad}\n', 'malformed_record'),
    (b'[]\n', 'nonobject_record'),
    (b'x' * 100 + b'\n', 'oversized_record'),
])
@pytest.mark.parametrize('chunk_size', [3, 1024])
def test_loss_is_reported_and_valid_peer_survives(tmp_path, monkeypatch, bad, reason, chunk_size):
    path = tmp_path / triage.PROXY_EVENTS_FILENAME
    path.write_bytes(bad + json.dumps(GOOD).encode() + b'\n')
    monkeypatch.setattr(triage, '_MAX_EVENT_LINE_BYTES', 80)
    original = os.read
    monkeypatch.setattr(triage.os, 'read', lambda fd, size: original(fd, min(size, chunk_size)))
    issues = set()
    assert triage._load_jsonl_stream(path, issues=issues) == ([GOOD], False)
    assert issues == {reason}
    report = triage.triage_run(tmp_path, allow_legacy=True)
    assert report['inputs']['total_proxy_events'] == 1
    assert report['inputs']['integrity']['proxy_events'] == triage._INTEGRITY_TAMPERED
    assert reason in json.dumps(report)


def test_read_error_preserves_prefix_and_reports_loss(tmp_path, monkeypatch):
    path = tmp_path / triage.PROXY_EVENTS_FILENAME
    payload = json.dumps(GOOD).encode() + b'\n'
    path.write_bytes(payload + payload)
    original = os.read
    calls = 0

    def fail_after_prefix(fd, size):
        nonlocal calls
        calls += 1
        if calls > 1:
            raise OSError('read interrupted by I/O failure')
        return original(fd, min(size, len(payload)))

    monkeypatch.setattr(triage.os, 'read', fail_after_prefix)
    issues = set()
    assert triage._load_jsonl_stream(path, issues=issues) == ([GOOD], False)
    assert issues == {'read_failure'}


@pytest.mark.parametrize('legacy', [False, True])
def test_only_discarded_records_still_produce_report(tmp_path, legacy):
    (tmp_path / triage.PROXY_EVENTS_FILENAME).write_bytes(b'[]\n')
    report = triage.triage_run(tmp_path, allow_legacy=legacy)
    assert report is not None
    assert report['inputs']['integrity']['proxy_events'] == triage._INTEGRITY_TAMPERED
    assert 'nonobject_record' in json.dumps(report)


def test_absent_and_blank_streams_are_not_parse_loss(tmp_path):
    path = tmp_path / triage.PROXY_EVENTS_FILENAME
    issues = set()
    assert triage._load_jsonl_stream(path, issues=issues) == ([], False)
    path.write_bytes(b' \n\n')
    assert triage._load_jsonl_stream(path, issues=issues) == ([], False)
    assert issues == set()
