"""Malformed count-sidecar schemas must not abort triage."""
import json

import pytest

from core.sandbox import telemetry_mac, triage
from core.sandbox.proxy import PROXY_EVENTS_COUNT_FILENAME


BAD_RECORDS = [
    [], 'wrong', 7,
    {'count': True, 'flags': []}, {'count': -1, 'flags': []},
    {'count': '0', 'flags': []}, {'count': 0, 'flags': 7},
    {'count': 0, 'flags': 'failure'}, {'count': 0, 'flags': {'x': 1}},
    {'count': 0, 'flags': [7]}, {'count': 0, 'flags': None},
]


@pytest.mark.parametrize('record', BAD_RECORDS)
def test_bad_schema_rejected_before_mac(record, monkeypatch):
    def unexpected(*args):
        pytest.fail('malformed schema reached MAC canonicalization')

    monkeypatch.setattr(telemetry_mac, 'proxy_events_count_fields', unexpected)
    usable, rejected, integrity, note = triage._verify_proxy_events(
        [], 'run', allow_legacy=False, count_record=record)
    assert usable == []
    assert rejected == 0
    assert integrity == triage._INTEGRITY_TAMPERED
    assert 'malformed' in note


def test_invalid_flags_produce_report(tmp_path, monkeypatch):
    monkeypatch.setenv('XDG_DATA_HOME', str(tmp_path / 'keys'))
    (tmp_path / PROXY_EVENTS_COUNT_FILENAME).write_text(json.dumps({
        'count': 0, 'flags': 7, 'mac': 'invalid',
    }))
    report = triage.triage_run(tmp_path, allow_legacy=False)
    assert report is not None
    assert 'malformed' in json.dumps(report)


@pytest.mark.parametrize('flags', [[], ['persist_write_failure']])
def test_valid_schema_still_verifies(flags, monkeypatch):
    monkeypatch.setattr(telemetry_mac, 'verify', lambda fields, token: token == 'valid')
    _, _, integrity, note = triage._verify_proxy_events(
        [], 'run', allow_legacy=False,
        count_record={'count': 0, 'flags': flags, 'mac': 'valid'})
    assert integrity == (triage._INTEGRITY_TAMPERED if flags else triage._INTEGRITY_VERIFIED)
    assert bool(note) == bool(flags)
