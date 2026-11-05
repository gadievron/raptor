"""Malformed event rows are rejected without losing valid peers."""
import json

import pytest

from core.sandbox import telemetry_mac, triage


@pytest.mark.parametrize('field', ['host', 'result', 'resolved_ip'])
@pytest.mark.parametrize('value', [[], {}, 7, True])
@pytest.mark.parametrize('stamped', [False, True])
def test_bad_event_fields_preserve_valid_peers(field, value, stamped, monkeypatch):
    good = {'host': 'example.test', 'result': 'allowed', 'seq': 0}
    bad = {'host': 'bad.test', 'result': 'allowed', 'seq': 1, field: value}
    if stamped:
        good['mac'] = bad['mac'] = 'valid'
    monkeypatch.setattr(telemetry_mac, 'verify', lambda fields, token: token == 'valid')
    usable, rejected, integrity, _ = triage._verify_proxy_events(
        [good, bad], 'run', count_record={'count': 2, 'flags': [], 'mac': 'valid'})
    assert usable == [good]
    assert rejected == 1
    assert integrity == triage._INTEGRITY_TAMPERED


@pytest.mark.parametrize('row', [None, 7, [], {'host': []}])
def test_all_invalid_rows_are_tampered(row):
    usable, rejected, integrity, _ = triage._verify_proxy_events([row], 'run')
    assert usable == []
    assert rejected == 1
    assert integrity == triage._INTEGRITY_TAMPERED


def test_malformed_legacy_event_produces_report(tmp_path):
    (tmp_path / triage.PROXY_EVENTS_FILENAME).write_text(json.dumps({
        'host': ['bad'], 'result': 'denied_host',
    }) + '\n')
    report = triage.triage_run(tmp_path, allow_legacy=True)
    assert report is not None
    assert report['inputs']['integrity']['proxy_events'] == triage._INTEGRITY_TAMPERED


@pytest.mark.parametrize('with_count', [False, True])
def test_sequence_overflow_is_tampered(monkeypatch, with_count):
    monkeypatch.setattr(telemetry_mac, 'verify', lambda fields, token: True)
    event = {'host': 'example.test', 'result': 'allowed', 'seq': float('inf'), 'mac': 'valid'}
    count = {'count': 1, 'flags': [], 'mac': 'valid'} if with_count else None
    _, _, integrity, _ = triage._verify_proxy_events([event], 'run', count_record=count)
    assert integrity == triage._INTEGRITY_TAMPERED
