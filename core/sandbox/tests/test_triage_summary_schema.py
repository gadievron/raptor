"""Malformed summary counters and row containers cannot abort triage."""
import json

import pytest

from core.sandbox import telemetry_mac, triage


BAD_SUMMARIES = [
    [], 'summary', 7,
    {'corrupt_lines': 'bad'}, {'corrupt_lines': []},
    {'corrupt_lines': True}, {'corrupt_lines': -1},
    {'total_denials': '4'}, {'total_denials': None},
    {'total_denials': True}, {'total_denials': -1},
    {'denials': None}, {'denials': 7}, {'denials': {}},
    {'denials': 'rows'}, {'denials': [None]}, {'denials': [7]},
]


@pytest.mark.parametrize('summary', BAD_SUMMARIES)
@pytest.mark.parametrize('allow_legacy', [False, True])
def test_bad_summary_schema_is_rejected(summary, allow_legacy, monkeypatch):
    def unexpected(*args, **kwargs):
        pytest.fail('invalid summary reached MAC construction')

    monkeypatch.setattr(telemetry_mac, 'summary_fields', unexpected)
    if isinstance(summary, dict):
        summary = {**summary, 'mac': 'invalid'}
    assert triage._verify_summary(summary, 'run', allow_legacy=allow_legacy) == (
        None, triage._INTEGRITY_TAMPERED)


@pytest.mark.parametrize('bad', [
    {'total_denials': '4'}, {'denials': 7}, {'denials': [None]},
])
def test_unstamped_malformed_summary_still_produces_report(tmp_path, bad):
    (tmp_path / triage.SUMMARY_FILE).write_text(json.dumps(bad))
    report = triage.triage_run(tmp_path, allow_legacy=True)
    assert report is not None
    assert report['inputs']['integrity']['sandbox_summary'] == triage._INTEGRITY_TAMPERED


@pytest.mark.parametrize('stamped', [False, True])
def test_valid_empty_summary_remains_accepted(stamped, monkeypatch):
    summary = {'total_denials': 0, 'denials': []}
    if stamped:
        summary['mac'] = 'valid'
    monkeypatch.setattr(telemetry_mac, 'verify', lambda fields, token: token == 'valid')
    accepted, integrity = triage._verify_summary(summary, 'run')
    assert accepted == summary
    assert integrity == (triage._INTEGRITY_VERIFIED if stamped else triage._INTEGRITY_LEGACY)
