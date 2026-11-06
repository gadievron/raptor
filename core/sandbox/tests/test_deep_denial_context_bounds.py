"""Denial context keeps capped commands and only usable timestamp metadata."""
from datetime import datetime, timezone
import json

import pytest

from core.sandbox import summary, telemetry_mac as mac, triage, triage_deep as deep
from core.sandbox.tests.test_triage_deep import _FakeClient
from core.testing.state_isolation import pin_user_state_dirs


UTC = '2026-11-06T12:00:00+00:00'


@pytest.fixture(autouse=True)
def owned_state(tmp_path, monkeypatch):
    pin_user_state_dirs(monkeypatch, tmp_path / 'state')
    monkeypatch.setenv('XDG_DATA_HOME', str(tmp_path / 'data'))


def write_summary(run, cmd='owned-command', stamp=UTC, *, signed=False):
    records = [{'type': 'write', 'path': '/tmp/owned', 'cmd': cmd, 'ts': stamp}]
    payload = {'run_dir': str(run), 'total_denials': 1, 'by_type': {'write': 1},
               'denials': records}
    if signed:
        payload['mac'] = mac.mint(mac.summary_fields(
            1, triage._denials_sha256(records), mac.run_binding(run)))
        assert payload['mac']
    path = run / summary.SUMMARY_FILE
    path.write_text(json.dumps(payload) + '\n')
    return path


@pytest.mark.parametrize('pattern', ['x', '\x1b', '\u2603', 'x\0\u2603\t', '\udcff'],
                         ids=['plain', 'escape', 'unicode', 'mixed', 'surrogate'])
@pytest.mark.parametrize('length', [299, 300, 2000], ids=['under', 'exact', 'over'])
def test_command_escaping_only_processes_the_visible_prefix(tmp_path, monkeypatch, pattern, length):
    command = (pattern * ((length + len(pattern) - 1) // len(pattern)))[:length]
    path = write_summary(tmp_path, command, signed=True)
    original_bytes = path.read_bytes()
    original_escape = deep.escape_nonprintable
    expected = original_escape(command)[:300]
    lengths = []

    def escape(value):
        lengths.append(len(value))
        return original_escape(value)

    monkeypatch.setattr(deep, 'escape_nonprintable', escape)
    lines = deep._denial_context(tmp_path)
    assert lines == [f'[t={UTC}] ' + expected]
    assert max(lengths) <= 300
    assert path.read_bytes() == original_bytes


@pytest.mark.parametrize('stamp', [True, False, [], {'not': 'a timestamp'}, 'not-a-time',
                                  '\x1b[31mnot-a-time', float('nan'), float('inf'),
                                  10 ** 400, 1e300],
                         ids=['true', 'false', 'array', 'object', 'invalid-string',
                              'control-string', 'nan', 'infinity', 'overflow', 'out-of-range'])
def test_malformed_timestamp_does_not_hide_command_or_claim_a_time(tmp_path, stamp):
    path = write_summary(tmp_path, stamp=stamp)
    original_bytes = path.read_bytes()
    assert deep._denial_context(tmp_path, allow_legacy=True) == ['owned-command']
    assert path.read_bytes() == original_bytes


@pytest.mark.parametrize('stamp,expected_epoch', [
    pytest.param(UTC, datetime(2026, 11, 6, 12, tzinfo=timezone.utc).timestamp(), id='utc'),
    pytest.param('2026-11-06T13:00:00+01:00', datetime(2026, 11, 6, 12, tzinfo=timezone.utc).timestamp(), id='offset'),
    pytest.param('2026-11-06T12:00:00', datetime(2026, 11, 6, 12, tzinfo=timezone.utc).timestamp(), id='naive'),
    pytest.param(0, 0.0, id='epoch-zero'),
    pytest.param(1.5, 1.5, id='fractional-epoch'),
    pytest.param('2026-11-06T12:00:00.125000+00:00', datetime(2026, 11, 6, 12, 0, 0, 125000, tzinfo=timezone.utc).timestamp(), id='fractional-iso'),
])
def test_supported_timestamps_keep_their_instant(tmp_path, stamp, expected_epoch):
    write_summary(tmp_path, stamp=stamp, signed=True)
    line = deep._denial_context(tmp_path)[0]
    assert line.endswith(' owned-command')
    displayed = line[3:line.index(']')]
    try:
        actual_epoch = float(displayed)
    except ValueError:
        parsed = datetime.fromisoformat(displayed)
        actual_epoch = parsed.replace(tzinfo=timezone.utc).timestamp() if parsed.tzinfo is None else parsed.timestamp()
    assert actual_epoch == expected_epoch


@pytest.mark.parametrize('stamp', [
    '2026-11-06T12:00:00.' + '125000' + '0' * 2000 + '+00:00',
    '2026-11-06\x1b12:00:00.125000+00:00',
], ids=['long-fraction', 'control-separator'])
def test_valid_nonstandard_timestamp_is_bounded_and_inert(tmp_path, stamp):
    write_summary(tmp_path, stamp=stamp, signed=True)
    line = deep._denial_context(tmp_path)[0]
    assert len(line) <= 337
    assert '\x1b' not in line
    assert line.endswith(' owned-command')


def test_missing_timestamp_and_default_provenance_gate_are_preserved(tmp_path):
    write_summary(tmp_path, stamp=None)
    assert deep._denial_context(tmp_path) == []
    assert deep._denial_context(tmp_path, allow_legacy=True) == ['owned-command']


def test_full_advisory_uses_clean_context_without_modifying_evidence(tmp_path):
    evidence = write_summary(tmp_path, stamp={'not-timestamp': 'unusable'}, signed=True)
    evidence_bytes = evidence.read_bytes()
    rules = {'run_dir': str(tmp_path), 'verdict': 'notable',
             'signals': [{'type': 'volume_anomaly', 'severity': 'medium',
                          'count': 1, 'evidence': ['owned signal']}],
             'inputs': {}, 'caveats': []}
    rules_path = tmp_path / triage.TRIAGE_FILE
    triage._write(rules_path, rules)
    rules_bytes = rules_path.read_bytes()
    client = _FakeClient(json.dumps({'assessments': [{
        'signal_type': 'volume_anomaly', 'judgement': 'unclear',
        'confidence': 0.5, 'rationale': 'owned advice'}]}))
    result = deep.deep_analyse(tmp_path, client=client)
    assert len(client.calls) == 1
    assert 'owned-command' in client.calls[0]['user']
    assert 'not-timestamp' not in client.calls[0]['user']
    assert evidence.read_bytes() == evidence_bytes
    assert rules_path.read_bytes() == rules_bytes
    assert result['rules_verdict'] == 'notable'
    assert deep.verify_deep_report(result, tmp_path) == 'verified'


@pytest.mark.parametrize('stamp', ['0001-01-01T00:00:00.000001+00:00',
                                  '9999-12-31T23:59:59.999999+00:00'],
                         ids=['minimum-year', 'maximum-year'])
def test_iso_extremes_preserve_microseconds_without_float_roundtrip(tmp_path, stamp):
    write_summary(tmp_path, stamp=stamp, signed=True)
    line = deep._denial_context(tmp_path)[0]
    displayed = line[3:line.index(']')]
    assert datetime.fromisoformat(displayed) == datetime.fromisoformat(stamp)
