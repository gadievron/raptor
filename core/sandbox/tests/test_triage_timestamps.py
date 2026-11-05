"""Offset-aware and malformed timestamps cannot derail burst triage."""
import json

import pytest

from core.sandbox import triage


def rows(times):
    return [{'type': 'seccomp', 'syscall': 'ptrace', 'ts': ts} for ts in times]


def test_timezone_offsets_preserve_instants():
    utc = triage._parse_ts('2026-01-01T00:00:00+00:00')
    assert triage._parse_ts('2026-01-01T02:00:00+02:00') == utc
    assert triage._parse_ts('2025-12-31T19:00:00-05:00') == utc
    assert triage._parse_ts('2026-01-01T00:00:00') == utc


def test_burst_across_different_offsets():
    times = ['2026-01-01T00:00:00+00:00', '2026-01-01T02:00:01+02:00',
             '2025-12-31T19:00:02-05:00']
    records = rows((times * triage._ESCAPE_BURST_COUNT)[:triage._ESCAPE_BURST_COUNT])
    assert triage._check_escape_burst(records)


def test_same_clock_time_different_instants_is_not_burst():
    records = rows([f'2026-01-01T12:00:00+0{i}:00' for i in range(triage._ESCAPE_BURST_COUNT)])
    assert triage._check_escape_burst(records) == []


@pytest.mark.parametrize('ts', [10 ** 400, float('inf'), float('-inf'), float('nan'), True])
def test_invalid_timestamp_does_not_abort_report(tmp_path, ts):
    summary = {'total_denials': triage._ESCAPE_BURST_COUNT,
               'denials': rows([ts] * triage._ESCAPE_BURST_COUNT)}
    (tmp_path / triage.SUMMARY_FILE).write_text(json.dumps(summary))
    report = triage.triage_run(tmp_path, allow_legacy=True)
    assert report is not None
    assert any(s['type'] == 'escape_primitive_denied' for s in report['signals'])
    assert not any(s['type'] == 'escape_burst' for s in report['signals'])


def test_platform_timestamp_failure_is_local_to_burst(monkeypatch):
    def fail(ts):
        raise OSError('timestamp outside platform range')

    monkeypatch.setattr(triage, '_parse_ts', fail)
    assert triage._check_escape_burst(rows([0] * triage._ESCAPE_BURST_COUNT)) == []


@pytest.mark.parametrize('ts', [float('inf'), float('-inf'), float('nan'), True])
def test_nonfinite_and_boolean_values_are_rejected(ts):
    with pytest.raises(ValueError):
        triage._parse_ts(ts)
