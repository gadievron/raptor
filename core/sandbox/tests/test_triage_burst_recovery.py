"""Bad timestamps cannot suppress a burst established by valid peers."""
import json

import pytest

from core.sandbox import triage


def row(ts):
    return {'type': 'seccomp', 'syscall': 'ptrace', 'ts': ts}


@pytest.mark.parametrize('bad', ['invalid', [], {}, 10 ** 400, float('nan'), float('inf'), True])
@pytest.mark.parametrize('first', [False, True])
def test_valid_burst_survives_bad_peer(bad, first):
    valid = [row(i / 10) for i in range(triage._ESCAPE_BURST_COUNT)]
    records = [row(bad), *valid] if first else [*valid, row(bad)]
    signals = triage._check_escape_burst(records)
    assert len(signals) == 1
    assert signals[0]['count'] == len(valid)


def test_bad_timestamps_do_not_fill_threshold():
    records = [row(0)] * (triage._ESCAPE_BURST_COUNT - 1) + [row('invalid')] * 10
    assert triage._check_escape_burst(records) == []


def test_valid_nonburst_stays_nonburst():
    records = [row(i * (triage._ESCAPE_BURST_WINDOW_SECS + 1))
               for i in range(triage._ESCAPE_BURST_COUNT)]
    assert triage._check_escape_burst([row('invalid'), *records]) == []


def test_report_keeps_burst_signal_with_invalid_peer(tmp_path):
    records = [row('invalid')] + [row(i / 10) for i in range(triage._ESCAPE_BURST_COUNT)]
    (tmp_path / triage.SUMMARY_FILE).write_text(json.dumps({
        'total_denials': len(records), 'denials': records,
    }))
    report = triage.triage_run(tmp_path, allow_legacy=True)
    signal = next(s for s in report['signals'] if s['type'] == 'escape_burst')
    assert signal['count'] == triage._ESCAPE_BURST_COUNT
