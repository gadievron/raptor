"""Filesystem-byte metadata remains stampable without changing old MAC bytes."""
import os

import pytest

from core.sandbox import summary, telemetry_mac as mac, triage
from core.testing.state_isolation import pin_user_state_dirs


@pytest.fixture(autouse=True)
def owned_state(tmp_path, monkeypatch):
    pin_user_state_dirs(monkeypatch, tmp_path / 'state')
    monkeypatch.setenv('XDG_DATA_HOME', str(tmp_path / 'data'))
    monkeypatch.setattr(summary, '_degraded_markers', {})


@pytest.mark.parametrize('value', [
    pytest.param('path-\udcff', id='filesystem-byte'),
    pytest.param('high-\ud800', id='high-surrogate'),
    pytest.param('pair-\ud800\udc00', id='surrogate-pair'),
])
def test_metadata_can_be_minted_and_verified(value):
    fields = {'kind': 'test', 'detail': value}
    token = mac.mint(fields)
    assert token is not None
    assert mac.verify(fields, token)
    assert not mac.verify({**fields, 'detail': value + '!'}, token)


@pytest.mark.skipif(os.name != 'posix', reason='requires POSIX filesystem bytes')
@pytest.mark.parametrize('location', ['run', 'reason'])
def test_audit_degradation_with_filesystem_bytes(tmp_path, location):
    name = os.fsdecode(b'run-\xff') if location == 'run' else 'run'
    reason = os.fsdecode(b'unavailable-\xff') if location == 'reason' else 'audit unavailable'
    run = tmp_path / name
    run.mkdir()
    summary.record_audit_degraded(run, reason=reason)
    report = triage.triage_run(run, allow_legacy=False)
    assert report['audit_degraded'] is True
    assert report['inputs']['integrity']['audit_degraded'] == 'verified'
    assert triage.verify_triage_report(report, run) == 'verified'
    assert (run / summary.AUDIT_DEGRADED_FILE).is_file()
    assert (run / triage.TRIAGE_FILE).is_file()


@pytest.mark.parametrize('value', ['ascii', 'caf\u00e9', '\U00010000'],
                         ids=['ascii', 'unicode', 'scalar'])
def test_existing_utf8_canonical_bytes_are_unchanged(value):
    fields = {'kind': 'test', 'detail': value}
    items = sorted(fields.items())
    expected = len(items).to_bytes(4, 'big')
    for key, item in items:
        for part in (key.encode('utf-8'), item.encode('utf-8')):
            expected += len(part).to_bytes(4, 'big') + part
    assert mac._canonical(fields) == expected


@pytest.mark.parametrize('left,right', [
    pytest.param('\ud800\udc00', '\U00010000', id='pair-and-scalar'),
    pytest.param('\udcc3\udca9', '\u00e9', id='escaped-bytes-and-scalar'),
    pytest.param('\udcff', '\ufffd', id='escaped-byte-and-replacement'),
])
def test_surrogate_metadata_has_distinct_canonical_bytes(left, right):
    left_fields = {'kind': 'test', 'detail': left}
    right_fields = {'kind': 'test', 'detail': right}
    assert mac._canonical(left_fields) != mac._canonical(right_fields)
    token = mac.mint(left_fields)
    assert token is not None
    assert not mac.verify(right_fields, token)
