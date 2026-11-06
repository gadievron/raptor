"""Parent-known audit loss survives unavailable marker storage."""
import errno

import pytest

from core.sandbox import summary, triage
from core.testing.state_isolation import pin_user_state_dirs


@pytest.fixture(autouse=True)
def owned_state(tmp_path):
    with pytest.MonkeyPatch.context() as monkeypatch:
        pin_user_state_dirs(monkeypatch, tmp_path / 'state')
        monkeypatch.setenv('XDG_DATA_HOME', str(tmp_path / 'data'))
        monkeypatch.setattr(summary, '_degraded_markers', {})
        yield


@pytest.fixture
def monkeypatch(owned_state):
    """Undo body patches before restoring the file-owned state."""
    with pytest.MonkeyPatch.context() as patch:
        yield patch


@pytest.mark.parametrize('allow_legacy', [False, True], ids=['lifecycle', 'manual'])
@pytest.mark.parametrize('failure', [errno.ENOSPC, errno.EACCES, errno.EROFS],
                         ids=['full', 'denied', 'readonly'])
@pytest.mark.parametrize('phase', ['initial', 'deleted', 'altered'])
def test_parent_degradation_survives_marker_write_failure(
        tmp_path, monkeypatch, allow_legacy, failure, phase):
    run = tmp_path / 'run'
    run.mkdir()
    marker = run / summary.AUDIT_DEGRADED_FILE
    reason = 'audit source unavailable'

    def fail_marker_write(*args, **kwargs):
        raise OSError(failure, 'owned marker storage unavailable')

    if phase == 'initial':
        monkeypatch.setattr(summary, 'write_text_atomically', fail_marker_write)
    summary.record_audit_degraded(run, reason=reason)
    if phase == 'deleted':
        marker.unlink()
    elif phase == 'altered':
        marker.write_text('{}')
    monkeypatch.setattr(summary, 'write_text_atomically', fail_marker_write)

    for _ in range(2):
        report = triage.triage_run(run, allow_legacy=allow_legacy)
        assert report is not None
        assert report['audit_degraded'] is True
        assert any(reason in caveat for caveat in report['caveats'])
        tampered = any(s['type'] == 'telemetry_tampering' for s in report['signals'])
        assert tampered is (phase != 'initial')
        assert (run / triage.TRIAGE_FILE).is_file()


def test_absent_parent_record_still_produces_no_report(tmp_path):
    assert triage.triage_run(tmp_path, allow_legacy=False) is None


def test_parent_snapshot_is_independent_and_run_bound(tmp_path):
    summary.record_audit_degraded(tmp_path, reason='original')
    snapshot = summary.get_audit_degraded(tmp_path)
    assert snapshot['reason'] == 'original'
    snapshot['reason'] = 'modified'
    assert summary.get_audit_degraded(tmp_path)['reason'] == 'original'
    assert summary.get_audit_degraded(tmp_path / 'other') is None
