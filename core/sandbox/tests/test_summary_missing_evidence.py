"""A detected missing evidence inode must survive summary finalization."""
import json

import pytest

from core.sandbox import summary, telemetry_mac, triage

from core.testing.sandbox_state_scope import isolated_summary_state


@pytest.fixture(autouse=True)
def isolated_run(tmp_path, monkeypatch):
    with isolated_summary_state():
        try:
            monkeypatch.setenv('XDG_DATA_HOME', str(tmp_path / 'keys'))
            summary.set_active_run_dir(None)
            monkeypatch.setattr(summary, '_floor_refusals', {})
            monkeypatch.setattr(summary, '_evidence_inode_mismatches', {}, raising=False)
            monkeypatch.setattr(summary, '_cli_disables', {})
            yield
            summary.set_active_run_dir(None)
        finally:
            monkeypatch.undo()


def test_missing_held_evidence_produces_flagged_summary(tmp_path):
    summary.set_active_run_dir(tmp_path)
    summary.record_denial('test command', 1, 'write', path='/outside/example')
    handle = summary._evidence_handle
    assert handle is not None
    handle.path.unlink()
    result = summary.summarize_and_write(tmp_path)
    assert result is not None
    assert result['inode_mismatch'] is True
    assert result['total_denials'] == 0
    assert handle._closed
    assert summary._evidence_handle is None
    persisted = json.loads((tmp_path / summary.SUMMARY_FILE).read_text())
    assert persisted['inode_mismatch'] is True
    report = triage.triage_run(tmp_path, allow_legacy=False)
    assert report['inputs']['integrity']['sandbox_summary'] == triage._INTEGRITY_TAMPERED


def test_flagged_empty_summary_has_verifiable_binding(tmp_path):
    summary.set_active_run_dir(tmp_path)
    summary.record_denial('test command', 1, 'network', host='example.test')
    summary._evidence_handle.path.unlink()
    result = summary.summarize_and_write(tmp_path)
    assert result is not None
    fields = telemetry_mac.summary_fields(
        0, triage._denials_sha256([]), telemetry_mac.run_binding(tmp_path),
        inode_mismatch=True,
    )
    assert telemetry_mac.verify(fields, result['mac'])


def test_never_created_evidence_still_has_no_summary(tmp_path):
    summary.set_active_run_dir(tmp_path)
    assert summary.summarize_and_write(tmp_path) is None
    assert not (tmp_path / summary.SUMMARY_FILE).exists()


def test_run_switch_keeps_missing_inode_result(tmp_path):
    summary.set_active_run_dir(tmp_path)
    summary.record_denial('test command', 1, 'network', host='example.test')
    summary._evidence_handle.path.unlink()
    summary.set_active_run_dir(None)
    result = summary.summarize_and_write(tmp_path)
    assert result is not None
    assert result['inode_mismatch'] is True


def test_summary_write_failure_can_retry_missing_evidence(tmp_path, monkeypatch):
    summary.set_active_run_dir(tmp_path)
    summary.record_denial('test command', 1, 'network', host='example.test')
    summary._evidence_handle.path.unlink()

    def fail_write(*args, **kwargs):
        raise OSError('summary storage unavailable')

    with monkeypatch.context() as scoped:
        scoped.setattr(summary, 'write_text_atomically', fail_write)
        assert summary.summarize_and_write(tmp_path) is None
    result = summary.summarize_and_write(tmp_path)
    assert result is not None
    assert result['inode_mismatch'] is True


def test_inode_failure_is_scoped_to_its_run(tmp_path):
    first, second = tmp_path / 'first', tmp_path / 'second'
    first.mkdir()
    second.mkdir()
    summary.set_active_run_dir(first)
    summary.record_denial('test command', 1, 'network', host='example.test')
    summary._evidence_handle.path.unlink()
    summary.set_active_run_dir(second)
    assert summary.summarize_and_write(second) is None
    assert summary.summarize_and_write(first)['inode_mismatch'] is True
