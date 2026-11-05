"""Repeated integrity failures cannot erase already published forensic records."""
import json

import pytest

from core.sandbox import evidence, summary


@pytest.fixture(autouse=True)
def isolated_run(tmp_path, monkeypatch):
    monkeypatch.setenv('XDG_DATA_HOME', str(tmp_path / 'keys'))
    summary.set_active_run_dir(None)
    monkeypatch.setattr(summary, '_evidence_inode_mismatches', {})
    monkeypatch.setattr(summary, '_evidence_write_failures', {})
    monkeypatch.setattr(summary, '_floor_refusals', {})
    monkeypatch.setattr(summary, '_cli_disables', {})
    yield
    summary.set_active_run_dir(None)


def deny(cmd='test command'):
    summary.record_denial(cmd, 1, 'network', host='example.test')


@pytest.mark.parametrize('deactivate', [False, True])
def test_repeated_inode_failure_keeps_completed_summary(tmp_path, deactivate):
    summary.set_active_run_dir(tmp_path)
    deny()
    path = summary._evidence_handle.path
    path.unlink()
    path.write_text(json.dumps({'type': 'network', 'cmd': 'surviving forensic record'}) + '\n')
    first = summary.summarize_and_write(tmp_path)
    assert first['inode_mismatch'] is True
    assert first['total_denials'] == 1
    output = tmp_path / summary.SUMMARY_FILE
    before = output.read_bytes()

    deny('later lost record')
    summary._evidence_handle.path.unlink()
    if deactivate:
        summary.set_active_run_dir(None)
    assert summary.summarize_and_write(tmp_path) is None
    assert output.read_bytes() == before
    assert summary.get_evidence_inode_mismatch(tmp_path)


def test_repeated_write_failure_keeps_completed_summary(tmp_path, monkeypatch):
    summary.set_active_run_dir(tmp_path)
    deny('surviving forensic record')
    with monkeypatch.context() as scoped:
        scoped.setattr(summary._evidence_handle, 'write_line', lambda line: False)
        deny('first lost record')
    first = summary.summarize_and_write(tmp_path)
    assert first['evidence_write_failure'] is True
    assert first['total_denials'] == 1
    output = tmp_path / summary.SUMMARY_FILE
    before = output.read_bytes()

    def unavailable(*args, **kwargs):
        raise OSError('later evidence open failed')

    monkeypatch.setattr(evidence.EvidenceFile, 'open', staticmethod(unavailable))
    deny('later lost record')
    assert summary.summarize_and_write(tmp_path) is None
    assert output.read_bytes() == before
    assert summary.get_evidence_write_failure(tmp_path)
