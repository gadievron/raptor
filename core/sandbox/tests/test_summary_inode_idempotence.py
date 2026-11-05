"""Published inode failures remain sticky without erasing completed summaries."""
import json

import pytest

from core.sandbox import summary


@pytest.fixture(autouse=True)
def isolated_run(tmp_path, monkeypatch):
    monkeypatch.setenv('XDG_DATA_HOME', str(tmp_path / 'keys'))
    summary.set_active_run_dir(None)
    # Use the module's representation so this regression also runs on baseline.
    monkeypatch.setattr(summary, '_evidence_inode_mismatches', type(summary._evidence_inode_mismatches)())
    yield
    summary.set_active_run_dir(None)


def test_repeat_finalization_preserves_surviving_records(tmp_path):
    summary.set_active_run_dir(tmp_path)
    summary.record_denial('first command', 1, 'network', host='example.test')
    path = summary._evidence_handle.path
    path.unlink()
    path.write_text(json.dumps({'type': 'network', 'cmd': 'surviving record', 'host': 'example.test'}) + '\n')
    first = summary.summarize_and_write(tmp_path)
    assert first['inode_mismatch'] is True
    assert first['total_denials'] == 1
    output = tmp_path / summary.SUMMARY_FILE
    before = output.read_bytes()
    assert summary.summarize_and_write(tmp_path) is None
    assert output.read_bytes() == before


def test_repeat_missing_finalization_does_not_rewrite_output(tmp_path):
    summary.set_active_run_dir(tmp_path)
    summary.record_denial('first command', 1, 'network', host='example.test')
    summary._evidence_handle.path.unlink()
    first = summary.summarize_and_write(tmp_path)
    assert first['inode_mismatch'] is True
    output = tmp_path / summary.SUMMARY_FILE
    before = output.read_bytes()
    assert summary.summarize_and_write(tmp_path) is None
    assert output.read_bytes() == before


def test_new_evidence_keeps_previously_reported_failure(tmp_path):
    summary.set_active_run_dir(tmp_path)
    summary.record_denial('first command', 1, 'network', host='example.test')
    summary._evidence_handle.path.unlink()
    assert summary.summarize_and_write(tmp_path)['inode_mismatch'] is True
    summary.record_denial('later command', 1, 'network', host='later.test')
    later = summary.summarize_and_write(tmp_path)
    assert later['total_denials'] == 1
    assert later['inode_mismatch'] is True
