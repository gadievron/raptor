"""Parent evidence-integrity observations survive missing disk summaries."""
import pytest

from core.sandbox import summary, triage

from core.testing.sandbox_state_scope import isolated_summary_state


@pytest.fixture(autouse=True)
def isolated_run(tmp_path, monkeypatch):
    with isolated_summary_state():
        try:
            monkeypatch.setenv('XDG_DATA_HOME', str(tmp_path / 'keys'))
            summary.set_active_run_dir(None)
            monkeypatch.setattr(summary, '_evidence_inode_mismatches', {})
            yield
            summary.set_active_run_dir(None)
        finally:
            monkeypatch.undo()


def failed_run(path):
    summary.set_active_run_dir(path)
    summary.record_denial('test command', 1, 'network', host='example.test')
    summary._evidence_handle.path.unlink()
    assert summary.summarize_and_write(path)['inode_mismatch'] is True


def test_missing_summary_still_reports_parent_observation(tmp_path):
    failed_run(tmp_path)
    (tmp_path / summary.SUMMARY_FILE).unlink()
    report = triage.triage_run(tmp_path, allow_legacy=False)
    assert report is not None
    assert report['inputs']['integrity']['sandbox_summary'] == triage._INTEGRITY_TAMPERED
    assert report['inputs']['sandbox_summary_present'] is False
    assert report['verdict'] == 'suspicious'
    evidence = [
        item
        for signal in report['signals']
        if signal['type'] == 'telemetry_tampering'
        for item in signal['evidence']
    ]
    assert 'sandbox_summary: parent observed an evidence-file verification failure' in evidence


def test_later_valid_summary_cannot_clear_parent_observation(tmp_path):
    failed_run(tmp_path)
    # Another legitimate producer need not know this parent's prior state.
    later = summary._assemble_and_write_summary(
        tmp_path, records=[{'type': 'network', 'cmd': 'later record'}],
        refusals=[], corrupt_lines=0, inode_mismatch=False, planted_object='')
    assert 'inode_mismatch' not in later
    report = triage.triage_run(tmp_path, allow_legacy=False)
    assert report['inputs']['integrity']['sandbox_summary'] == triage._INTEGRITY_TAMPERED
    assert report['inputs']['total_denials'] == 0


def test_query_remains_true_after_publication_and_resolves_aliases(tmp_path):
    failed_run(tmp_path)
    assert summary.get_evidence_inode_mismatch(tmp_path)
    alias = tmp_path / 'alias'
    alias.symlink_to(tmp_path, target_is_directory=True)
    assert summary.get_evidence_inode_mismatch(alias)


def test_clean_run_and_other_run_are_not_flagged(tmp_path):
    other = tmp_path / 'other'
    other.mkdir()
    failed_run(other)
    assert not summary.get_evidence_inode_mismatch(tmp_path)
    assert triage.triage_run(tmp_path, allow_legacy=False) is None


def test_disk_flag_remains_effective_without_parent_memory(tmp_path, monkeypatch):
    failed_run(tmp_path)
    monkeypatch.setattr(summary, '_evidence_inode_mismatches', {})
    report = triage.triage_run(tmp_path, allow_legacy=False)
    assert report['inputs']['integrity']['sandbox_summary'] == triage._INTEGRITY_TAMPERED
