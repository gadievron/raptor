"""Dangling evidence links are refused inputs, not absent telemetry."""
import json

import pytest

from core.sandbox import evidence, summary, triage


@pytest.fixture(autouse=True)
def isolated_run(tmp_path, monkeypatch):
    monkeypatch.setenv('XDG_DATA_HOME', str(tmp_path / 'keys'))
    summary.set_active_run_dir(None)
    monkeypatch.setattr(summary, '_evidence_inode_mismatches', {})
    monkeypatch.setattr(summary, '_evidence_write_failures', {})
    yield
    summary.set_active_run_dir(None)


@pytest.mark.parametrize('location', ['new', 'legacy'])
def test_dangling_evidence_entry_produces_flagged_summary(tmp_path, location):
    path = (evidence.evidence_write_path(tmp_path, summary.DENIALS_FILE)
            if location == 'new' else evidence.legacy_read_path(tmp_path, summary.DENIALS_FILE))
    path.parent.mkdir(parents=True, exist_ok=True)
    missing = tmp_path / 'missing destination'
    path.symlink_to(missing)
    assert evidence.resolve_read_path(tmp_path, summary.DENIALS_FILE) == path
    result = summary.summarize_and_write(tmp_path)
    assert result is not None
    assert result['planted_object'] == 'symlink'
    assert result['total_denials'] == 0
    assert not missing.exists()
    report = triage.triage_run(tmp_path, allow_legacy=False)
    assert report['inputs']['integrity']['sandbox_summary'] == triage._INTEGRITY_TAMPERED


def test_dangling_new_entry_cannot_fall_back_to_older_data(tmp_path):
    new = evidence.evidence_write_path(tmp_path, summary.DENIALS_FILE)
    new.parent.mkdir(parents=True)
    new.symlink_to(tmp_path / 'missing destination')
    old = evidence.legacy_read_path(tmp_path, summary.DENIALS_FILE)
    data = (json.dumps({'type': 'network', 'cmd': 'legacy record'}) + '\n').encode()
    old.write_bytes(data)
    assert evidence.resolve_read_path(tmp_path, summary.DENIALS_FILE) == new
    result = summary.summarize_and_write(tmp_path)
    assert result['planted_object'] == 'symlink'
    assert result['total_denials'] == 0
    assert old.read_bytes() == data


def test_absent_new_entry_still_allows_legacy_fallback(tmp_path):
    old = evidence.legacy_read_path(tmp_path, summary.DENIALS_FILE)
    old.write_text(json.dumps({'type': 'network', 'cmd': 'legacy record'}) + '\n')
    assert evidence.resolve_read_path(tmp_path, summary.DENIALS_FILE) == old
    result = summary.summarize_and_write(tmp_path)
    assert result['total_denials'] == 1
    assert 'planted_object' not in result
