"""Actual report projection over retained knowledge bytes after a failed write."""
from __future__ import annotations

import json

from core.audit.tests.test_knowledge_reporting import _captured


LABEL = "knowledge-processing history (persistence failed)"


def _draft_report(monkeypatch):
    from core.audit import report
    return report



def _finding(out_dir):
    finding = {"id": "FIND-owned", "title": "Retained captured concern", "file": "owned.c",
               "line": 1, "severity": "medium", "evidence_tier": "heuristic"}
    (out_dir / "findings.json").write_text(json.dumps([finding]), encoding="utf-8")
    return finding


def test_failed_knowledge_retention_preserves_assessments_and_hides_stale_counts(tmp_path, monkeypatch):
    report = _draft_report(monkeypatch)
    artifact, payload = _captured(tmp_path)
    finding = _finding(tmp_path)
    before = artifact.read_bytes()
    baseline = report.generate_report(tmp_path, final_status="completed")
    assert baseline["knowledge_processing"]["state"] == "recorded"
    failed = report.generate_report(tmp_path, final_status="completed", processing_limitations=[LABEL])
    assert failed["completeness"]["partial"] is True
    assert LABEL in failed["completeness"]["missing"]
    assert failed["knowledge_processing"] == {
        "state": "unavailable", "artifact": "knowledge-results.json", "reason": "persistence_failed"}
    assert "requests" not in failed["knowledge_processing"]
    assert "Knowledge processing record unavailable" in failed["summary"]
    assert "3 recorded requests" not in failed["summary"]
    assert failed["stats"] == baseline["stats"]
    assert failed["findings"] == baseline["findings"] == [finding]
    assert artifact.read_bytes() == before and json.loads(before) == payload


def test_knowledge_retention_loss_uses_existing_sticky_history_record(tmp_path, monkeypatch):
    report = _draft_report(monkeypatch)
    artifact, _payload = _captured(tmp_path)
    _finding(tmp_path)
    before = artifact.read_bytes()
    failed = report.generate_report(tmp_path, final_status="completed", processing_limitations=[LABEL])
    path = report.write_report(failed, tmp_path)
    history = json.loads((tmp_path / "processing-completeness.json").read_text())
    assert history == {"schema_version": 1, "limitations": [LABEL]}
    assert json.loads(path.read_text())["knowledge_processing"]["reason"] == "persistence_failed"
    # Later rendering without the in-memory result cannot reconstruct the
    # unretained final history merely from a valid, older knowledge artifact.
    later = report.generate_report(tmp_path, final_status="completed")
    assert later["completeness"]["partial"] is True
    assert LABEL in later["completeness"]["missing"]
    assert later["knowledge_processing"]["state"] == "unavailable"
    assert later["findings"] == failed["findings"]
    assert later["stats"] == failed["stats"]
    assert artifact.read_bytes() == before


def test_unrelated_or_unrecognized_limitations_do_not_hide_recorded_knowledge(tmp_path, monkeypatch):
    report = _draft_report(monkeypatch)
    artifact, _payload = _captured(tmp_path)
    _finding(tmp_path)
    before = artifact.read_bytes()
    baseline = report.generate_report(tmp_path, final_status="completed")
    assert baseline["knowledge_processing"]["state"] == "recorded"
    assert baseline["knowledge_processing"]["requests"] == 3
    assert LABEL not in baseline["completeness"]["missing"]
    assert not (tmp_path / "processing-completeness.json").exists()
    for limitation in ("new dark verification pass results (persistence failed)", LABEL + " forged"):
        current = report.generate_report(tmp_path, final_status="completed", processing_limitations=[limitation])
        assert current["knowledge_processing"] == baseline["knowledge_processing"]
        assert current["stats"] == baseline["stats"]
        assert current["findings"] == baseline["findings"]
        assert LABEL not in current["completeness"]["missing"]
    assert artifact.read_bytes() == before
