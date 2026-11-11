"""Captured knowledge provenance reaches the real finalizer console."""
import json

from core.audit.knowledge_reporting import knowledge_processing_lines
from core.audit.orchestrator import OrchestratorResult
from core.audit.tests.test_knowledge_reporting import _captured
from core.audit.tests.test_processing_finalization_integration import _finalize
from core.audit.tests.test_report_completeness import TestCompleteRunReport as _CompleteRun
from core.audit.tests.test_report_completeness import _journal


def _run_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("_RAPTOR_TRUSTED", "1")
    out = _CompleteRun()._complete_run(tmp_path)
    _journal(out, "prior_supported", "finding")
    return out


def test_captured_current_knowledge_reaches_finalizer_console(tmp_path, monkeypatch, capsys):
    out = _run_dir(tmp_path, monkeypatch)
    path, payload = _captured(out)
    origin = {"file": "owned.c", "function": "f", "line_start": 1}
    frozen, late = "context:late_joern:frozen", "context:late_joern:late"
    for version in ("frozen", "late"):
        payload["events"].append({"event": "context_delta_offered", "origin": origin,
                                  "context_id": "context:late_joern:" + version,
                                  "kind": "late_joern", "version": version})
    payload["events"].extend([
        {"event": "continuation_reserved", "origin": origin, "pass_id": "context-pass"},
        {"event": "review_prompt_context", "pass_id": "context-pass", "records": [
            {"field": "external_context_delivery", "context_id": frozen, "delivered": True}]},
        {"event": "continuation_completed", "pass_id": "context-pass",
         "published_status": "clean", "delivered_request_ids": [frozen]},
    ])
    payload["units"][0]["cycle"]["delta_ids"].append(late)
    payload["requests"][0]["question"] = "PRIVATE_QUESTION_904"
    path.write_text(json.dumps(payload), encoding="utf-8")
    before = {p.name: p.read_bytes() for p in out.iterdir() if p.is_file()}
    result = OrchestratorResult(total_cost_usd=1.25)
    _finalize(out, result, monkeypatch)
    console = capsys.readouterr().out
    (out / "captured-console.txt").write_text(console, encoding="utf-8")
    report = json.loads((out / "audit-report.json").read_text())
    record = report["knowledge_processing"]
    assert record["available_requests_never_delivered"] == 1
    assert record["delivered_context_updates"] == 1
    assert record["pending_delivery_context_updates"] == 1
    for line in knowledge_processing_lines(report):
        assert line in console
    assert "Delivery totals are historical" in console
    assert "not verification evidence or proof of safety" in console
    assert "PRIVATE_QUESTION_904" not in console
    assert report["stats"]["finding"] == 1 and report["stats"]["clean"] == 1
    assert result.total_cost_usd == 1.25
    for name, data in before.items():
        assert (out / name).read_bytes() == data


def test_legacy_knowledge_absence_is_silent_at_finalizer(tmp_path, monkeypatch, capsys):
    out = _run_dir(tmp_path, monkeypatch)
    _finalize(out, OrchestratorResult(), monkeypatch)
    console = capsys.readouterr().out
    assert "Knowledge processing" not in console and "Knowledge context updates" not in console


def test_invalid_present_knowledge_is_unavailable_at_finalizer(tmp_path, monkeypatch, capsys):
    out = _run_dir(tmp_path, monkeypatch)
    path = out / "knowledge-results.json"
    path.write_text("{PRIVATE_INVALID_905", encoding="utf-8")
    before = path.read_bytes()
    _finalize(out, OrchestratorResult(), monkeypatch)
    console = capsys.readouterr().out
    assert "Knowledge processing record unavailable; request completion and delivery are unknown." in console
    assert "PRIVATE_INVALID_905" not in console
    assert path.read_bytes() == before
