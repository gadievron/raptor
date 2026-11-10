"""Audit presentation freezes readiness, native counts and integrity flags."""
from copy import deepcopy

from core.llm.scorecard import audit as audit_module
from core.llm.scorecard.audit import AuditReport, DecisionClassSummary, EventTypeSummary, PRIMARY_EVENT_TYPE, render_json, render_markdown
from core.llm.scorecard.audit_document import build_audit_document
from core.reporting.document import ReportDocument
from core.reporting.renderers import render_document


def _report(path):
    return AuditReport(str(path), 2, 2, 5, 10,
                       [EventTypeSummary(PRIMARY_EVENT_TYPE, 10, 10, {10: 2, 30: 2, 100: 0}, 140),
                        EventTypeSummary("future_signal", 1, 1, {10: 1, 30: 1, 100: 0}, 35)],
                       [DecisionClassSummary("dense", 2, 50.0, 100),
                        *[DecisionClassSummary(f"sparse-{index}", 2, 5.0, 10) for index in range(4)]],
                       PRIMARY_EVENT_TYPE, "amber", "2/10 cells reach N=30", key_unusable=True)


def test_typed_audit_preserves_native_json_unknown_events_and_readiness(tmp_path, monkeypatch):
    report = _report(tmp_path / "source.json")
    before = deepcopy(report)
    native = render_json(report)
    def refuse(*args, **kwargs):
        raise AssertionError("presentation must not reread or rerun audit")
    monkeypatch.setattr(audit_module, "audit", refuse)
    monkeypatch.setattr(audit_module, "_load_raw", refuse)
    document = build_audit_document(report)
    assert ReportDocument.from_dict(document.to_dict()).to_dict() == document.to_dict()
    assert document.extensions["raptor.readiness_verdict"] == "amber"
    assert document.metadata["Integrity key unusable"] is True
    assert render_markdown(report) == render_document(document, "markdown").content.decode()
    table = next(block for block in document.blocks if block.title == "Per-event-type coverage")
    assert table.rows[1] == ["future_signal", 1, 1, 1, 1, 0, 35]
    for format in ("markdown", "json", "xml"):
        text = render_document(document, format).content
        assert b"future_signal" in text and b"unverified sidecar content" in text
        assert b"not finding validity or target security" in text
    assert report == before and render_json(report) == native
    assert not any(block.kind == "legacy_markdown" for block in document.blocks)


def test_projection_caps_keep_native_counts_and_integrity_flags_explicit(tmp_path):
    report = _report(tmp_path / "source.json")
    report.event_type_summaries.extend([
        EventTypeSummary("label" * 40 + str(index), 1, 0, {10: 0, 30: 0, 100: 0}, 0) for index in range(999)])
    before = deepcopy(report)
    document = build_audit_document(report)
    assert document.extensions["raptor.event_rows_omitted"] == 1
    assert "Event type" in document.extensions["raptor.truncated_fields"]
    assert any("includes unverified sidecar content" in note for note in document.diagnostics)
    assert any("Portable capture is limited" in note for note in document.diagnostics)
    assert report == before
