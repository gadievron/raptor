"""Threat-model assessment portability, caps and visual safety."""
from __future__ import annotations

import json
from xml.etree import ElementTree

from core.reporting.document import ReportDocument
from core.reporting.renderers import get_renderer
from core.threat_model import ThreatModel, render_report
from core.threat_model.reporting import build_threat_model_document


def _model():
    return ThreatModel("fixture", "/source", assets=["records"], entry_points=["API"],
                       trust_boundaries=["internet"], trust_zones=[{"id": "inside"}],
                       data_flows=[{"id": "flow-1", "source": "API", "sink": "Database"}],
                       threats=[{"id": "t-1", "title": "Threat", "risk_score": 8, "severity": "high", "status": "needs_evidence"}],
                       controls=[{"id": "c-1"}], evidence=[{"id": "e-1", "oracle": "test", "status": "inconclusive", "summary": "Observation",
                                                              "reproducible": True, "raw": {"provenance_verified": True}}])


def test_assessment_fields_and_formats_leave_native_model_unchanged():
    model = _model()
    before = model.to_dict()
    lint = [{"severity": "warning", "message": "needs evidence"}]
    document = build_threat_model_document(model, lint=lint, drift={"new_entry_points": ["Debug API"]})
    executive = dict(next(block.rows for block in document.blocks if block.title == "Executive View"))
    assert executive == {"Assets": 1, "Entry points": 1, "Trust boundaries": 2, "Data flows": 1,
                         "Threats": 1, "Controls": 1, "Evidence records": 1, "Open quality issues": 1}
    assert all(block.kind != "legacy_markdown" for block in document.blocks)
    evidence = next(block for block in document.blocks if block.title == "Evidence Loop")
    assert evidence.rows[0][-2:] == ["True", "True"]
    assert any("no new reproduction or authentication" in note for note in document.diagnostics)
    markdown = render_report(model, lint=lint, drift={"new_entry_points": ["Debug API"]})
    assert all(text in markdown for text in ["Top Threats", "Evidence Loop", "Quality Gates", "Debug API", "inconclusive", "needs_evidence"])
    assert "```mermaid" in markdown
    captured = json.loads(get_renderer("json").render(document).content)
    assert ReportDocument.from_dict(captured).to_dict() == document.to_dict()
    xml = ElementTree.fromstring(get_renderer("xml").render(document).content)
    assert "Observation" in " ".join(xml.itertext())
    assert model.to_dict() == before


def test_native_caps_are_explicit_and_ranking_is_preserved():
    model = _model()
    model.threats = [{"id": str(i), "risk_score": i, "title": "threat"} for i in range(12)]
    model.evidence *= 21
    model.data_flows *= 26
    document = build_threat_model_document(model, lint=[], drift={"new_entry_points": [str(i) for i in range(10)]})
    threats = next(block for block in document.blocks if block.title == "Top Threats")
    assert len(threats.rows) == 10
    assert [row[0] for row in threats.rows] == [str(i) for i in range(11, 1, -1)]
    evidence = next(block for block in document.blocks if block.title == "Evidence Loop")
    assert len(evidence.rows) == 20
    diagram = next(block for block in document.blocks if block.kind == "diagram")
    assert diagram.extensions["raptor.recorded_flows"] == 26
    assert diagram.extensions["raptor.displayed_flows"] == 25
    assert any("showing 20 of 21" in note for note in document.diagnostics)
    assert "2 additional records omitted" in render_report(model, lint=[], drift={"new_entry_points": [str(i) for i in range(10)]})


def test_hostile_and_secret_fields_remain_inert_without_mutating_source():
    model = _model()
    secret = "private-" + "a" * 24
    model.threats[0]["title"] = "Threat\n# forged\n```html\n<script>bad</script>"
    model.evidence[0]["summary"] = "https://example.test/?api_key=" + secret
    model.data_flows[0]["source"] = '"]; click A "https://example.test"; [bad'
    before = model.to_dict()
    document = build_threat_model_document(model, lint=[])
    assert secret not in json.dumps(document.to_dict())
    markdown = render_report(model, lint=[])
    assert "\n# forged" not in markdown
    assert "```html" not in markdown
    assert "<script>" not in markdown
    assert "```mermaid" not in markdown
    assert "Diagram visual unavailable" in markdown
    assert "Captured diagram source" in markdown
    assert model.to_dict() == before


def test_empty_model_reports_unavailable_evidence_and_quality_pass_separately():
    markdown = render_report(ThreatModel("empty", "/source"), lint=[])
    assert "No threats recorded yet" in markdown
    assert "No oracle evidence linked yet" in markdown
    assert "No quality issues found" in markdown
    assert "not new validation verdicts" in markdown
