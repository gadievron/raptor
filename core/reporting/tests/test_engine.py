"""Behavioral contracts for reporting, persistence, and the operator quick view."""
from __future__ import annotations

import io
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from core.reporting.adapters import context_from_sarif, native_findings
from core.reporting.builders import build_document, document_from_spec
from core.reporting.delta import build_delta
from core.reporting.document import Block, ReportContext, ReportDocument, StageEnvelope
from core.reporting.options import ReportOptions
from core.reporting.renderers import render_document
from core.reporting.service import complete_reporting
from core.reporting.spec import ReportSection, ReportSpec
from core.reporting.summary import build_operator_summary, render_operator_summary
from core.reporting.writer import load_document, publish_report, regenerate


def sarif(tmp_path: Path, *, count: int = 2, name: str = "combined.sarif", tool: str = "Semgrep") -> Path:
    path = tmp_path / name
    path.write_text(json.dumps({"version": "2.1.0", "runs": [{
        "tool": {"driver": {"name": tool, "rules": [{"id": "r", "defaultConfiguration": {"level": "error"}}]}},
        "results": [{"ruleId": "r", "message": {"text": "Inspect bounds"},
                     "fingerprints": {"matchBasedId/v1": "same"},
                     "properties": {"raptor": {"verdict": "confirmed"}},
                     "locations": [{"physicalLocation": {"artifactLocation": {"uri": "src/a.c"}, "region": {"startLine": i + 1}}}]}
                    for i in range(count)]}]}))
    return path


def context() -> ReportContext:
    c = ReportContext("validate", "run-a", target="src", state="completed")
    c.findings = native_findings([{"id": "x", "file": "a.c", "line": 4, "final_status": "confirmed", "message": "Bounds"}], run_id=c.run_id, producer="validate")
    return c


def test_sarif_triage_preserves_lines_levels_and_never_accepts_verdicts(tmp_path):
    p = sarif(tmp_path)
    before = p.read_bytes()
    c = context_from_sarif([p], stages=[StageEnvelope("semgrep", "completed")])
    assert [f["line"] for f in c.findings] == [1, 2]
    assert all(f["scanner_level"] == "error" and f["severity"] is None and f["status"] == "Unconfirmed" for f in c.findings)
    assert len({f["occurrence_ref"] for f in c.findings}) == 2
    assert c.state == "completed" and p.read_bytes() == before
    summary = build_operator_summary(c)
    assert summary.scanner_levels == {"error": 2}
    assert summary.security_severities == {}
    assert "Scanner levels: error=2" in render_operator_summary(summary)


def test_invalid_input_is_not_a_clean_zero(tmp_path):
    p = tmp_path / "bad.sarif"
    p.write_text("garbage")
    broken = context_from_sarif([p])
    empty = context_from_sarif([sarif(tmp_path, count=0)], stages=[StageEnvelope("scanner", "completed")])
    assert broken.state == "partial" and broken.diagnostics
    assert empty.state == "completed" and not empty.diagnostics


def test_tools_have_distinct_occurrences_even_with_same_fingerprints(tmp_path):
    c = context_from_sarif([sarif(tmp_path, name="one.sarif"), sarif(tmp_path, name="two.sarif", tool="CodeQL")])
    assert len({f["occurrence_ref"] for f in c.findings}) == 4


def test_adapter_cap_is_declared_and_counts_are_not_lost(tmp_path):
    c = context_from_sarif([sarif(tmp_path, count=5)], max_findings=2)
    assert len(c.findings) == 2
    assert c.extensions["raptor.accounting"]["observed_results"] == 5
    assert any("truncated" in n for n in c.diagnostics)


def test_missing_stage_and_suppression_remain_visible():
    c = context()
    c.expected_stages = ["sanity"]
    c.findings[0]["suppressed"] = True
    s = build_operator_summary(c)
    assert s.state == "partial" and s.total == 1 and s.rows == []
    assert "coverage unknown" in render_operator_summary(s)
    assert "suppressed" in render_operator_summary(s, markdown=True)


def test_no_report_keeps_quick_summary(tmp_path):
    output = io.StringIO()
    result = complete_reporting(context(), tmp_path, options=ReportOptions(enabled=False), stream=output)
    assert "Confirmed" in output.getvalue()
    assert result.publication is None
    assert (tmp_path / "summary.md").exists()
    assert not (tmp_path / "report.md").exists()


def test_report_write_failure_keeps_summary(tmp_path, monkeypatch):
    def fail(*args, **kwargs):
        raise OSError("disk full")
    monkeypatch.setattr("core.reporting.service.write_summary", fail)
    output = io.StringIO()
    result = complete_reporting(context(), tmp_path, stream=output)
    assert "Confirmed" in output.getvalue() and "persistence failed" in output.getvalue()
    assert result.diagnostics


def test_uncapturable_metadata_does_not_erase_the_quick_view():
    c = context()
    c.extensions["unsupported"] = object()
    summary = build_operator_summary(c)
    assert len(summary.rows) == 1 and summary.counts == {"Confirmed": 1}
    assert "could not be serialized" in render_operator_summary(summary)


@pytest.mark.parametrize("format", ["markdown", "html", "json", "xml"])
def test_portable_document_roundtrip_and_offline_render(tmp_path, format):
    c = context()
    d = build_document(c)
    pub = publish_report(c, d, tmp_path, options=ReportOptions(formats=(format,)))
    captured = load_document(tmp_path / "report-document.json")
    assert captured.to_dict() == d.to_dict()
    assert pub.snapshot_id == c.snapshot_id
    dest = tmp_path / "offline-output"
    regenerate(tmp_path / "report-document.json", dest, format=format)
    assert dest.read_bytes() == render_document(d, format).content
    loaded = ReportContext.from_dict(json.loads((tmp_path / "report-context.json").read_text()))
    assert loaded.snapshot_id == c.snapshot_id


def test_html_escapes_hostile_prose_and_legacy_markdown():
    c = context()
    spec = ReportSpec(title='<script>alert(1)</script>', sections=[ReportSection("Notes", '<img src="http://evil">')])
    d = document_from_spec(spec, c)
    result = render_document(d, "html")
    assert b"<script>" not in result.content and b"<img" not in result.content
    assert b"&lt;img" in result.content and result.diagnostics


def test_imported_legacy_markdown_is_inert_even_with_mermaid_and_fence_breaks():
    c = context()
    payload = '<img src="https://example.invalid/track">\n```\n```mermaid\nflowchart LR\nclick A "https://example.invalid"\n```'
    d = build_document(c, blocks=[Block("legacy_markdown", text=payload)])
    result = render_document(d)
    assert b"```text" in result.content and result.diagnostics
    assert b"\n```mermaid\n" not in result.content


def test_diagrams_have_offline_fallback_and_reject_active_source():
    c = context()
    d = build_document(c, blocks=[Block("diagram", text="A calls B", extensions={"mermaid": 'flowchart LR\nA-->B\nclick A "https://evil"'})])
    md = render_document(d)
    assert b"```mermaid" not in md.content and b"A calls B" in md.content
    assert md.diagnostics
    assert b"A calls B" in render_document(d, "html").content


def test_explicit_lineage_delta_does_not_call_absence_fixed():
    before = context()
    after = ReportContext("validate", "run-b", target="src", state="completed")
    _, doc = build_delta(before, after)
    md = render_document(doc).content.decode()
    assert "not observed" in md
    assert "does not establish a fix" in md
    after.findings = [{**before.findings[0], "occurrence_ref": "other", "status": "Unconfirmed"}]
    _, doc = build_delta(before, after, lineage={"other": before.findings[0]["occurrence_ref"]})
    assert "changed: status" in render_document(doc).content.decode()


def test_strict_serialization_and_versions():
    c = context()
    c.extensions["bad"] = float("nan")
    with pytest.raises(ValueError, match="unsupported reporting value"):
        c.to_dict()
    d = build_document(context()).to_dict()
    d["schema_version"] = 99
    with pytest.raises(ValueError, match="schema version"):
        ReportDocument.from_dict(d)


def test_document_and_snapshot_must_match(tmp_path):
    c = context()
    d = build_document(c)
    c.target = "changed"
    with pytest.raises(ValueError, match="identities disagree"):
        publish_report(c, d, tmp_path)


def test_unsupported_format_and_multiformat_destination():
    with pytest.raises(ValueError, match="Unsupported"):
        ReportOptions(formats=("pdf",)).validate()
    with pytest.raises(ValueError, match="directory"):
        ReportOptions(formats=("html", "markdown"), output=Path("report.html")).validate()


def test_concurrent_publication_guard_and_old_generation_retained(tmp_path):
    c = context()
    first = publish_report(c, build_document(c), tmp_path)
    c.target = "later"
    second = publish_report(c, build_document(c), tmp_path, expected_generation=first.generation)
    assert first.generation != second.generation
    assert (tmp_path / ".reporting" / first.generation / "report-document.json").exists()
    with pytest.raises(ValueError, match="newer report"):
        publish_report(c, build_document(c), tmp_path, expected_generation=first.generation)


def test_sarif_markdown_message_and_artifact_index(tmp_path):
    p = sarif(tmp_path, count=1)
    data = json.loads(p.read_text())
    run = data["runs"][0]
    run["artifacts"] = [{"location": {"uri": "indexed.c"}}]
    run["results"][0]["message"] = {"markdown": "**scanner claim**"}
    run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"] = {"index": 0}
    p.write_text(json.dumps(data))
    c = context_from_sarif([p])
    assert c.findings[0]["file"] == "indexed.c"
    assert c.findings[0]["message"] == "**scanner claim**"


def test_codeql_programmatic_failure_path_still_publishes_summary(tmp_path, monkeypatch):
    from packages.codeql.agent import CodeQLAgent
    agent = object.__new__(CodeQLAgent)
    agent.repo_path = tmp_path
    agent.out_dir = tmp_path / "out"
    result = SimpleNamespace(sarif_files=[], success=False, errors=["No supported languages"],
                             duration_seconds=0.01, timestamp="2026-11-06T00:00:00Z")
    monkeypatch.setattr(agent, "_run_autonomous_analysis", lambda **kwargs: result)
    assert agent.run_autonomous_analysis() is result
    summary = json.loads((agent.out_dir / "summary.json").read_text())
    assert summary["state"] == "partial"
    assert "No supported languages" in summary["diagnostics"]
    assert (agent.out_dir / "codeql-report.md").exists()


def test_diagram_fallback_is_a_note_not_a_failed_report(tmp_path):
    c = context()
    d = build_document(c, blocks=[Block("diagram", title="Context", text="Recorded graph", extensions={"mermaid": "flowchart LR\nA-->B"})])
    result = complete_reporting(c, tmp_path, document=d, options=ReportOptions(formats=("html",)))
    assert result.diagnostics and not result.errors
    assert result.publication.outputs["html"]
    assert json.loads((tmp_path / "reporting-manifest.json").read_text())["status"] == "completed"
    assert "visual unavailable" in (tmp_path / "summary.md").read_text()


def test_failed_project_export_preserves_previous_and_sibling_user_files(tmp_path, monkeypatch):
    import core.project.report as reports
    original = [{"id": "F1", "file": "a.c", "line": 1, "vuln_type": "bounds"}]
    reports.export_findings_directory(original, tmp_path)
    notes = tmp_path / "operator-notes.txt"
    notes.write_text("keep this")
    reports.export_findings_directory([], tmp_path)
    assert notes.read_text() == "keep this"
    before = (tmp_path / "findings" / "manifest.json").read_bytes()
    def fail(*args, **kwargs):
        raise OSError("failed staging")
    monkeypatch.setattr(reports, "_write_findings_directory", fail)
    with pytest.raises(OSError):
        reports.export_findings_directory(original, tmp_path)
    assert (tmp_path / "findings" / "manifest.json").read_bytes() == before
    assert notes.read_text() == "keep this"


def test_project_baseline_is_captured_before_current_snapshot_is_replaced(tmp_path, monkeypatch):
    import core.project.report as reports
    root = tmp_path / "project"
    run = root / "scan-20261106-000000"
    run.mkdir(parents=True)
    payload = run / "findings.json"
    payload.write_text(json.dumps({"findings": [{"id": "F1", "file": "a.c", "line": 1, "vuln_type": "bounds"}]}))
    project = SimpleNamespace(name="demo", output_path=root, get_run_dirs=lambda **kwargs: [run])
    monkeypatch.setattr(reports, "gather_project_annotations", lambda _: [])
    reports.generate_project_report(project)
    baseline = root / "_report" / "report-context.json"
    old_id = json.loads(baseline.read_text())["snapshot_id"]
    payload.write_text(json.dumps({"findings": [{"id": "F1", "file": "a.c", "line": 1, "vuln_type": "bounds", "status": "confirmed"}]}))
    reports.generate_project_report(project, baseline=baseline)
    current_id = json.loads(baseline.read_text())["snapshot_id"]
    delta = json.loads((root / "_report" / "delta" / "report-context.json").read_text())
    assert old_id != current_id
    assert delta["parents"] == [old_id, current_id]


def test_persistence_names_are_reserved(tmp_path):
    c = context()
    with pytest.raises(ValueError, match="filename"):
        publish_report(c, build_document(c), tmp_path, stem="report-context")


def test_snapshot_digest_is_for_the_original_sarif_bytes(tmp_path):
    import hashlib
    p = sarif(tmp_path)
    c = context_from_sarif([p])
    assert c.artifacts[0]["digest"] == hashlib.sha256(p.read_bytes()).hexdigest()


def test_nosemgrep_and_rejected_suppression_quick_view(tmp_path):
    p = sarif(tmp_path)
    data = json.loads(p.read_text())
    results = data["runs"][0]["results"]
    results[0]["properties"]["nosemgrep"] = {"suppressed": True}
    results[1]["suppressions"] = [{"kind": "external", "status": "rejected"}]
    p.write_text(json.dumps(data))
    c = context_from_sarif([p])
    assert [f["suppressed"] for f in c.findings] == [True, False]
    assert len(build_operator_summary(c).rows) == 1
    assert len(build_operator_summary(c, show_suppressed=True).rows) == 2


def test_existing_rich_diagrams_are_captured_not_dropped_or_reread(tmp_path):
    from packages.diagram.reporting import capture_directory_blocks
    source = tmp_path / "context-map.json"
    source.write_text(json.dumps({"language": "c", "entry_points": [{"name": "main", "file": "a.c", "line": 1}], "sinks": []}))
    blocks = capture_directory_blocks(tmp_path)
    assert blocks and "Context Map" in blocks[0].text
    c = context()
    d = build_document(c, blocks=blocks)
    expected = render_document(d).content
    source.unlink()
    assert render_document(d).content == expected
    publish_report(c, d, tmp_path)
    assert "Context Map" in (tmp_path / "diagrams.md").read_text()
