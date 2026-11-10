"""End-to-end contracts at reporting's domain and operator boundaries."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
import json
from threading import Barrier
from types import SimpleNamespace

import pytest

from core.reporting.adapters import context_from_sarif, native_findings
from core.reporting.builders import build_document
from core.reporting.delta import build_delta
from core.reporting.document import Block, Inline, ReportContext, StageEnvelope
from core.reporting.renderers import render_document
from core.reporting.results import NativeResult
from core.reporting.service import complete_reporting
from core.reporting.writer import load_committed_report, publish_report, regenerate


def test_binary_export_uses_captured_json_without_analysis(tmp_path, capsys):
    from packages.binary_analysis.cli import main
    (tmp_path / "binary-context-map.json").write_text(json.dumps({"functions": [{"name": "parse", "role": "decoder"}]}))
    source = (tmp_path / "binary-context-map.json").read_bytes()
    assert main(["report", str(tmp_path), "--report-format", "html"]) == 0
    assert b"decoder" in (tmp_path / "binary-report.html").read_bytes()
    assert (tmp_path / "binary-context-map.json").read_bytes() == source
    assert "finding population" in capsys.readouterr().out


def test_sca_html_alias_preflights_destination_before_work(tmp_path):
    from packages.sca._scan_args import resolve_report_options
    args = SimpleNamespace(report_format=["markdown"], report_output=tmp_path / "report.md", no_report=False, html=True)
    with pytest.raises(ValueError, match="directory"):
        resolve_report_options(args)
    assert not list(tmp_path.iterdir())


def test_project_merge_preserves_regenerable_histories(tmp_path):
    from core.project.merge import merge_runs
    source = tmp_path / "source"
    c = sample()
    publish_report(c, build_document(c), source)
    destination = tmp_path / "merged"
    merge_runs([source], destination)
    bundles = list((destination / "report-histories").iterdir())
    assert len(bundles) == 1
    captured, _, _ = load_committed_report(bundles[0])
    assert captured.snapshot_id == c.snapshot_id
    regenerate(bundles[0], tmp_path / "history.html", format="html")
    assert (tmp_path / "history.html").is_file()


def test_project_freezes_discovery_for_annotations_and_contradictions(tmp_path, monkeypatch):
    import core.project.report as reports
    import core.project.readjudication as contradictions
    source = tmp_path / "run"
    source.mkdir()
    (source / "findings.json").write_text(json.dumps({"findings": [{"id": "F", "file": "a.c", "line": 1}]}))
    calls = []
    def discover(**kwargs):
        calls.append(kwargs)
        return [source]
    project = SimpleNamespace(name="P", output_path=tmp_path / "project", get_run_dirs=discover)
    monkeypatch.setattr(contradictions, "load_findings_from_dir", lambda _: pytest.fail("contradictions must use the frozen records"))
    reports.generate_project_report(project)
    assert len(calls) == 1


def test_native_offline_import_retains_metadata_and_explicit_passes(tmp_path, capsys):
    from core.reporting.__main__ import main
    source = tmp_path / "source.json"
    payload = {"findings": [{"id": "F", "description": "claim"}], "coverage": {"unit": "function", "reviewed": 3}}
    source.write_text(json.dumps(payload))
    out = tmp_path / "out"
    assert main(["native", str(source), "--out", str(out), "--run-id", "R", "--pass-id", "targeted", "--attempt-id", "2", "--parent", "prior"]) == 0
    c, d, _ = load_committed_report(out)
    assert c.extensions["raptor.imported"] == payload
    assert (c.run_id, c.pass_id, c.attempt_id, c.parents) == ("R", "targeted", "2", ["prior"])
    assert b"reviewed" in render_document(d, "html").content
    assert "pass: targeted" in capsys.readouterr().out


def test_native_offline_inventory_makes_no_finding_claim(tmp_path, capsys):
    from core.reporting.__main__ import main
    source = tmp_path / "source.json"
    source.write_text(json.dumps({"-": "not a population", "inventory": ["a", "b"]}))
    assert main(["native", str(source), "--findings-key", "-", "--out", str(tmp_path / "out")]) == 0
    assert "Captured findings: 0" not in capsys.readouterr().out


def test_format_aliases_produce_one_destination(tmp_path):
    from core.reporting.options import ReportOptions
    options = ReportOptions(("md", "markdown"), tmp_path / "one.md").validate()
    assert options.formats == ("markdown",)


def test_markdown_truncation_is_declared_and_full_data_is_preserved():
    c = sample()
    text = "x" * 20_100 + "END_OF_EVIDENCE"
    d = build_document(c, blocks=[Block("paragraph", text=text)])
    result = render_document(d)
    assert result.diagnostics and b"Format notes" in result.content
    assert "END_OF_EVIDENCE" in d.to_dict()["blocks"][-1]["text"]


def test_regeneration_preserves_original_source_artifacts(tmp_path):
    source = tmp_path / "evidence.json"
    source.write_text('{"source":true}')
    c = sample()
    c.artifacts = [{"uri": str(source)}]
    publish_report(c, build_document(c), tmp_path / "report")
    with pytest.raises(ValueError, match="source artifact"):
        regenerate(tmp_path / "report", source, format="json")
    assert source.read_text() == '{"source":true}'


def test_project_delta_uses_a_separate_custom_destination_even_when_empty(tmp_path, monkeypatch):
    import core.project.report as reports
    from core.reporting.options import ReportOptions
    source = tmp_path / "run"
    source.mkdir()
    (source / "findings.json").write_text(json.dumps({"findings": [{"id": "F", "file": "a.c", "line": 1}]}))
    runs = [source]
    project = SimpleNamespace(name="P", output_path=tmp_path / "project", get_run_dirs=lambda **kw: runs)
    monkeypatch.setattr(reports, "gather_project_annotations", lambda _: [])
    reports.generate_project_report(project)
    baseline = project.output_path / "_report"
    destination = tmp_path / "custom.md"
    runs.clear()
    reports.generate_project_report(project, baseline=baseline, report_options=ReportOptions(output=destination))
    assert "Snapshot Delta" not in destination.read_text()
    assert "Snapshot Delta" in (tmp_path / "custom-delta.md").read_text()
    rows = json.loads((baseline / "findings.json").read_text())
    assert rows["findings"] == []


def test_validation_enrichment_is_portable_and_does_not_require_sarif(tmp_path):
    from packages.exploitability_validation.report import write_validation_report
    from core.reporting.options import ReportOptions
    payload = {"findings": [{"id": "F", "status": "confirmed_unverified", "file": "a.c", "line": 1,
                              "ruling": {"reason": "retained ruling"}, "feasibility": {"status": "error", "error": "missing target binary"}}],
               "stage_f_review": "retained review"}
    (tmp_path / "findings.json").write_text(json.dumps(payload))
    path = write_validation_report(str(tmp_path), report_options=ReportOptions(formats=("html", "xml")))
    assert path.suffix == ".html"
    _, d, _ = load_committed_report(tmp_path)
    def blocks(values):
        for block in values:
            yield block
            yield from blocks(block.children)
    assert not any(b.kind == "legacy_markdown" for b in blocks(d.blocks))
    for format in ("markdown", "html", "xml", "json"):
        content = render_document(d, format).content
        assert b"retained ruling" in content and b"missing target binary" in content and b"retained review" in content
        assert b"Confirmed (Unverified) Findings" in content
    assert not (tmp_path / "validation.sarif").exists()


def test_capability_preflight_is_machine_readable_and_does_not_start_work(capsys, monkeypatch):
    import core.reporting.__main__ as cli
    monkeypatch.setattr(cli, "complete_reporting", lambda *a, **kw: pytest.fail("capability lookup must not publish or analyze"))
    assert cli.main(["capabilities"]) == 0
    capabilities = json.loads(capsys.readouterr().out)
    assert any(c["command"] == "binary report" and c["artifact_policy"] == "explicit export" for c in capabilities)
    assert any(c["command"] == "understand native map/hunt/trace/resume"
               and c["document_kind"] == "understand" and c["summary_independent"] for c in capabilities)


def test_validation_supplement_changes_snapshot_identity(tmp_path):
    from packages.exploitability_validation.report import write_validation_report
    (tmp_path / "findings.json").write_text(json.dumps({"findings": [{"id": "F", "status": "confirmed", "file": "a.c"}]}))
    preflight = tmp_path / "capability-preflight.json"
    def capture(detail):
        preflight.write_text(json.dumps({"warnings": [{"code": "fixture", "detail": detail}]}))
        write_validation_report(str(tmp_path))
        c, _, _ = load_committed_report(tmp_path)
        return c
    before = capture("first capability limitation")
    after = capture("different capability limitation")
    assert before.snapshot_id != after.snapshot_id
    assert after.extensions["raptor.validation_enrichment"]["enrichment"]["Capability Preflight"]["warnings"][0]["detail"] == "different capability limitation"


def test_agentic_audit_enrichment_freezes_sibling_evidence(tmp_path):
    from raptor_agentic import _build_audit_report_section
    from core.reporting.builders import document_from_spec
    from core.reporting.spec import ReportSpec
    source = tmp_path / "audit-report.json"
    evidence = {"findings": [{"id": "A", "file": "a.c", "function": "parse", "severity": "high", "title": "Recorded audit claim",
                               "tool_evidence": [{"tool": "fixture", "details": "full sibling evidence"}]}]}
    source.write_text(json.dumps(evidence))
    section = _build_audit_report_section({"completed": True, "audit_dir": str(tmp_path), "findings_count": 1})
    assert section.source_data["findings"] == evidence["findings"]
    c = sample()
    c.extensions["raptor.phase_enrichment"] = section.source_data
    d = document_from_spec(ReportSpec(sections=[section]), c)
    source.unlink()
    assert b"full sibling evidence" in render_document(d, "html").content


def sample():
    c = ReportContext("project", "P", target="src", state="completed")
    c.findings = native_findings([{"id": "F", "file": "a.c", "line": 2}], run_id="R", producer="scan", triage=True)
    c.extensions["raptor.project"] = {"annotation_digest": "one", "annotations": []}
    return c


def test_project_annotation_delta_is_not_a_new_discovery():
    before = sample()
    after = deepcopy(before)
    after.extensions["raptor.project"] = {"annotation_digest": "two", "annotations": [{"note": "review later"}]}
    c, d = build_delta(before, after)
    delta = c.extensions["raptor.delta"]
    assert delta["changes"] == []
    assert {r["dimension"] for r in delta["context_changes"]} >= {"project annotations", "project annotation_digest"}
    assert b"project annotations" in render_document(d).content


def test_evidence_only_delta_is_visible_without_inventing_a_verdict():
    before = sample()
    after = deepcopy(before)
    after.findings[0]["native"]["analysis"] = {"reason": "additional evidence"}
    c, _ = build_delta(before, after)
    assert "recorded evidence" in c.extensions["raptor.delta"]["changes"][0][1]
    assert c.extensions["raptor.delta"]["changes"][0][2:] == ["Unconfirmed", "Unconfirmed"]


def test_ambiguous_split_is_not_also_reported_absent():
    before = sample()
    after = deepcopy(before)
    old_ref = before.findings[0]["occurrence_ref"]
    after.findings = [{**after.findings[0], "occurrence_ref": "new-a"}, {**after.findings[0], "occurrence_ref": "new-b"}]
    c, _ = build_delta(before, after, lineage={"new-a": old_ref, "new-b": old_ref})
    assert [row[1] for row in c.extensions["raptor.delta"]["changes"]] == ["uncertain match", "uncertain match"]


def test_concurrent_publishers_only_commit_one_selected_view(tmp_path):
    initial = sample()
    current = complete_reporting(initial, tmp_path).publication.generation
    gate = Barrier(2)
    def publish(label):
        c = sample()
        c.target = label
        gate.wait(timeout=10)
        return complete_reporting(c, tmp_path, expected_generation=current)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(publish, ["a", "b"]))
    assert sum(not r.errors for r in results) == 1
    c, _, manifest = load_committed_report(tmp_path)
    summary = json.loads((tmp_path / "summary.json").read_text())
    assert summary["snapshot_id"] == c.snapshot_id == manifest["snapshot_id"]


def test_regeneration_uses_committed_snapshot_and_cannot_mutate_it(tmp_path):
    c = sample()
    result = publish_report(c, build_document(c), tmp_path)
    (tmp_path / "report-document.json").write_text("stale compatibility mirror")
    regenerate(tmp_path, tmp_path / "copy.html", format="html")
    assert (tmp_path / "copy.html").exists()
    with pytest.raises(ValueError, match="immutable"):
        regenerate(tmp_path, tmp_path / ".reporting" / result.generation / "report.md")


def test_sca_has_one_portable_builder_with_rich_evidence(tmp_path):
    from packages.sca.reporting import build_sca_document
    rows = [{"finding_id": "sca:F", "vuln_type": "sca:vulnerable_dependency", "file": "pom.xml", "severity": "critical",
             "description": "Affected dependency", "suppressed": False,
             "sca": {"name": "example", "version": "1", "fixed_version": "2", "in_kev": True, "epss": 0.9,
                     "reachability": {"status": "not_evaluated"}, "all_advisories": [{"id": "CVE-fixture"}]}}]
    c, d = build_sca_document(rows=rows, target=tmp_path, output_dir=tmp_path, deps_analysed=1)
    assert all(b.kind != "legacy_markdown" for b in d.blocks)
    assert c.findings[0]["status"] == "Advisory match"
    for format in ("markdown", "html", "json", "xml"):
        data = render_document(d, format).content
        assert b"CVE-fixture" in data and b"not_evaluated" in data and b"example" in data
    assert b"**KEV**" in render_document(d).content
    assert b"<strong>KEV</strong>" in render_document(d, "html").content


def test_inventory_result_does_not_claim_zero_findings():
    c, d = NativeResult("describe", "src", "inspection", {"functions": 42}, state="completed").build()
    from core.reporting.summary import build_operator_summary, render_operator_summary
    text = render_operator_summary(build_operator_summary(c))
    assert "No findings" not in text and "Captured findings: 0" not in text
    assert "functions" in render_document(d).content.decode()


def test_inline_links_are_inert_for_disallowed_schemes():
    c = sample()
    d = build_document(c, blocks=[Block("paragraph", inline=[Inline("link", "unsafe", "javascript:alert(1)")])])
    assert b"href=" not in render_document(d, "html").content
    assert b"javascript:" not in render_document(d).content


def test_new_scan_snapshots_participate_in_project_findings(tmp_path, monkeypatch):
    import core.project.report as reports
    run = tmp_path / "scan-20261106-001122"
    run.mkdir()
    sarif = run / "combined.sarif"
    sarif.write_text(json.dumps({"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "Scanner"}},
        "results": [{"ruleId": "r", "message": {"text": "inspect"}, "locations": [{"physicalLocation": {"artifactLocation": {"uri": "a.c"}, "region": {"startLine": 1}}}]}]}]}))
    c = context_from_sarif([sarif], stages=[StageEnvelope("scan", "completed")])
    complete_reporting(c, run)
    monkeypatch.setattr(reports, "gather_project_annotations", lambda _: [])
    project = SimpleNamespace(name="P", output_path=tmp_path, get_run_dirs=lambda **kwargs: [run])
    stats = reports.generate_project_report(project)
    assert stats["findings"] == 1
    merged = json.loads((tmp_path / "_report" / "findings.json").read_text())["findings"]
    assert merged[0]["status"] == "unconfirmed"


def test_final_project_view_excludes_active_runs(tmp_path, monkeypatch):
    import core.project.report as reports
    run = tmp_path / "active"
    run.mkdir()
    monkeypatch.setattr("core.run.metadata.load_run_metadata", lambda _: {"status": "running"})
    project = SimpleNamespace(name="P", output_path=tmp_path, get_run_dirs=lambda **kwargs: [run])
    stats = reports.generate_project_report(project)
    assert stats["runs"] == 0
    c, _, _ = load_committed_report(tmp_path / "_report")
    assert c.state == "partial" and "active run omitted" in c.diagnostics[0]
