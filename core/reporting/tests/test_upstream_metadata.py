"""Reporting projections for producer metadata added on main through 50821ebba."""
import pytest

from core.reporting.adapters import apply_scan_metrics
from core.reporting.builders import build_document
from core.reporting.document import ReportContext
from core.reporting.summary import build_operator_summary


@pytest.mark.parametrize("metrics", [
    {"execution_status": "partial", "sarif_input_errors": 1},
    {"execution_status": "ok", "tool_coverage_limitations": {"semgrep": 2}},
    {"semgrep_metadata_errors": 1},
    {"execution_status": "unexpected"},
])
def test_zero_findings_does_not_hide_recorded_scan_failure(metrics):
    context = ReportContext("scan", "run", state="completed")
    apply_scan_metrics(context, metrics)
    summary = build_operator_summary(context)
    assert summary.total == 0
    assert summary.state == "partial"
    assert summary.metrics["Scan execution"] == "partial"
    assert summary.diagnostics
    block = next(b for b in build_document(context).blocks if b.title == "Recorded scan execution and coverage")
    import json
    assert json.loads(block.text) == metrics


def test_empty_coverage_snapshot_is_preserved_and_old_status_remains_unknown():
    context = ReportContext("scan", "run")
    apply_scan_metrics(context, {"tool_coverage": {}})
    assert context.extensions["raptor.scan_metrics"]["tool_coverage"] == {}
    assert build_operator_summary(context).state == "unknown"
    assert "Scan execution" not in build_operator_summary(context).metrics


@pytest.mark.parametrize("format", ["markdown", "html", "json", "xml"])
def test_source_package_fix_is_labelled_in_sca_report(tmp_path, format):
    from packages.sca.reporting import build_sca_document
    from core.reporting.renderers import render_document
    row = {"id": "V1", "vuln_type": "sca:vulnerable_dependency", "severity": "high",
           "sca": {"ecosystem": "Debian", "name": "libexample-bin", "version": "1",
                   "fixed_version": "2", "advisory": {"id": "ADV-1"},
                   "advisory_package": {"ecosystem": "Debian", "name": "example-src", "version": "1"},
                   "advisory_match_scope": "source_package"}}
    context, document = build_sca_document(rows=[row], target=tmp_path, output_dir=tmp_path, deps_analysed=1)
    text = render_document(document, format).content.decode()
    assert "Source package fixed version" in text
    assert "Source package Debian:example-src@1: 2" in text
    assert context.findings[0]["native"] == row


def test_sca_cache_accounting_is_captured_in_snapshot_identity(tmp_path):
    from packages.sca.reporting import build_sca_document
    first, document = build_sca_document(rows=[], target=tmp_path, output_dir=tmp_path,
                                         deps_analysed=3, cache_hits=2, cache_misses=1, cache_evictions=0)
    second, _ = build_sca_document(rows=[], target=tmp_path, output_dir=tmp_path,
                                   deps_analysed=3, cache_hits=2, cache_misses=1, cache_evictions=1)
    assert document.summary["Cache evictions"] == 0
    assert first.extensions["raptor.metrics"]["Cache evictions"] == 0
    assert first.snapshot_id != second.snapshot_id


def test_sarif_location_and_rule_namespace_metadata_survive_capture(tmp_path):
    from core.json import save_json
    from core.reporting.adapters import context_from_sarif
    source = tmp_path / "scan.sarif"
    namespace = "a" * 64
    save_json(source, {"version": "2.1.0", "runs": [{
        "tool": {"driver": {"name": "fixture", "rules": [{"id": "R", "properties": {"raptor_rule_scope": namespace}}]}},
        "results": [{"ruleId": "R", "message": {"text": "claim"}, "locations": [{
            "logicalLocations": [{"kind": "function", "name": "parse"}],
            "physicalLocation": {"artifactLocation": {"uri": "a.c"},
                                 "region": {"startLine": 2, "endLine": 4, "startColumn": 3, "endColumn": 5}}
        }]}]
    }]})
    context = context_from_sarif([source])
    finding = context.findings[0]
    assert finding["function"] == "parse" and finding["rule_scope"] == namespace
    assert (finding["end_line"], finding["start_column"], finding["end_column"]) == (4, 3, 5)
    def blocks(items):
        for block in items:
            yield block
            yield from blocks(block.children)
    assert any(block.title == "Scanner location and namespace" for block in blocks(build_document(context).blocks))
    assert finding["status"] == "Unconfirmed"


def test_sca_summary_announces_only_current_outputs_and_escapes_paths(tmp_path, capsys):
    from packages.sca.cli import _print_summary
    from packages.sca.pipeline import RunResult
    report = tmp_path / "stale-report.md"
    report.write_text("old report")
    report.with_suffix(".html").write_text("old HTML")
    result = RunResult(target=tmp_path / "source\x1b[31m\nFORGED", output_dir=tmp_path,
                       findings_path=tmp_path / "findings.json", report_path=report,
                       sbom_path=tmp_path / "sbom.cdx.json", sarif_path=tmp_path / "findings.sarif",
                       deps_analysed=0, vuln_findings=0, hygiene_findings=0, supply_chain_findings=0,
                       suppressed_findings=0, in_kev=0, cache_hits=0, cache_misses=0)
    _print_summary(result)
    text = capsys.readouterr().out
    assert "\x1b" not in text and "\nFORGED" not in text
    assert "full report" in text and "stale-report" not in text
