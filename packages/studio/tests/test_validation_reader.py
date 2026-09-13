"""Tests for validation bundle + run summary reader."""

from __future__ import annotations

import json
from pathlib import Path

from packages.studio.services.validation_reader import load_validation_bundle, summarize_run


def test_empty_bundle(tmp_path: Path):
    bundle = load_validation_bundle(tmp_path)
    assert not bundle.has_any
    assert bundle.counts == {
        "checklist": 0, "findings": 0, "attack_tree": 0,
        "hypotheses": 0, "disproven": 0, "attack_paths": 0,
    }


def test_bundle_reads_artifacts(tmp_path: Path):
    (tmp_path / "findings.json").write_text(json.dumps([{"id": "F-1"}, {"id": "F-2"}]))
    (tmp_path / "attack-surface.json").write_text(json.dumps({
        "sources": ["request.args"], "sinks": ["os.system"], "trust_boundaries": ["http"],
    }))
    (tmp_path / "hypotheses.json").write_text(json.dumps([{"hypothesis": "a"}]))
    (tmp_path / "disproven.json").write_text(json.dumps([{"approach": "x"}, {"approach": "y"}]))
    (tmp_path / "validation-report.md").write_text("# report")

    bundle = load_validation_bundle(tmp_path)
    assert bundle.has_any
    assert bundle.counts["findings"] == 2
    assert bundle.counts["hypotheses"] == 1
    assert bundle.counts["disproven"] == 2
    assert bundle.attack_surface["sources"] == ["request.args"]
    assert bundle.report_md.startswith("# report")


def test_summarize_run_empty(tmp_path: Path):
    s = summarize_run(tmp_path)
    assert s.has_sarif is False
    assert s.findings_count == 0
    assert s.has_exploits is False
    assert s.has_validation_bundle is False


def test_summarize_run_with_scan_artifacts(tmp_path: Path):
    (tmp_path / "semgrep.sarif").write_text(json.dumps({"version": "2.1.0", "runs": []}))
    (tmp_path / "findings.json").write_text(json.dumps([{"id": "A"}, {"id": "B"}, {"id": "C"}]))
    (tmp_path / "scan_metrics.json").write_text(json.dumps({"files_scanned": 42}))

    exp_dir = tmp_path / "exploits"
    exp_dir.mkdir()
    (exp_dir / "poc.py").write_text("# poc")

    (tmp_path / "patches").mkdir()
    (tmp_path / "patches" / "fix.patch").write_text("")

    (tmp_path / "validation-report.md").write_text("report")

    s = summarize_run(tmp_path)
    assert s.has_sarif
    assert s.sarif_files == ["semgrep.sarif"]
    assert s.has_findings_json
    assert s.findings_count == 3
    assert s.has_scan_metrics
    assert s.scan_metrics["files_scanned"] == 42
    assert s.has_exploits
    assert s.exploits_count == 1
    assert s.has_patches
    assert s.patches_count == 1
    assert s.has_reports
    assert "validation-report.md" in s.report_files


def test_summarize_fuzz_run(tmp_path: Path):
    (tmp_path / "fuzzing_report.json").write_text(json.dumps({"crashes": 5, "cost": 0.12}))
    crashes = tmp_path / "afl_output" / "main" / "crashes"
    crashes.mkdir(parents=True)
    (crashes / "id:000000").write_text("")
    (crashes / "id:000001").write_text("")
    (crashes / "README.txt").write_text("")  # should be excluded from count

    s = summarize_run(tmp_path)
    assert s.fuzzing_report["crashes"] == 5
    assert s.afl_crashes_count == 2


def test_summarize_detects_validation_bundle(tmp_path: Path):
    (tmp_path / "findings.json").write_text(json.dumps([{"id": "F-1"}]))
    (tmp_path / "attack-tree.json").write_text(json.dumps([{"node": "a"}]))
    s = summarize_run(tmp_path)
    assert s.has_validation_bundle
    assert s.validation_counts["findings"] == 1
    assert s.validation_counts["attack_tree"] == 1


def test_summarize_pairs_dataflow_svg_with_json(tmp_path: Path):
    (tmp_path / "dataflow_sql_injection.svg").write_text("<svg/>")
    (tmp_path / "dataflow_sql_injection.json").write_text(json.dumps({"path": []}))
    (tmp_path / "dataflow_xss.svg").write_text("<svg/>")  # no json pair
    s = summarize_run(tmp_path)
    by_name = {d.name: d for d in s.dataflow_diagrams}
    assert "dataflow_sql_injection" in by_name
    assert by_name["dataflow_sql_injection"].json_filename == "dataflow_sql_injection.json"
    assert by_name["dataflow_xss"].json_filename is None


def test_summarize_ignores_non_dataflow_svgs(tmp_path: Path):
    (tmp_path / "logo.svg").write_text("<svg/>")
    s = summarize_run(tmp_path)
    assert s.dataflow_diagrams == []
