"""Gadget reports preserve captured census limits and native CLI policies."""
from copy import deepcopy
import json

import pytest

from core.analysis import gadget_oracle as oracle
from core.analysis import gadget_oracle_cli as cli
from core.analysis import gadget_reporting as reports
from core.reporting.document import ReportDocument
from core.reporting.renderers import render_document
from core.reporting.writer import load_committed_report, regenerate
from core.testing.module_views import scoped_function_imports


def _report(target):
    return {"target_path": str(target), "tier": "hint", "absence_tier": "recorded-native-tier",
            "producer": {"module": "gadget_oracle", "version": "test-captured"},
            "census": {"complete": False, "php_files": 4, "parsed_clean": 3,
                       "read_error_count": 1, "incomplete_reasons": ["read_error"]},
            "analysis_depth": {"inheritance_resolved": False, "flow_insensitive": True},
            "chains": [{"file": "|\n<script>file</script>\x1b[2J", "class": "Witness", "magic_method": "__destruct",
                        "property_path": "value", "availability": "not_established",
                        "sink": {"category": "output", "callee": "echo", "line": 2}}],
            "unserialize_sites": [], "unserialize_sites_total": 20, "unserialize_sites_truncated": True,
            "chains_truncated": True, "census_detail": {"read_error_files": ["private-path"]}}


def test_captured_document_preserves_native_limits_without_rescanning(tmp_path):
    report = _report(tmp_path)
    before = deepcopy(report)
    document = reports.build_document(report)
    assert document.metadata["Native absence tier"] == "recorded-native-tier"
    assert document.summary["Census complete"] is False
    assert document.summary["Retained chains"] == 1 and document.summary["Retained unserialize sites"] == 0
    assert document.summary["Native unserialize sites total"] == 20
    assert document.summary["Native chain truncation"] is True
    assert document.summary["Native site truncation"] is True
    assert ReportDocument.from_dict(document.to_dict()).to_dict() == document.to_dict()
    for format in ("markdown", "json", "xml"):
        result = render_document(document, format).content.decode()
        assert "read_error_count" in result and "not_established" in result
        assert "private-path" not in result and "\x1b" not in result
        if format != "json":
            assert "<script>" not in result
    assert report == before


def test_bounded_projection_discloses_omitted_rows_without_merging_labels(tmp_path):
    report = _report(tmp_path)
    report["magic_method_census"] = {"by_method": {f"method{i}": i for i in range(1005)}}
    report["chains"] = report["chains"] * 102 + [None]
    # Malformed retained witness is distinct from the portable row cap.
    report["chains"][0] = None
    document = reports.build_document(report)
    assert document.extensions["raptor.capture_limited"] is True
    assert document.extensions["raptor.rows_omitted"]["magic_method_census"] == 5
    assert document.extensions["raptor.rows_omitted"]["witness rows"] == 3
    assert document.extensions["raptor.witness_rows_rejected"] == 1
    rows = next(b.rows for b in document.blocks if b.title == "magic_method_census")
    assert rows[0][-1] == 0 and rows[-1][-1] == 999


@pytest.mark.parametrize("mode", ["default", "disabled", "json", "export"])
def test_cli_captures_once_and_preserves_native_display(tmp_path, monkeypatch, capsys, mode):
    target = tmp_path / "source"
    target.mkdir()
    result = _report(target)
    calls = []
    def scan(root, **kwargs):
        calls.append(root)
        return result
    flags = [] if mode == "default" else ["--no-report"] if mode == "disabled" else ["--json"] if mode == "json" else ["--json", "--report-format", "json", "--report-format", "xml", "--report-output", str(tmp_path / "reports")]
    with scoped_function_imports(cli, ["main"], {"core.analysis.gadget_oracle": oracle}) as imports:
        private = getattr(imports, "core.analysis.gadget_oracle")
        monkeypatch.setattr(private, "scan_tree", scan)
        monkeypatch.setattr(private, "php_grammar_available", lambda: True)
        assert cli.main([str(target), *flags]) == 0
    shown = capsys.readouterr()
    if mode in {"json", "export"}:
        assert json.loads(shown.out) == result
    else:
        assert "Census:" in shown.out and "\x1b" not in shown.out
    assert calls == [target] and "gadget-scan" in shown.err
    assert "Optional gadget report unavailable" not in shown.err
    if mode == "export":
        root = tmp_path / "reports"
        context, document, _ = load_committed_report(root)
        assert context.state == "partial" and context.stages[0].state == "partial"
        assert context.extensions["raptor.findings_available"] is False
        assert document.metadata["Native absence tier"] == result["absence_tier"]
        rendered = (root / "gadget-oracle.xml").read_bytes()
        def refuse(*args, **kwargs):
            raise AssertionError("offline render ran scanner")
        monkeypatch.setattr(oracle, "scan_tree", refuse)
        regenerate(root, tmp_path / "offline.xml", format="xml")
        assert (tmp_path / "offline.xml").read_bytes() == rendered
    else:
        assert not (tmp_path / "reports").exists() and not (tmp_path / "portable-reports").exists()


@pytest.mark.parametrize("kind", ["missing-destination", "format", "native-collision", "target-collision"])
def test_refusal_before_scan_or_native_write(tmp_path, monkeypatch, kind):
    target = tmp_path / "source"
    target.mkdir()
    native = tmp_path / "native"
    native.mkdir()
    artifact = native / "gadget-chains.json"
    artifact.write_text("native old evidence")
    source = target / "composer.json"
    source.write_text("source old content")
    flags = {"missing-destination": ["--report-format", "json"],
             "format": ["--report-format", "not-available"],
             "native-collision": ["--out", str(native), "--report-format", "json", "--report-output", str(artifact)],
             "target-collision": ["--report-format", "json", "--report-output", str(source)]}[kind]
    with scoped_function_imports(cli, ["main"], {"core.analysis.gadget_oracle": oracle}) as imports:
        private = getattr(imports, "core.analysis.gadget_oracle")
        def refuse(*args, **kwargs):
            raise AssertionError("preflight reached native scanner")
        monkeypatch.setattr(private, "scan_tree", refuse)
        with pytest.raises(SystemExit) as exc:
            cli.main([str(target), *flags])
    assert exc.value.code == 2
    assert artifact.read_text() == "native old evidence" and source.read_text() == "source old content"


def test_report_fault_does_not_change_native_zero_exit(tmp_path, monkeypatch, capsys):
    reached = []
    def fail(*args, **kwargs):
        reached.append(True)
        raise OSError("private failure")
    monkeypatch.setattr(reports, "complete_reporting", fail)
    target = tmp_path / "source"
    target.mkdir()
    with scoped_function_imports(cli, ["main"], {"core.analysis.gadget_oracle": oracle}) as imports:
        private = getattr(imports, "core.analysis.gadget_oracle")
        monkeypatch.setattr(private, "php_grammar_available", lambda: True)
        monkeypatch.setattr(private, "scan_tree", lambda *a, **k: _report(target))
        assert cli.main([str(target), "--json", "--report-output", str(tmp_path / "reports")]) == 0
    shown = capsys.readouterr()
    assert json.loads(shown.out)["tier"] == "hint" and reached == [True]
    assert "native result retained" in shown.err and "private failure" not in shown.err


def test_original_missing_target_and_capability_exit_codes(tmp_path, monkeypatch):
    assert cli.main([str(tmp_path / "missing")]) == 1
    with scoped_function_imports(cli, ["main"], {"core.analysis.gadget_oracle": oracle}) as imports:
        monkeypatch.setattr(getattr(imports, "core.analysis.gadget_oracle"), "php_grammar_available", lambda: False)
        assert cli.main([str(tmp_path)]) == 3


def test_real_php_snapshot_keeps_native_artifact_while_exporting(tmp_path, monkeypatch):
    if not oracle.php_grammar_available():
        pytest.skip("actual tree-sitter-php required for native producer control")
    target = tmp_path / "source"
    target.mkdir()
    (target / "one.php").write_text("<?php class Sample { public $value; function __destruct() { echo $this->value; } }")
    root = tmp_path / "native"
    calls = []
    original = oracle.scan_tree
    def capture(*args, **kwargs):
        report = original(*args, **kwargs)
        calls.append(deepcopy(report))
        return report
    with scoped_function_imports(cli, ["main"], {"core.analysis.gadget_oracle": oracle}) as imports:
        monkeypatch.setattr(getattr(imports, "core.analysis.gadget_oracle"), "scan_tree", capture)
        assert cli.main([str(target), "--out", str(root), "--report-format", "json"]) == 0
    assert len(calls) == 1
    native = json.loads((root / "gadget-chains.json").read_text())
    assert native == calls[0]
    context, document, _ = load_committed_report(root / "portable-reports")
    assert document.summary["Parsed clean"] == native["census"]["parsed_clean"] == 1
    assert document.metadata["Native absence tier"] == native["absence_tier"]
    assert context.extensions["raptor.findings_available"] is False


def test_depth_loss_unavailable_scalars_and_autoload_unknown_are_distinct(tmp_path):
    report = _report(tmp_path)
    nested = {"leaf": 3}
    for _ in range(10):
        nested = {"nested": nested}
    report["analysis_depth"] = {"nested_payload": nested, "invalid_rate": float("nan")}
    document = reports.build_document(report)
    assert document.summary["Autoload registered"] is None
    assert document.summary["Retained autoload sites"] is None
    assert document.extensions["raptor.metadata_subtrees_omitted"]["analysis_depth"] == 1
    assert document.extensions["raptor.rows_omitted"]["analysis_depth"] == 0
    assert document.extensions["raptor.metadata_values_unavailable"]["analysis_depth"] == 1
    assert document.extensions["raptor.capture_limited"] is True
    assert "inside omitted subtrees is unknown" in " ".join(document.diagnostics)
    report["autoload"] = {"registered": False, "sites": []}
    observed = reports.build_document(report)
    assert observed.summary["Autoload registered"] is False
    assert observed.summary["Retained autoload sites"] == 0
    for format in ("markdown", "json", "xml"):
        assert render_document(observed, format).content
