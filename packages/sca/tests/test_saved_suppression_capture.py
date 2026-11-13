"""Saved SCA suppression admission at portable capture."""
from __future__ import annotations

import json

import pytest

from core.reporting.writer import load_committed_report
from packages.sca import render
from packages.sca.reporting import build_sca_document
from packages.sca.rows import FindingRow
from packages.sca.tests.test_render import _vuln_row


@pytest.mark.parametrize("value", ["yes", None, 0, [], {}], ids=["text", "null", "integer", "list", "object"])
def test_builder_refuses_supplied_nonboolean_suppression(tmp_path, value):
    row = _vuln_row()
    row["suppressed"] = value
    original = json.dumps(row, sort_keys=True)
    with pytest.raises(ValueError, match="suppression status must be a boolean"):
        build_sca_document(rows=iter([row]), target=tmp_path, output_dir=tmp_path, deps_analysed=None, rerender=True)
    assert json.dumps(row, sort_keys=True) == original


@pytest.mark.parametrize("value", [True, False, "missing"], ids=["suppressed", "active", "absent"])
def test_canonical_saved_suppression_remains_captured(tmp_path, value):
    row = _vuln_row()
    if value == "missing":
        row.pop("suppressed")
    else:
        row["suppressed"] = value
    source = tmp_path / "findings.json"
    source.write_text(json.dumps([row]))
    original = source.read_bytes()
    assert render.main([str(source), "--no-sarif", "--report-format", "json", "--report-format", "markdown"]) == 0
    context, document, _ = load_committed_report(tmp_path)
    assert context.findings[0]["suppressed"] is (value is True)
    assert document.summary["KEV matches"] == (0 if value is True else 1)
    assert source.read_bytes() == original


@pytest.mark.parametrize("prior", [False, True], ids=["fresh", "retained"])
def test_saved_malformed_suppression_is_unavailable_without_replacing_report(tmp_path, capsys, prior):
    source = tmp_path / "findings.json"
    source.write_text(json.dumps([_vuln_row()]))
    argv = [str(source), "--no-sarif", "--report-format", "json", "--report-format", "markdown"]
    previous = None
    if prior:
        assert render.main(argv) == 0
        previous = load_committed_report(tmp_path)
    protected = {str(p.relative_to(tmp_path)): p.read_bytes() for p in tmp_path.rglob("*")
                 if p.is_file() and p.name not in {"findings.json", "summary.json", "summary.md"}}
    capsys.readouterr()
    row = _vuln_row()
    row["suppressed"] = "yes"
    source.write_text(json.dumps([row]))
    original = source.read_bytes()
    assert FindingRow.from_row(row).suppressed is True
    assert render.main([*argv, "--fail-on-kev"]) == 2
    output = capsys.readouterr()
    assert "suppression status must be a boolean" in output.err
    assert "Structured report capture failed (InvalidSuppressionError)" in output.out
    summary = json.loads((tmp_path / "summary.json").read_text())
    assert summary["findings_available"] is False
    assert summary["state"] == "partial"
    assert source.read_bytes() == original
    remaining = {str(p.relative_to(tmp_path)): p.read_bytes() for p in tmp_path.rglob("*")
                 if p.is_file() and p.name not in {"findings.json", "summary.json", "summary.md"}}
    if not prior:
        assert remaining.pop(".reporting/.lock") == b""
    assert remaining == protected
    if prior:
        assert load_committed_report(tmp_path) == previous
    else:
        assert not (tmp_path / "reporting-manifest.json").exists()


def test_malformed_suppression_beyond_detail_cap_refuses(tmp_path, monkeypatch):
    from packages.sca import reporting
    monkeypatch.setattr(reporting, "MAX_FINDINGS", 1)
    bad = _vuln_row()
    bad["suppressed"] = "yes"
    with pytest.raises(ValueError, match="suppression status must be a boolean"):
        build_sca_document(rows=iter([_vuln_row(), bad]), target=tmp_path, output_dir=tmp_path, deps_analysed=None)


@pytest.mark.parametrize("value", ["PRIVATE-SUPPRESSION-VALUE", ""], ids=["text", "empty-text"])
def test_no_gate_refusal_explains_suppression_without_echoing_value(tmp_path, monkeypatch, capsys, value):
    from packages.sca import pipeline
    def no_analysis(*args, **kwargs):
        pytest.fail("saved render must not analyse dependencies")
    monkeypatch.setattr(pipeline, "run_sca", no_analysis)
    row = _vuln_row()
    row["suppressed"] = value
    source = tmp_path / "findings.json"
    source.write_text(json.dumps([row]))
    original = source.read_bytes()
    assert render.main([str(source), "--no-sarif", "--report-format", "json"]) == 1
    output = capsys.readouterr()
    assert "suppressed must be JSON true or false, or omitted" in output.err
    assert "PRIVATE-SUPPRESSION-VALUE" not in output.err + output.out
    assert "wrote json" not in output.out
    assert not (tmp_path / "report.json").exists()
    assert not (tmp_path / "reporting-manifest.json").exists()
    assert json.loads((tmp_path / "summary.json").read_text())["findings_available"] is False
    assert source.read_bytes() == original
