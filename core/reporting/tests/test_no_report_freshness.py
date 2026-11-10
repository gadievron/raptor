"""Disabled exports preserve native output and disclose retained old receipts."""
from io import StringIO

import pytest

from core.reporting.document import ReportContext
from core.reporting.options import ReportOptions
from core.reporting.service import complete_reporting
from core.testing.logging_state import isolated_cli_logging


@pytest.mark.parametrize("previous", [False, True])
def test_disabled_service_discloses_retained_files_without_building_document(tmp_path, previous):
    marker = tmp_path / "reporting-manifest.json"
    if previous:
        prior = ReportContext("prior", "prior", extensions={"raptor.findings_available": False})
        assert not complete_reporting(prior, tmp_path, stream=StringIO()).errors
        prior_marker = marker.read_bytes()
        prior_report = (tmp_path / "report.md").read_bytes()
    context = ReportContext("owned", "owned", extensions={"raptor.findings_available": False})
    stream = StringIO()
    result = complete_reporting(context, tmp_path, options=ReportOptions(enabled=False), stream=stream,
                                 document_factory=lambda context: pytest.fail("disabled export must not build a document"))
    assert not result.errors
    assert ("prior report artifacts were not refreshed" in stream.getvalue()) == previous
    assert "Structured command result captured" in stream.getvalue()
    if previous:
        assert marker.read_bytes() == prior_marker
        assert (tmp_path / "report.md").read_bytes() == prior_report
    else:
        assert not (tmp_path / "report.md").exists()


@isolated_cli_logging()
def test_frida_disabled_receipt_warns_once_and_keeps_native_status(tmp_path, monkeypatch, capsys):
    from packages.frida import cli, runner
    marker = tmp_path / "reporting-manifest.json"
    marker.write_text("owned previous generation")
    monkeypatch.setattr(cli, "run", lambda cfg: runner.RunResult(ok=True, events_captured=3))
    monkeypatch.setattr(cli, "_maybe_harvest_seeds", lambda path: None)
    monkeypatch.setattr(cli, "_maybe_correlate_io", lambda path: None)
    assert cli.main(["--target", "1234", "--out", str(tmp_path), "--template", "api-trace", "--no-report"]) == 0
    streams = capsys.readouterr()
    assert "3 events captured" in streams.out
    assert streams.err.count("prior report artifacts were not refreshed") == 1
    assert marker.read_text() == "owned previous generation"
    assert not (tmp_path / "frida-capture-report.md").exists()


@isolated_cli_logging()
def test_binary_disabled_receipt_warns_once_without_duplicate_completion(tmp_path, monkeypatch, capsys):
    from packages.binary_analysis import cli
    from packages.binary_analysis.manifest import BinaryManifest
    from packages.binary_analysis.pipeline import BinaryAnalysisResult
    binary = tmp_path / "sample"
    binary.write_bytes(b"owned")
    out = tmp_path / "out"
    out.mkdir()
    marker = out / "reporting-manifest.json"
    marker.write_text("owned previous generation")
    manifest = BinaryManifest(schema_version=1, binary_path=str(binary), binary_sha256="a" * 64,
                              size_bytes=5, executable=True, target_kind="elf", arch="x86", bits=64, binary_format="elf")
    result = BinaryAnalysisResult(manifest, {"entry_points": []}, [], [], out / "graph.sqlite")
    monkeypatch.setattr(cli, "analyse_blackbox_binary", lambda *args, **kwargs: result)
    monkeypatch.setattr(cli, "start_run", lambda *args, **kwargs: out)
    monkeypatch.setattr(cli, "complete_run", lambda *args, **kwargs: None)
    assert cli.main(["map", str(binary), "--out", str(out), "--no-report"]) == 0
    streams = capsys.readouterr()
    assert "Items: 0" in streams.out and streams.err.count("prior report artifacts were not refreshed") == 1
    assert marker.read_text() == "owned previous generation"
    assert not (out / "binary-map-report.md").exists()
