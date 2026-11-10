"""Portable readback redacts captured values while retaining native evidence."""
import json

from core.evidence import EvidenceTier, make_evidence
from core.reporting.options import ReportOptions
from core.reporting.writer import load_committed_report
from packages.binary_analysis.cli import _print_report


def test_binary_evidence_export_redacts_credentials_without_changing_native_bytes(tmp_path):
    evidence = make_evidence("a" * 64, kind="string", source="owned fixture",
                             summary="captured https://user:owned-secret@example.invalid/path",
                             tier=EvidenceTier.OBSERVED_RUNTIME, confidence="candidate", reproducible=False,
                             tool="owned fixture", data={"samples": ["captured https://user:owned-secret@example.invalid/path"]})
    source = tmp_path / "binary-evidence.json"
    source.write_text(json.dumps({"evidence": [evidence.to_dict()]}))
    original = source.read_bytes()
    assert _print_report(str(tmp_path), report_options=ReportOptions(formats=("json",))) == 0
    context, document, _ = load_committed_report(tmp_path)
    assert b"owned-secret" not in (tmp_path / "report-context.json").read_bytes()
    assert "owned-secret" not in json.dumps(document.to_dict())
    assert "owned-secret" not in (tmp_path / "binary-report.json").read_text()
    assert source.read_bytes() == original and b"owned-secret" in original
    assert context.extensions["raptor.result"][source.name]["evidence"][0]["tier"] == "observed_runtime"
    assert context.extensions["raptor.findings_available"] is False


def test_readback_keeps_full_collections_scalars_and_filesystem_names(tmp_path):
    long_text = "captured ordinary text " * 200
    payload = {"binary_path": "/owned/Bearer ordinary/input.bin", "location": {"file": "/owned/Basic ordinary/input.c"},
               "samples": list(range(105)), "long text": long_text, "empty": None, "false": False, "zero": 0}
    source = tmp_path / "binary-evidence.json"
    source.write_text(json.dumps(payload))
    original = source.read_bytes()
    assert _print_report(str(tmp_path), report_options=ReportOptions(formats=("json",))) == 0
    context, _, _ = load_committed_report(tmp_path)
    assert context.extensions["raptor.result"][source.name] == payload
    assert source.read_bytes() == original


def test_overdeep_readback_keeps_minimal_capture_failure_summary(tmp_path):
    nested = "captured"
    for _ in range(45):
        nested = [nested]
    source = tmp_path / "binary-evidence.json"
    source.write_text(json.dumps({"nested": nested}))
    original = source.read_bytes()
    assert _print_report(str(tmp_path), report_options=ReportOptions(formats=("json",))) == 1
    summary = json.loads((tmp_path / "summary.json").read_text())
    assert summary["state"] == "partial"
    assert any("Structured report capture failed" in note for note in summary["diagnostics"])
    assert source.read_bytes() == original
    assert not (tmp_path / "reporting-manifest.json").exists()
