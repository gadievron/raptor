"""Verification capture must not rescan or change domain gate status."""
import json
from pathlib import Path

import pytest

from core.json import JsonCache
from packages.sca import verify
from packages.sca.diff import DeltaResult
from packages.sca.pipeline import RunResult
from packages.sca.verify_reporting import verification_result


@pytest.mark.parametrize("degraded,exit_code", [(False, 0), (True, 4)])
def test_verify_export_captures_existing_scans_and_unavailability(tmp_path, monkeypatch, capsys, degraded, exit_code):
    target, proposed = tmp_path / "target", tmp_path / "proposed"
    target.mkdir()
    proposed.mkdir()
    (target / "requirements.txt").write_text("owned==1\n")
    (proposed / "requirements.txt").write_text("owned==2\n")
    calls = []

    def completed_scan(*, target, output_dir, **kwargs):
        calls.append(target)
        output_dir.mkdir(parents=True)
        findings = output_dir / "findings.json"
        findings.write_text(json.dumps([{"vuln_type": "sca:scan_health:osv_lookup_degraded", "severity": "info"}] if degraded else []))
        return RunResult(target, output_dir, findings, output_dir / "report.md", output_dir / "sbom.json",
                         output_dir / "findings.sarif", 1, 0, 0, 0, 0, 0, 0, 0)

    monkeypatch.setattr(verify, "run_sca", completed_scan)
    output = tmp_path / "verification.json"
    rc = verify.main([str(target), "--proposed", str(proposed), "--out", str(tmp_path / "out"),
                      "--report-format", "json", "--report-output", str(output)],
                     http=verify.default_client(offline=True), cache=JsonCache(root=tmp_path / "cache"))
    assert rc == exit_code and len(calls) == 2
    assert (target / "requirements.txt").read_text() == "owned==1\n"
    streams = capsys.readouterr()
    assert "Summary" in streams.err and "Verdict" in streams.out
    from core.reporting.writer import load_committed_report
    context, _, _ = load_committed_report(tmp_path / ".verification-report")
    payload = context.extensions["raptor.result"]
    assert payload["exit_code"] == exit_code
    assert payload["advisory coverage degraded"] is degraded
    assert context.state == ("partial" if degraded else "completed")
    assert not payload["baseline reused"]


def test_verification_projection_keeps_targeted_gate_counts_and_binds_content(monkeypatch):
    from packages.sca import verify_reporting
    monkeypatch.setattr(verify_reporting, "DETAIL_LIMIT", 1)
    row = {"severity": "high", "file": "untouched.txt", "sca": {"name": "owned"}}
    delta = DeltaResult(new=[], resolved=[], suppression_added=[], suppression_lifted=[], persistent=[row, row])
    summary = {"persistent_above_threshold": 2, "not_cleared_above_threshold": 0, "severity_threshold": "high"}
    result = verification_result(target=Path("target"), proposed=Path("proposed"), applied=[Path("patched.txt")],
                                 delta=delta, summary=summary, osv_degraded=False, exit_code=0,
                                 before_findings=Path("before.json"), after_findings=Path("after.json"),
                                 out_dir=Path("output"), baseline_reused=True)
    context, document = result.build()
    payload = context.extensions["raptor.result"]
    assert payload["category counts"]["persistent"] == 2 and len(payload["persistent"]) == 1
    assert payload["summary"] == summary and payload["exit_code"] == 0
    assert payload["baseline reused"]
    assert any("captures 1 of 2" in note for note in context.diagnostics)
    assert document.snapshot_id == context.snapshot_id


def test_verify_report_preflight_before_target_or_network(tmp_path, capsys):
    with pytest.raises(SystemExit) as error:
        verify.main([str(tmp_path / "missing"), "--proposed", str(tmp_path / "missing-too"), "--report-format", "json"])
    assert error.value.code == 2
    assert "requires --report-output" in capsys.readouterr().err
