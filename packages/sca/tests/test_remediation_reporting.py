"""Remediation reports observe completed planning/writes without changing mode."""
import json

import pytest

from core.reporting.writer import load_committed_report
from packages.sca import optimise, pipeline
from packages.sca.pipeline import RunResult


def _subject(tmp_path, monkeypatch, *, actionable=True):
    monkeypatch.chdir(tmp_path)
    target = tmp_path / "target"
    target.mkdir()
    manifest = target / "requirements.txt"
    manifest.write_text("owned==1.0.0\n")
    calls = []

    def completed_scan(*, target, output_dir, **kwargs):
        calls.append(target)
        output_dir.mkdir(parents=True, exist_ok=True)
        findings = output_dir / "findings.json"
        row = {"vuln_type": "sca:vulnerable_dependency", "file": str(manifest), "severity": "high",
               "sca": {"ecosystem": "PyPI", "name": "owned", "version": "1.0.0", "pin_style": "exact",
                       "is_lockfile": False, "fixed_version": "1.1.0",
                       "advisory": {"id": "TEST-1", "aliases": [], "fixed_versions": ["1.1.0"]}}}
        findings.write_text(json.dumps([row] if actionable else []))
        return RunResult(target, output_dir, findings, output_dir / "report.md", output_dir / "sbom.json",
                         output_dir / "findings.sarif", 1, int(actionable), 0, 0, 0, 0, 0, 0)

    monkeypatch.setattr(pipeline, "run_sca", completed_scan)
    return target, manifest, calls


@pytest.mark.parametrize("mode", ["plan only", "proposed export", "applied in place"])
def test_fix_report_retains_exact_remediation_mode(tmp_path, monkeypatch, capsys, mode):
    target, manifest, calls = _subject(tmp_path, monkeypatch)
    output = tmp_path / "receipt.json"
    extra = ["--apply"] if mode == "applied in place" else (["--out", str(tmp_path / "out")] if mode == "proposed export" else [])
    assert optimise.main([str(target), "--no-llm", "--no-hash-pin", *extra,
                          "--report-format", "json", "--report-output", str(output)]) == 0
    assert calls == [target]
    assert manifest.read_text() == ("owned==1.1.0\n" if mode == "applied in place" else "owned==1.0.0\n")
    streams = capsys.readouterr()
    assert "Summary" in streams.err
    context, _, _ = load_committed_report(tmp_path / ".receipt-report")
    result = context.extensions["raptor.result"]
    assert result["mode"] == mode and result["planned counts"]["CVE plans"] == 1
    assert result["recorded changes"] == (0 if mode == "plan only" else 1)
    assert result["policy"]["LLM disabled"]
    assert result["CVE plans"][0]["target"] == "1.1.0"


def test_no_actionable_receipt_does_not_claim_clean_scan(tmp_path, monkeypatch, capsys):
    target, manifest, calls = _subject(tmp_path, monkeypatch, actionable=False)
    output = tmp_path / "receipt.json"
    assert optimise.main([str(target), "--no-llm", "--report-format", "json", "--report-output", str(output)]) == 0
    context, _, _ = load_committed_report(tmp_path / ".receipt-report")
    assert context.extensions["raptor.result"]["mode"] == "no actionable changes"
    assert any("not a claim that the scan found no findings" in note for note in context.diagnostics)
    assert calls == [target] and manifest.read_text() == "owned==1.0.0\n"


def test_report_failure_does_not_change_completed_apply(tmp_path, monkeypatch, capsys):
    target, manifest, calls = _subject(tmp_path, monkeypatch)
    blocker = tmp_path / "file"
    blocker.write_text("retained")
    assert optimise.main([str(target), "--apply", "--no-llm", "--no-hash-pin",
                          "--report-output", str(blocker / "receipt.md")]) == 0
    assert calls == [target] and manifest.read_text() == "owned==1.1.0\n"
    assert blocker.read_text() == "retained"
    assert "persistence failed" in capsys.readouterr().err


def test_fix_report_preflight_precedes_scan(tmp_path):
    with pytest.raises(SystemExit) as error:
        optimise.main([str(tmp_path / "missing"), "--report-format", "json"])
    assert error.value.code == 2


def test_blocked_major_capture_does_not_turn_safe_annotation_into_consent(tmp_path, monkeypatch):
    from packages.sca import remediation_reporting
    from packages.sca.llm.schemas import UpgradeImpactVerdict
    from packages.sca.parsers import ParseFailure
    from packages.sca.remediation_reporting import fix_result
    from packages.sca.update import _PlanEntry
    from core.reporting.renderers import render_document
    target, manifest, _ = _subject(tmp_path, monkeypatch)
    scan = pipeline.run_sca(target=target, output_dir=tmp_path / "prepass")
    scan.parse_failures = [ParseFailure(manifest, "owned parser failure")]
    monkeypatch.setattr(remediation_reporting, "DETAIL_LIMIT", 1)
    args = optimise._parse_args([str(target), "--no-llm"])
    plan = _PlanEntry("PyPI", "owned", "1.0.0", "2.0.0", manifest, ["TEST-1"])
    key = ("PyPI", "owned", str(manifest))
    blocked = {key: plan, ("PyPI", "other", str(manifest)): plan}
    verdict = UpgradeImpactVerdict(verdict="safe", confidence="high", summary="</details><script>bad()</script>")
    result = fix_result(args, target=target, out_dir=tmp_path / "receipt", scan_result=scan, mode="plan only",
                        vuln_plans={}, hygiene_plans={}, major_blocked=blocked, changes=[], exit_code=1,
                        llm_approved=set(), llm_verdicts={key: verdict}, hash_pin_receipt=None)
    context, document = result.build()
    payload = context.extensions["raptor.result"]
    assert context.state == "partial" and payload["exit_code"] == 1
    assert payload["planned counts"]["major-version blocked"] == 2
    assert len(payload["major-version blocked"]) == 1
    assert not payload["major-version blocked"][0]["LLM approved"]
    assert payload["major-version blocked"][0]["impact review"]["verdict"] == "safe"
    assert payload["parser failures"] == [{"path": str(manifest), "reason": "owned parser failure"}]
    assert any("captures 1 of 2" in note for note in context.diagnostics)
    assert "<script>" not in render_document(document).content.decode()
