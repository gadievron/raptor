"""Bump exports preserve native streams and separate decisions from writes."""
import json

import pytest

from core.reporting.writer import load_committed_report
from packages.sca.bump import cli, orchestrator
from packages.sca.bump.orchestrator import BumpCandidate, BumpReport, BumpResult
from packages.sca.bump.reporting import bump_result
from packages.sca.findings import build_vuln_findings
from packages.sca.models import Advisory
from packages.sca.osv import OsvResult
from packages.sca.review import _synthesise_dep


def _report(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    source = target / "Dockerfile"
    source.write_text("ARG OWNED_VERSION=1.0.0\n")
    candidate = BumpCandidate("arg", "OWNED_VERSION", source, "1.0.0", "2.0.0")
    return BumpReport(target, [candidate], [BumpResult(candidate, 0, "Clean", [])])


def test_bump_export_preserves_json_and_does_not_copy_cli_token(tmp_path, monkeypatch, capsys):
    report = _report(tmp_path)
    calls = []

    def completed_bump(**kwargs):
        calls.append(kwargs)
        return report

    monkeypatch.setattr(orchestrator, "run_bump", completed_bump)
    output = tmp_path / "receipt.json"
    token = "owned-token-must-not-be-copied"
    assert cli.main([str(report.target), "--apply", "--json", "--offline", "--no-trust-repo",
                     "--github-token", token, "--cache-root", str(tmp_path / "cache"),
                     "--report-format", "json", "--report-output", str(output)]) == 0
    assert len(calls) == 1 and calls[0]["apply"] and calls[0]["github_token"] == token
    streams = capsys.readouterr()
    native = json.loads(streams.out)
    assert native == cli._report_to_dict(report)
    assert "Summary" in streams.err and token not in output.read_text()
    context, _, _ = load_committed_report(tmp_path / ".receipt-report")
    payload = context.extensions["raptor.result"]
    assert payload["recorded verdicts"] == {"clean": 1}
    assert payload["recorded applied results"] == 0
    assert payload["requested mode"] == "apply"
    assert report.candidates[0].file.read_text() == "ARG OWNED_VERSION=1.0.0\n"


def test_capture_retains_new_advisory_metadata_and_full_counts_without_mutation(tmp_path, monkeypatch):
    from packages.sca.bump import reporting
    report = _report(tmp_path)
    dependency = _synthesise_dep("PyPI", "owned", "2.0.0")
    advisory = Advisory("TEST-1", ["CVE-2099-OWNED"], "owned summary", "", [], None, [], [])
    matches = build_vuln_findings([dependency], [OsvResult(dependency.key(), [advisory])])
    assert len(matches) == 1
    row = report.results[0]
    row.bump_vuln_findings = matches * 2
    report.results.append(BumpResult(row.candidate, 1, "Review", [], error="vuln-delta unavailable"))
    monkeypatch.setattr(reporting, "DETAIL_LIMIT", 1)
    context, _ = bump_result(report, apply_requested=False, trust_repo=False).build()
    payload = context.extensions["raptor.result"]
    captured = payload["results"][0]
    assert captured["recorded_new_advisories"] == 2 and len(captured["new_advisories"]) == 1
    assert captured["new_advisories"][0]["sca"]["advisory"]["aliases"] == ["CVE-2099-OWNED"]
    assert payload["recorded counts"]["results"] == 2
    assert payload["recorded result errors"] == 1 and context.state == "partial"
    assert len(report.results) == 2 and len(row.bump_vuln_findings) == 2
    assert any("Per-result report evidence" in note for note in context.diagnostics)


def test_bump_failure_report_retains_error_exit_without_persisting_raw_exception(tmp_path, monkeypatch, capsys):
    report = _report(tmp_path)

    def failed_bump(**kwargs):
        raise RuntimeError("owned-secret-error-not-for-report")

    monkeypatch.setattr(orchestrator, "run_bump", failed_bump)
    output = tmp_path / "failed.json"
    assert cli.main([str(report.target), "--offline", "--no-trust-repo", "--cache-root", str(tmp_path / "cache"),
                     "--report-format", "json", "--report-output", str(output)]) == 3
    assert "owned-secret-error-not-for-report" not in output.read_text()
    context, _, _ = load_committed_report(tmp_path / ".failed-report")
    assert context.state == "failed" and context.extensions["raptor.result"]["error type"] == "RuntimeError"


def test_bump_report_preflight_before_target_lookup(tmp_path):
    with pytest.raises(SystemExit) as error:
        cli.main([str(tmp_path / "missing"), "--report-format", "json"])
    assert error.value.code == 2


def test_bump_report_cannot_replace_candidate_source(tmp_path, monkeypatch, capsys):
    report = _report(tmp_path)
    monkeypatch.setattr(orchestrator, "run_bump", lambda **kwargs: report)
    source = report.candidates[0].file
    before = source.read_bytes()
    assert cli.main([str(report.target), "--offline", "--no-trust-repo",
                     "--cache-root", str(tmp_path / "cache"), "--report-format", "json",
                     "--report-output", str(source)]) == 0
    assert source.read_bytes() == before
    assert "Report persistence failed" in capsys.readouterr().err
