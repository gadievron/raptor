"""CVE triage export consumes captured data without replay or verdict inference."""
from __future__ import annotations

from dataclasses import replace
import json

import pytest

from core.reporting.options import ReportOptions
from cve_diff.analysis.analyzer import RootCause
from cve_diff.core.models import CommitSha, DiffBundle, FileChange, RepoRef
from cve_diff.report import completion

_CVE = "CVE-2024-99001"


def _bundle():
    return DiffBundle(_CVE, RepoRef("https://github.com/example/project", CommitSha("a" * 40), CommitSha("b" * 40), 100),
                      CommitSha("b" * 40), CommitSha("a" * 40), "native private diff", 1, 19,
                      files=(FileChange("source.c", False, 1, "private before", "private after"),),
                      consensus={"agreement_count": 1, "attempted_count": 2,
                                 "methods": [{"name": "osv", "found": True, "slug": "example/project", "sha": "a" * 40}]},
                      extraction_agreement={"verdict": "partial", "sources": [{"name": "clone", "files": 1, "bytes": 19},
                                                                                {"name": "github_api", "files": 2, "bytes": 30}],
                                            "pairwise": {"clone:github_api": "partial"}, "outliers": []})


def _read(out):
    return json.loads((out / "portable-reports" / _CVE / "report-context.json").read_text())


def test_success_preserves_scope_costs_native_bytes_and_privacy(tmp_path, capsys):
    out = tmp_path / "run"
    out.mkdir()
    native = out / (_CVE + ".osv.json")
    native.write_text('{"native":true}')
    (out / ".raptor-run.json").write_text('{"run_id":"old-other-command"}')
    root_cause = RootCause("CWE-78", "command injection", "recorded hypothesis", ("input reaches sink",), ("handler",), 0.8, "model", 12, 8)
    telemetry = {"cost_usd": 0.25, "tokens": 20, "tool_calls": ["osv_raw"],
                 "tool_calls_with_args": [["http_fetch", "private arguments"]], "prompt": "private prompt"}
    before = native.read_bytes()
    result = completion.complete_cve_report(ReportOptions(("json",)), out, _CVE, 0, bundle=_bundle(), root_cause=root_cause,
                                            telemetry=telemetry, stage_status={"diff": {"status": "ok"}})
    assert not result.errors
    context = _read(out)
    data = context["extensions"]["raptor.result"]
    assert context["run_id"] == "unknown"
    assert context["state"] == "completed"
    assert data["bundle"]["files_changed"] == 1
    assert data["root_cause"]["input_tokens"] == 12
    assert data["discovery_telemetry"]["fields"]["cost_usd"] == 0.25
    assert data["discovery_telemetry"]["fields_not_projected"] == 2
    assert data["extraction_agreement"]["pairwise"]["entries"][0]["recorded_value"] == "partial"
    assert [dict(row["entries"])["files"] for row in data["extraction_agreement"]["sources"]["entries"]] == [1, 2]
    assert context["extensions"]["raptor.metrics"]["Discovery cost USD"] == 0.25
    assert any("No complete monetary total" in note for note in context["diagnostics"])
    serialized = json.dumps(context)
    assert not any(text in serialized for text in ["native private diff", "private before", "private after", "private arguments", "private prompt", "old-other-command"])
    assert native.read_bytes() == before
    assert capsys.readouterr().err.count("Native exit status") == 1


@pytest.mark.parametrize("status,state", [(0, "partial"), (9, "failed")])
def test_root_cause_failure_preserves_native_exit_policy(tmp_path, status, state):
    out = tmp_path / "run"
    result = completion.complete_cve_report(ReportOptions(("json",)), out, _CVE, status, bundle=_bundle(),
                                            root_cause_requested=True, root_cause_error="analysis unavailable")
    assert not result.errors
    context = _read(out)
    assert context["state"] == state
    assert context["extensions"]["raptor.result"]["native_exit_status"] == status
    assert next(stage for stage in context["stages"] if stage["stage_id"] == "root-cause analysis")["state"] == "failed"


def test_failed_attempt_has_unavailable_diff_populations(tmp_path):
    out = tmp_path / "run"
    result = completion.complete_cve_report(ReportOptions(("json",)), out, _CVE, 5,
                                            error_class="DiscoveryError", error_detail="no public reference",
                                            stage_status={"discover": {"status": "fail", "reason": "no reference"}})
    assert not result.errors
    context = _read(out)
    assert context["state"] == "failed"
    assert context["extensions"]["raptor.result"]["bundle"] is None
    assert "Files changed" not in context["extensions"]["raptor.metrics"]
    assert context["stages"][0]["state"] == "failed"
    assert any("unavailable, not zero" in note for note in context["diagnostics"])


def test_caps_and_nonfinite_metadata_are_explicit(tmp_path):
    out = tmp_path / "run"
    bundle = replace(_bundle(), files=tuple(FileChange(f"source-{i}.c", False, 1) for i in range(103)), files_changed=103)
    result = completion.complete_cve_report(ReportOptions(("json",)), out, _CVE, 0, bundle=bundle, telemetry={"cost_usd": float("nan")})
    assert not result.errors
    context = _read(out)
    data = context["extensions"]["raptor.result"]
    assert data["bundle"]["files_changed"] == 103
    assert len(data["bundle"]["files_captured"]) == 100
    assert data["bundle"]["file_records_omitted"] == 3
    assert data["capture_limited"] is True
    assert "non-finite" in data["discovery_telemetry"]["fields"]["cost_usd"]
    assert context["state"] == "partial"


@pytest.mark.parametrize("options", [None, ReportOptions(enabled=False)])
def test_unrequested_or_disabled_capture_does_not_build_or_write_reports(tmp_path, monkeypatch, capsys, options):
    monkeypatch.setattr(completion, "NativeResult", lambda *args, **kwargs: pytest.fail("capture must not build"))
    out = tmp_path / "absent"
    assert completion.complete_cve_report(options, out, _CVE, 0, bundle=_bundle()) is None
    assert not out.exists()
    displayed = capsys.readouterr()
    assert not displayed.out
    assert _CVE in displayed.err and "Files changed" in displayed.err
    assert displayed.err.count("Native exit status") == 1


def test_quick_failure_has_unavailable_populations_and_no_private_bodies(tmp_path, capsys):
    assert completion.complete_cve_report(None, tmp_path / "absent", _CVE, 5,
                                         error_class="DiscoveryError", error_detail="private detail") is None
    output = capsys.readouterr()
    assert not output.out
    assert "unavailable, not zero" in output.err
    assert "DiscoveryError" in output.err
    assert "private detail" not in output.err
    assert "Files changed" not in output.err


def test_disabled_quick_view_does_not_adopt_or_refresh_prior_receipts(tmp_path, capsys):
    out = tmp_path / "run"
    root = out / "portable-reports" / _CVE
    root.mkdir(parents=True)
    (root / "reporting-manifest.json").write_text("old manifest")
    previous = root / "cve-diff-report.json"
    previous.write_text("old receipt")
    assert completion.complete_cve_report(ReportOptions(enabled=False), out, _CVE, 0, bundle=_bundle()) is None
    output = capsys.readouterr()
    assert "not refreshed" in output.err and "Files changed" in output.err
    assert "old receipt" not in output.err
    assert previous.read_text() == "old receipt"
    assert not (root / "summary.json").exists()


def test_native_and_input_destinations_are_refused(tmp_path):
    out = tmp_path / "run"
    out.mkdir()
    native = out / (_CVE + ".osv.json")
    native.write_text("native bytes")
    with pytest.raises(ValueError, match="replace native"):
        completion.prepare_cve_report(ReportOptions(("json",), native), out, _CVE)
    with pytest.raises(ValueError, match="clone input"):
        completion.prepare_cve_report(ReportOptions(("json",), tmp_path / "clone" / "view.json"), out, _CVE,
                                      input_root=tmp_path / "clone")
    assert native.read_text() == "native bytes"


def test_text_budget_bounds_the_persisted_capture(tmp_path):
    out = tmp_path / "run"
    bundle = replace(_bundle(), files=tuple(FileChange(("a/" * 995) + str(i), False, 1) for i in range(100)), files_changed=100)
    root_cause = RootCause("CWE-78", "injection", "observation " * 150, ("one",), ("handler",), 0.8, "model", 12, 8)
    assert all(len(file.path) < 2000 for file in bundle.files)
    result = completion.complete_cve_report(ReportOptions(("json",)), out, _CVE, 0, bundle=bundle, root_cause=root_cause)
    assert not result.errors
    context = _read(out)
    assert context["extensions"]["raptor.result"]["capture_limited"] is True
    assert len(json.dumps(context)) < 2_000_000
