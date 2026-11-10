"""Alternative CLI keeps its native exception policy with optional exports."""
from __future__ import annotations

from importlib import import_module
import json

import pytest
from typer.testing import CliRunner

from core.testing.state_isolation import pin_user_state_dirs
from cve_diff.analysis.analyzer import RootCause, RootCauseAnalysisError, RootCauseAnalyzer
from cve_diff.core.exceptions import AcquisitionError, AnalysisError, DiscoveryError, IdenticalCommitsError, UnsupportedSource
from cve_diff.infra.disk_budget import DiskBudgetExceeded
from .test_libexec_reporting import _CVE, _pipeline

cli = import_module("cve_diff.cli.main")


@pytest.fixture(autouse=True)
def owned_state(tmp_path, monkeypatch):
    pin_user_state_dirs(monkeypatch, tmp_path)


def _invoke(out, flags):
    return CliRunner().invoke(cli.app, ["run", _CVE, "--output-dir", str(out), "--quiet", "--disk-limit", "99.9", *flags])


@pytest.mark.parametrize("flags,exported", [([], False), (["--report-format", "json"], True), (["--no-report"], False)])
def test_native_success_and_export_scope(tmp_path, monkeypatch, flags, exported):
    calls = []
    monkeypatch.setattr(cli, "Pipeline", _pipeline(calls))
    out = tmp_path / "run"
    result = _invoke(out, flags)
    assert result.exit_code == 0, result.output
    assert calls == [("pipeline", _CVE)]
    assert (out / (_CVE + ".osv.json")).exists()
    assert (out / (_CVE + ".md")).exists()
    capture = out / "portable-reports" / _CVE / "report-context.json"
    assert capture.exists() is exported
    if exported:
        context = json.loads(capture.read_text())
        assert context["run_id"] == "unknown"
        assert context["extensions"]["raptor.metrics"]["Files changed"] == 1


@pytest.mark.parametrize("exception,code", [(UnsupportedSource, 4), (DiscoveryError, 5), (AcquisitionError, 6),
                                          (IdenticalCommitsError, 7), (AnalysisError, 9), (DiskBudgetExceeded, 8)])
def test_native_failure_policy_and_capture_match(tmp_path, monkeypatch, exception, code):
    calls = []
    class FailedPipeline(_pipeline(calls)):
        def run(self, cve_id, work_dir):
            calls.append(("pipeline", cve_id))
            self._stage_status = {"discover": {"status": "fail", "reason": "fixture"}}
            raise exception("fixture")
    monkeypatch.setattr(cli, "Pipeline", FailedPipeline)
    out = tmp_path / "run"
    result = _invoke(out, ["--report-format", "json"])
    assert result.exit_code == code, result.output
    assert calls == [("pipeline", _CVE)]
    context = json.loads((out / "portable-reports" / _CVE / "report-context.json").read_text())
    assert context["state"] == "failed"
    assert context["extensions"]["raptor.result"]["native_exit_status"] == code
    assert context["extensions"]["raptor.result"]["bundle"] is None


@pytest.mark.parametrize("failed,code", [(False, 0), (True, 9)])
def test_root_cause_policy_and_separate_cost_scope(tmp_path, monkeypatch, failed, code):
    calls = []
    seen = []
    monkeypatch.setattr(cli, "Pipeline", _pipeline(calls))
    def analyze(self, bundle):
        seen.append(bundle)
        if failed:
            raise RootCauseAnalysisError("fixture root-cause unavailable")
        return RootCause("CWE-78", "injection", "recorded observation", ("one",), ("handler",), 0.8, "fixture-model", 12, 8)
    monkeypatch.setattr(RootCauseAnalyzer, "analyze", analyze)
    out = tmp_path / "run"
    result = _invoke(out, ["--with-root-cause", "--report-format", "json"])
    assert result.exit_code == code, result.output
    assert len(seen) == 1 and seen[0].cve_id == _CVE
    assert calls == [("pipeline", _CVE)]
    context = json.loads((out / "portable-reports" / _CVE / "report-context.json").read_text())
    assert context["extensions"]["raptor.result"]["native_exit_status"] == code
    assert (out / (_CVE + ".osv.json")).exists() is not failed
    if failed:
        assert context["state"] == "failed"
        assert context["extensions"]["raptor.result"]["bundle"] is not None
    else:
        assert context["extensions"]["raptor.metrics"]["Discovery cost USD"] == 0.25
        assert context["extensions"]["raptor.metrics"]["Root-cause input tokens"] == 12


@pytest.mark.parametrize("flags", [["--report-format", "unknown"], ["--no-report", "--report-format", "json"]])
def test_invalid_options_precede_pipeline_and_output_creation(tmp_path, monkeypatch, flags):
    monkeypatch.setattr(cli, "Pipeline", lambda **kwargs: pytest.fail("must refuse before constructing pipeline"))
    out = tmp_path / "absent"
    result = _invoke(out, flags)
    assert result.exit_code == 2, result.output
    assert not out.exists()


def test_presentation_fault_does_not_change_native_success(tmp_path, monkeypatch):
    from cve_diff.report import completion
    calls = []
    seen = []
    monkeypatch.setattr(cli, "Pipeline", _pipeline(calls))
    def fail(*args, **kwargs):
        seen.append(args)
        raise RuntimeError("private fault detail")
    monkeypatch.setattr(completion, "complete_cve_report", fail)
    out = tmp_path / "run"
    result = _invoke(out, ["--report-format", "json"])
    assert result.exit_code == 0, result.output
    assert len(seen) == 1
    assert (out / (_CVE + ".osv.json")).exists()
    assert "Optional CVE-diff report failed" in result.output
    assert "private fault detail" not in result.output


@pytest.mark.parametrize("source", [False, True])
def test_reserved_or_clone_input_destination_preflight(tmp_path, monkeypatch, source):
    monkeypatch.setattr(cli, "Pipeline", lambda **kwargs: pytest.fail("destination refusal must precede pipeline"))
    out = tmp_path / "run"
    clone = tmp_path / "clone"
    destination = clone / "view.json" if source else out / (_CVE + ".osv.json")
    flags = ["--report-format", "json", "--report-output", str(destination)]
    if source:
        flags += ["--work-dir", str(clone)]
    result = _invoke(out, flags)
    assert result.exit_code == 2, result.output
    assert not out.exists()
    assert not clone.exists()
