"""Standalone CVE report controls preserve lifecycle, native JSON and spend."""
from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from core.testing.state_isolation import pin_user_state_dirs
from cve_diff.acquisition.layers import CascadingRepoAcquirer, LayerReport
from cve_diff.agent.types import AgentOutput
from cve_diff.core.exceptions import UnsupportedSource
from cve_diff.core.models import CommitSha, DiffBundle, FileChange, PatchTuple, RepoRef
from .test_libexec_lifecycle import _load_shim, _run_shim

_CVE = "CVE-2024-99001"


@pytest.fixture(autouse=True)
def owned_state(tmp_path, monkeypatch):
    pin_user_state_dirs(monkeypatch, tmp_path)
    monkeypatch.setenv("_RAPTOR_TRUSTED", "1")


def _pipeline(calls, *, failed=False):
    class CapturedPipeline:
        def __init__(self, **kwargs):
            self.agent = SimpleNamespace(last_telemetry={"cost_usd": 0.25, "tokens": 20, "tool_calls": [], "tool_calls_with_args": []})
            self._stage_status = {"discover": {"status": "fail" if failed else "ok"}}
            self._last_extra_bundles = []

        def run(self, cve_id, work_dir):
            calls.append(("pipeline", cve_id))
            if failed:
                raise UnsupportedSource("fixture unavailable")
            from cve_diff.pipeline import PipelineResult
            ref = RepoRef("https://github.com/example/project", CommitSha("a" * 40), CommitSha("b" * 40), 100)
            diff = "--- a/src.c\n+++ b/src.c\n"
            bundle = DiffBundle(cve_id, ref, CommitSha("b" * 40), CommitSha("a" * 40), diff, 1, len(diff.encode()),
                                files=(FileChange("src.c", False, 1),))
            return PipelineResult(cve_id, bundle, AgentOutput(PatchTuple(ref.repository_url, ref.fix_commit, ref.introduced), "fixture"),
                                  CascadingRepoAcquirer(layers=(), reports=[LayerReport("fixture", True)]))
    return CapturedPipeline


@pytest.mark.parametrize("flags,exported", [([], False), (["--report-format", "json"], True), (["--no-report"], False)])
def test_success_captures_once_and_keeps_native_contract(tmp_path, monkeypatch, capsys, flags, exported):
    out = tmp_path / "run"
    calls = []
    assert _run_shim(["run", _CVE, "--output-dir", str(out), *flags], _pipeline(calls), calls, monkeypatch) == 0
    assert [call[0] for call in calls] == ["start", "pipeline", "complete"]
    displayed = capsys.readouterr()
    output = displayed.out
    assert "Files changed" in displayed.err
    assert displayed.err.count("Native exit status") == 1
    assert output.startswith(f"OUTPUT_DIR={out}\n")
    native = json.loads(output[output.index("{"):])
    assert native["ok"] is True
    assert native["bundle"]["files_changed"] == 1
    assert (out / (_CVE + ".osv.json")).exists()
    assert (out / (_CVE + ".md")).exists()
    report = out / "portable-reports" / _CVE / "report-context.json"
    assert report.exists() is exported
    if exported:
        context = json.loads(report.read_text())
        assert context["extensions"]["raptor.result"]["native_exit_status"] == 0
        assert context["extensions"]["raptor.metrics"]["Files changed"] == 1


def test_failure_exports_current_attempt_without_changing_code(tmp_path, monkeypatch, capsys):
    out = tmp_path / "run"
    calls = []
    assert _run_shim(["run", _CVE, "--output-dir", str(out), "--report-format", "json"],
                     _pipeline(calls, failed=True), calls, monkeypatch) == 4
    assert [call[0] for call in calls] == ["start", "pipeline", "fail"]
    output = capsys.readouterr().out
    native = json.loads(output[output.index("{"):])
    assert native["ok"] is False
    context = json.loads((out / "portable-reports" / _CVE / "report-context.json").read_text())
    assert context["state"] == "failed"
    assert context["extensions"]["raptor.result"]["bundle"] is None


@pytest.mark.parametrize("flags", [["--report-format", "unknown"], ["--no-report", "--report-format", "json"]])
def test_invalid_presentation_stops_before_start_or_dispatch(tmp_path, monkeypatch, flags):
    calls = []
    with pytest.raises(SystemExit) as exc:
        _run_shim(["run", _CVE, "--output-dir", str(tmp_path / "absent"), *flags], _pipeline(calls), calls, monkeypatch)
    assert exc.value.code == 1
    assert calls == []
    assert not (tmp_path / "absent").exists()


def test_native_artifact_destination_refused_before_run(tmp_path, monkeypatch):
    out = tmp_path / "run"
    calls = []
    assert _run_shim(["run", _CVE, "--output-dir", str(out), "--report-format", "json",
                      "--report-output", str(out / (_CVE + ".osv.json"))], _pipeline(calls), calls, monkeypatch) == 1
    assert calls == []


def test_presentation_exception_cannot_reclassify_native_success(tmp_path, monkeypatch, capsys):
    from cve_diff.report import completion
    seen = []
    def fail(*args, **kwargs):
        seen.append(args)
        raise RuntimeError("private report failure detail")
    monkeypatch.setattr(completion, "complete_cve_report", fail)
    out = tmp_path / "run"
    calls = []
    assert _run_shim(["run", _CVE, "--output-dir", str(out), "--report-format", "json"], _pipeline(calls), calls, monkeypatch) == 0
    assert [call[0] for call in calls] == ["start", "pipeline", "complete"]
    assert len(seen) == 1
    captured = capsys.readouterr()
    assert json.loads(captured.out[captured.out.index("{"):])["ok"] is True
    assert "Optional CVE-diff report failed" in captured.err
    assert "RuntimeError" in captured.err
    assert "private report failure detail" not in captured.err


def test_root_cause_warning_keeps_native_success_and_partial_report(tmp_path, monkeypatch):
    from cve_diff.analysis.analyzer import RootCauseAnalyzer
    seen = []
    def fail(self, bundle):
        seen.append(bundle)
        raise RuntimeError("root-cause unavailable")
    monkeypatch.setattr(RootCauseAnalyzer, "analyze", fail)
    out = tmp_path / "run"
    calls = []
    assert _run_shim(["run", _CVE, "--output-dir", str(out), "--with-root-cause", "--report-format", "json"],
                     _pipeline(calls), calls, monkeypatch) == 0
    assert [call[0] for call in calls] == ["start", "pipeline", "complete"]
    assert len(seen) == 1 and seen[0].cve_id == _CVE
    context = json.loads((out / "portable-reports" / _CVE / "report-context.json").read_text())
    assert context["state"] == "partial"
    assert next(stage for stage in context["stages"] if stage["stage_id"] == "root-cause analysis")["state"] == "failed"


def test_default_parser_dictionary_stays_compatible():
    shim = _load_shim()
    assert set(shim._parse_run_args([_CVE])) == {"cve_id", "output_dir", "budget_multiplier", "with_root_cause", "model"}
