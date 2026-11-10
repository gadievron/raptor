"""Baseline CLI captures once, honours settings and keeps measurement exits."""
from copy import deepcopy
import os
from pathlib import Path
import sys

import pytest

from core.dataflow import parity_report_completion as module
from core.dataflow.sanitizer_cut_parity import aggregate_parity, VERDICT_NO_SUPPRESS
from core.dataflow.tests.test_sanitizer_cut_parity import _rec
from core.reporting.writer import load_committed_report, regenerate
from core.testing.standalone_cli import run_standalone_cli


def _capture(monkeypatch):
    summary = aggregate_parity([_rec(fid="safe", lexical=True, verdict=VERDICT_NO_SUPPRESS, label="should_suppress"),
                                _rec(fid="real", lexical=False, verdict=VERDICT_NO_SUPPRESS, label="should_not_suppress")])
    calls = []
    def build():
        calls.append(True)
        return summary
    monkeypatch.setattr(module, "build_baseline_summary", build)
    return summary, calls


@pytest.mark.parametrize("mode", ["default", "disabled", "export"])
def test_once_captured_with_native_stdout_and_summary(tmp_path, monkeypatch, capsys, mode):
    summary, calls = _capture(monkeypatch)
    before = deepcopy(summary)
    monkeypatch.setenv("RAPTOR_SANITIZER_CUT", "0")
    root = tmp_path / "reports"
    flags = [] if mode == "default" else ["--no-report"] if mode == "disabled" else ["--report-format", "json", "--report-format", "xml", "--report-output", str(root)]
    assert module.main(flags) == 0
    shown = capsys.readouterr()
    assert "Safe to remove lexical (Phase 16 gate): NO" in shown.out
    assert "Baseline, not the gating window." in shown.out
    assert "fixture-measurement" in shown.err and "Optional parity report unavailable" not in shown.err
    assert calls == [True] and summary == before and os.environ["RAPTOR_SANITIZER_CUT"] == "0"
    if mode == "export":
        context, document, _ = load_committed_report(root)
        assert context.state == "completed" and context.stages[0].state == "completed"
        assert context.extensions["raptor.metrics"]["Native Phase 16 gate"] is False
        assert context.extensions["raptor.findings_available"] is False
        assert document.metadata["Measurement scope"] == "synthetic-baseline"
        captured = (root / "sanitizer-cut-parity.xml").read_bytes()
        def refuse():
            raise AssertionError("offline regeneration called fixture builder")
        monkeypatch.setattr(module, "build_baseline_summary", refuse)
        regenerate(root, tmp_path / "offline.xml", format="xml")
        assert (tmp_path / "offline.xml").read_bytes() == captured
    else:
        assert not root.exists() and "not refreshed" in shown.err
        assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("flags", [["--report-format", "json"], ["--report-format", "unavailable"],
                                   ["--no-report", "--report-format", "json"],
                                   ["--report-format", "json", "--report-output", "mismatch.md"]])
def test_refusal_before_fixture_execution(monkeypatch, flags):
    _, calls = _capture(monkeypatch)
    with pytest.raises(SystemExit) as exc:
        module.main(flags)
    assert exc.value.code == 2 and calls == []


def test_reached_publisher_fault_retains_informational_exit(tmp_path, monkeypatch, capsys):
    _, calls = _capture(monkeypatch)
    reached = []
    def fail(*args, **kwargs):
        reached.append(True)
        raise OSError("sensitive fault text")
    monkeypatch.setattr(module, "complete_reporting", fail)
    assert module.main(["--report-output", str(tmp_path / "reports")]) == 0
    shown = capsys.readouterr()
    assert "Safe to remove lexical (Phase 16 gate): NO" in shown.out
    assert reached == [True] and calls == [True]
    assert "native measurement retained" in shown.err and "sensitive fault text" not in shown.err


@pytest.mark.slow
def test_developer_entrypoint_uses_owned_root_without_ambient_raptor_dir(tmp_path):
    script = Path(__file__).resolve().parents[1] / "scripts" / "sanitizer-cut-parity-report"
    env = dict(os.environ, RAPTOR_DIR=str(tmp_path / "untrusted-root"))
    result = run_standalone_cli([sys.executable, str(script), "--help"], env=env, cwd=tmp_path,
                                capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert "--report-output" in result.stdout and "--report-format" in result.stdout
