"""Lifecycle and trust-gate tests for libexec/raptor-validation-helper.

Stage 0 starts the run record; any failure after that point must flip
the record to 'failed' rather than strand it in 'running'. The stage E
dynamic-execution gates must all resolve the project 'dynamic' marker
against the run's --target, not the launcher cwd fallback. Colocated
with the run-lifecycle CLI tests.
"""

import importlib.util
import os
import subprocess
import sys
from importlib.machinery import SourceFileLoader
from pathlib import Path

import pytest

from core.json import load_json
from core.run.metadata import RUN_METADATA_FILE

REPO_ROOT = Path(__file__).resolve().parents[3]
HELPER = str(REPO_ROOT / "libexec" / "raptor-validation-helper")


def _load_helper():
    os.environ.setdefault("_RAPTOR_TRUSTED", "1")
    loader = SourceFileLoader("raptor_validation_helper", HELPER)
    spec = importlib.util.spec_from_loader("raptor_validation_helper", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


def _run_stage0(tmp_path: Path, *extra: str):
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    target = tmp_path / "target"
    target.mkdir(exist_ok=True)
    (target / "a.c").write_text("int add(int a, int b) { return a + b; }\n")
    out = tmp_path / "out"
    env = os.environ.copy()
    env["HOME"] = str(home)
    env["_RAPTOR_TRUSTED"] = "1"
    env.pop("RAPTOR_CALLER_DIR", None)
    result = subprocess.run(
        [sys.executable, HELPER, "0", "--target", str(target),
         "--out", str(out), "--no-bridge", *extra],
        capture_output=True, text=True, env=env,
    )
    return result, out


class TestStage0Stranding:

    def test_invalid_sanitizer_cut_mode_marks_run_failed(self, tmp_path):
        result, out = _run_stage0(tmp_path, "--sanitizer-cut", "bogus")
        assert result.returncode != 0
        # The run record was created by start_run before the mode was
        # resolved — it must end 'failed', never a phantom 'running'.
        meta = load_json(out / RUN_METADATA_FILE)
        assert meta is not None, result.stderr
        assert meta["status"] == "failed"

    def test_valid_sanitizer_cut_mode_still_starts_run(self, tmp_path):
        result, out = _run_stage0(tmp_path, "--sanitizer-cut", "off")
        assert result.returncode == 0, result.stderr
        assert "OUTPUT_DIR=" in result.stdout
        # Stage 0 leaves the run in-flight for stages A-F/1.
        meta = load_json(out / RUN_METADATA_FILE)
        assert meta["status"] == "running"


class TestWitnessExecutionGate:

    def test_gate_receives_run_target(self, tmp_path, monkeypatch, capsys):
        # The project 'dynamic' marker's one-target rule must be
        # resolved from the run's --target (like the sibling sink-watch
        # and symbolic-replay gates), not from the launcher cwd.
        mod = _load_helper()
        trust = pytest.importorskip("core.project.trust")
        ws = pytest.importorskip(
            "packages.exploitability_validation.witness_stage")
        seen = {}

        def fake_gate(explicit, *, banner=True, target_path=None,
                      run_dir=None):
            seen["target_path"] = target_path
            return False

        def never(*args, **kwargs):
            raise AssertionError("must not execute when gate refuses")

        monkeypatch.setattr(trust, "resolve_dynamic_validation", fake_gate)
        monkeypatch.setattr(ws, "eligible_findings",
                            lambda findings: list(findings))
        monkeypatch.setattr(ws, "run_witness_stage", never)

        data = {"findings": [{"id": "FIND-1"}]}
        mod._run_witness_execution(str(tmp_path), str(tmp_path / "tree"),
                                   data, dynamic=None)
        assert seen["target_path"] == str(tmp_path / "tree")
        assert "dynamic execution not granted" in capsys.readouterr().out
