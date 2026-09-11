"""Run-record lifecycle tests for libexec/raptor-sca-run.

The scan path wraps ``run_sca`` in start/complete/fail lifecycle calls;
these tests assert the run record can never be stranded in 'running'
(interrupt, option-resolution failure) and that the exit code always
agrees with the recorded run status (threshold-check input failures).
Colocated with the run-lifecycle CLI tests.
"""

import importlib.util
import json
import os
from importlib.machinery import SourceFileLoader
from pathlib import Path

import pytest

from core.json import load_json
from core.run.metadata import RUN_METADATA_FILE

REPO_ROOT = Path(__file__).resolve().parents[3]


def _load_script():
    os.environ.setdefault("_RAPTOR_TRUSTED", "1")
    script = str(REPO_ROOT / "libexec" / "raptor-sca-run")
    loader = SourceFileLoader("raptor_sca_run", script)
    spec = importlib.util.spec_from_loader("raptor_sca_run", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


@pytest.fixture
def env(tmp_path: Path, monkeypatch) -> dict:
    """Hermetic target/out dirs with a scrubbed HOME (no real project
    state can leak into project resolution or journal merges)."""
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("RAPTOR_CALLER_DIR", raising=False)
    target = tmp_path / "target"
    target.mkdir()
    out = tmp_path / "out"
    mod = _load_script()
    # Summary rendering needs a real pipeline result shape; the run
    # record is what these tests assert on.
    monkeypatch.setattr(mod, "_print_summary", lambda result: None)
    return {"mod": mod, "target": target, "out": out}


def _status(out_dir: Path) -> str:
    return load_json(out_dir / RUN_METADATA_FILE)["status"]


def _argv(env: dict, *extra: str) -> list:
    return [str(env["target"]), "--out", str(env["out"]), *extra]


class TestStranding:

    def test_keyboard_interrupt_marks_run_interrupted(self, env, monkeypatch):
        def boom(**kwargs):
            raise KeyboardInterrupt

        monkeypatch.setattr("packages.sca.pipeline.run_sca", boom)
        with pytest.raises(KeyboardInterrupt):
            env["mod"]._run_analyse(_argv(env))
        assert _status(env["out"]) == "interrupted"

    def test_scan_exception_marks_run_failed(self, env, monkeypatch):
        def boom(**kwargs):
            raise RuntimeError("scanner exploded")

        monkeypatch.setattr("packages.sca.pipeline.run_sca", boom)
        rc = env["mod"]._run_analyse(_argv(env))
        assert rc == 3
        assert _status(env["out"]) == "failed"

    def test_options_resolution_failure_marks_run_failed(self, env,
                                                         monkeypatch):
        def boom(args):
            raise RuntimeError("corrupt project settings")

        monkeypatch.setattr("packages.sca._scan_args.options_from_args", boom)
        rc = env["mod"]._run_analyse(_argv(env))
        assert rc == 3
        assert _status(env["out"]) == "failed"

    def test_success_path_completes_run(self, env, monkeypatch):
        monkeypatch.setattr("packages.sca.pipeline.run_sca",
                            lambda **kwargs: {"findings": []})
        rc = env["mod"]._run_analyse(_argv(env))
        assert rc == 0
        assert _status(env["out"]) == "completed"


class TestThresholdGateStatusAgreement:

    def test_unreadable_findings_fails_run_and_exits_3(self, env,
                                                       monkeypatch):
        # run_sca "succeeds" but never writes findings.json — the
        # threshold gate's input read fails, so exit code 3 must be
        # matched by a 'failed' run record, never 'completed'.
        monkeypatch.setattr("packages.sca.pipeline.run_sca",
                            lambda **kwargs: {"findings": []})
        rc = env["mod"]._run_analyse(
            _argv(env, "--fail-on-severity", "high"))
        assert rc == 3
        assert _status(env["out"]) == "failed"

    def test_readable_findings_completes_run(self, env, monkeypatch):
        def fake_run_sca(*, target, output_dir, options):
            output_dir.mkdir(parents=True, exist_ok=True)
            (output_dir / "findings.json").write_text(json.dumps([]))
            return {"findings": []}

        monkeypatch.setattr("packages.sca.pipeline.run_sca", fake_run_sca)
        rc = env["mod"]._run_analyse(
            _argv(env, "--fail-on-severity", "high"))
        assert rc == 0
        assert _status(env["out"]) == "completed"
