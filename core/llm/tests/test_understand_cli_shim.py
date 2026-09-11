"""CLI-contract tests for libexec/raptor-understand.

Two behaviours of the shim itself (not the hunt/trace substrate):

* ``--hunt-tool slopsquat`` is offline and model-independent — its
  documented no ``--model`` invocation must work, while --trace and the
  other hunt backends still require a model.
* ``RAPTOR_TRAJECTORY_DIR`` is snapshot/restored around ``main()`` —
  the run points it at --out for its duration, but an operator-exported
  value is handed back afterwards and nothing leaks to in-process
  callers.

Hermetic: slopsquat is the no-LLM, no-network backend, so no API key or
provider stub is needed.
"""

from __future__ import annotations

import importlib.machinery
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.integration

REPO_ROOT = Path(__file__).resolve().parents[3]
SCRIPT = REPO_ROOT / "libexec" / "raptor-understand"


@pytest.fixture
def env():
    e = os.environ.copy()
    e["_RAPTOR_TRUSTED"] = "1"
    # No provider key may leak in — these tests must never spend money.
    for k in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GEMINI_API_KEY",
              "MISTRAL_API_KEY", "GOOGLE_API_KEY"):
        e.pop(k, None)
    return e


@pytest.fixture
def repo(tmp_path):
    d = tmp_path / "repo"
    d.mkdir()
    (d / "requirements.txt").write_text("requests==2.31.0\n")
    return d


def _run(args, env):
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        capture_output=True, text=True, env=env, timeout=120,
    )


def test_slopsquat_hunt_needs_no_model(env, repo, tmp_path):
    out = tmp_path / "out"
    proc = _run(
        ["--hunt", "x", "--target", str(repo), "--out", str(out),
         "--hunt-tool", "slopsquat"],
        env,
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads((out / "hunt-result.json").read_text())
    assert payload["backend"] == "slopsquat"
    assert payload["models"] == ["sca-slopsquat"]


def test_hunt_with_other_backends_still_requires_model(env, repo, tmp_path):
    proc = _run(
        ["--hunt", "x", "--target", str(repo),
         "--out", str(tmp_path / "out")],
        env,
    )
    assert proc.returncode == 2
    assert "--model is required" in proc.stderr


def test_trace_requires_model_even_with_slopsquat_tool(env, repo, tmp_path):
    # --hunt-tool has no effect on --trace; the no-model carve-out must
    # not leak across modes.
    traces = tmp_path / "traces.json"
    traces.write_text("[]")
    proc = _run(
        ["--trace", str(traces), "--target", str(repo),
         "--out", str(tmp_path / "out"), "--hunt-tool", "slopsquat"],
        env,
    )
    assert proc.returncode == 2
    assert "--model is required" in proc.stderr


def _load_shim(monkeypatch):
    monkeypatch.setenv("_RAPTOR_TRUSTED", "1")
    loader = importlib.machinery.SourceFileLoader(
        "raptor_understand_under_test", str(SCRIPT))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


class TestTrajectoryDirHygiene:
    def _main(self, monkeypatch, repo, out) -> int:
        mod = _load_shim(monkeypatch)
        monkeypatch.setattr(sys, "argv", [
            "raptor-understand", "--hunt", "x", "--target", str(repo),
            "--out", str(out), "--hunt-tool", "slopsquat",
        ])
        return mod.main()

    def test_operator_value_restored_after_run(
            self, monkeypatch, repo, tmp_path):
        operator_dir = str(tmp_path / "operator-trajectories")
        monkeypatch.setenv("RAPTOR_TRAJECTORY_DIR", operator_dir)
        assert self._main(monkeypatch, repo, tmp_path / "out") == 0
        # The run points the var at --out for its duration (co-location
        # contract, pinned elsewhere) but must hand the operator's own
        # value back afterwards.
        assert os.environ.get("RAPTOR_TRAJECTORY_DIR") == operator_dir

    def test_unset_value_restored_to_unset(self, monkeypatch, repo, tmp_path):
        monkeypatch.delenv("RAPTOR_TRAJECTORY_DIR", raising=False)
        assert self._main(monkeypatch, repo, tmp_path / "out") == 0
        # The run-scoped value must not leak into in-process callers.
        assert "RAPTOR_TRAJECTORY_DIR" not in os.environ
