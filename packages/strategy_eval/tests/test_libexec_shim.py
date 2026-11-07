"""Tests for ``packages/strategy_eval/scripts/strategy-eval``.

Drives the shim as a subprocess. Only the deterministic paths are
exercised — selection mode and argument handling; efficacy mode makes
live LLM calls and is never run in CI.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest

# parents[3] = packages/strategy_eval/tests -> strategy_eval -> packages -> repo root.
REPO_ROOT = Path(__file__).resolve().parents[3]
SHIM = (REPO_ROOT / "packages" / "strategy_eval" / "scripts"
        / "strategy-eval")


def _run(*args, env_extra=None, trusted=True):
    # This is a standalone dispatch test, not a child of the runner's launch.
    with TemporaryDirectory(prefix="strategy-eval-test-") as directory:
        root = Path(directory)
        home, scratch = root / "home", root / "tmp"
        home.mkdir()
        scratch.mkdir()
        env = dict(os.environ)
        for name in ("_RAPTOR_SCRATCH_AUTH", "RAPTOR_SESSION_PID", "RAPTOR_SESSION_TOKEN",
                     "_RAPTOR_TRUSTED", "CLAUDECODE"):
            env.pop(name, None)
        env.update(HOME=str(home), TMPDIR=str(scratch), TEMP=str(scratch), TMP=str(scratch),
                   RAPTOR_REGISTRY_HOME=str(home / ".raptor"),
                   XDG_CONFIG_HOME=str(home / ".config"), XDG_CACHE_HOME=str(home / ".cache"),
                   XDG_DATA_HOME=str(home / ".local/share"), XDG_STATE_HOME=str(home / ".local/state"))
        if trusted:
            env["_RAPTOR_TRUSTED"] = "1"
        if env_extra:
            env.update(env_extra)
        return subprocess.run(
            [sys.executable, str(SHIM), *args],
            env=env, capture_output=True, text=True, timeout=30,
            stdin=subprocess.DEVNULL,
        )


class TestTrustMarker:
    def test_refuses_without_marker(self):
        r = _run(trusted=False)
        assert r.returncode == 2
        assert "internal dispatch" in r.stderr


class TestSelectionMode:
    @pytest.mark.parametrize("stale_launch", [False, True])
    def test_default_is_selection_and_passes(self, monkeypatch, tmp_path, stale_launch):
        if stale_launch:
            monkeypatch.setenv("TMPDIR", str(tmp_path / "missing-runner-scratch"))
            monkeypatch.setenv("_RAPTOR_SCRATCH_AUTH", "invalid-runner-authorization")
        r = _run()
        assert r.returncode == 0, r.stderr
        assert "Selection eval (routing)" in r.stdout
        # All 8 strategies appear in the recall table.
        assert "lifecycle_drift" in r.stdout
        assert "failed: 0" in r.stdout


class TestEfficacyArgs:
    def test_efficacy_without_corpus_errors(self):
        # Deterministic: no LLM call is reached because the missing
        # --corpus is rejected first.
        r = _run("--efficacy")
        assert r.returncode == 1
        assert "requires --corpus" in r.stderr
