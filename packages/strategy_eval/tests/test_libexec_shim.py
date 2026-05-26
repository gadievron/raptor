"""Tests for ``libexec/raptor-strategy-eval``.

Drives the shim as a subprocess. Only the deterministic paths are
exercised — selection mode and argument handling; efficacy mode makes
live LLM calls and is never run in CI.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

# parents[3] = packages/strategy_eval/tests -> strategy_eval -> packages -> repo root.
REPO_ROOT = Path(__file__).resolve().parents[3]
SHIM = REPO_ROOT / "libexec" / "raptor-strategy-eval"


def _run(*args, env_extra=None):
    env = dict(os.environ)
    env["_RAPTOR_TRUSTED"] = "1"
    if env_extra:
        env.update(env_extra)
    return subprocess.run(
        [sys.executable, str(SHIM), *args],
        env=env, capture_output=True, text=True,
    )


class TestTrustMarker:
    def test_refuses_without_marker(self):
        env = {k: v for k, v in os.environ.items()
               if k not in ("_RAPTOR_TRUSTED", "CLAUDECODE")}
        r = subprocess.run(
            [sys.executable, str(SHIM)],
            env=env, capture_output=True, text=True,
        )
        assert r.returncode == 2
        assert "internal dispatch" in r.stderr


class TestSelectionMode:
    def test_default_is_selection_and_passes(self):
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
