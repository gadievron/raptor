"""Smoke tests for libexec/raptor-coverage-summary --store wiring.

Drives the CLI as a subprocess; the store view logic itself is unit-tested
in test_store_summary.py. Here we only confirm the wiring + trust marker.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

# parents[3] = core/coverage/tests -> core/coverage -> core -> repo root.
REPO_ROOT = Path(__file__).resolve().parents[3]
CLI = REPO_ROOT / "libexec" / "raptor-coverage-summary"


def _run(*args, marker=True):
    env = dict(os.environ)
    if marker:
        env["_RAPTOR_TRUSTED"] = "1"
    else:
        env.pop("_RAPTOR_TRUSTED", None)
        env.pop("CLAUDECODE", None)
    env["RAPTOR_DIR"] = str(REPO_ROOT)
    return subprocess.run(
        [sys.executable, str(CLI), *args],
        env=env, capture_output=True, text=True,
    )


def _run_dir(tmp_path):
    d = tmp_path / "scan-1"
    d.mkdir()
    (d / ".raptor-run.json").write_text("{}")
    (d / "checklist.json").write_text(json.dumps({"files": [
        {"path": "a.c", "total_lines": 100, "items": [
            {"name": "f1", "line_start": 0, "line_end": 20},
            {"name": "f2", "line_start": 30, "line_end": 60},
        ]}]}))
    (d / "coverage-semgrep.json").write_text(json.dumps(
        {"tool": "semgrep", "files_examined": ["a.c"], "timestamp": "t"}))
    return d


def test_store_view_renders(tmp_path):
    r = _run(str(_run_dir(tmp_path)), "--store")
    assert r.returncode == 0, r.stderr
    assert "Coverage (persistent store)" in r.stdout
    # Both functions are semgrep(static)-covered, neither LLM -> LLM gap of 2.
    assert "no LLM review:  2" in r.stdout
    assert "a.c:f1" in r.stdout


def test_store_refuses_without_trust_marker(tmp_path):
    r = _run(str(_run_dir(tmp_path)), "--store", marker=False)
    assert r.returncode == 2
    assert "internal dispatch" in r.stderr
