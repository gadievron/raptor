"""Standalone child state does not adopt or mutate a launcher's state."""

import json
import os
from pathlib import Path
import sys

import pytest

from core.testing.standalone_cli import run_standalone_cli


@pytest.mark.parametrize("trusted", [False, True])
def test_child_owns_state_and_preserves_transport(tmp_path, monkeypatch, trusted):
    monkeypatch.setenv("TMPDIR", str(tmp_path / "missing"))
    monkeypatch.setenv("_RAPTOR_SCRATCH_AUTH", "stale")
    monkeypatch.setenv("RAPTOR_SESSION_PID", "999999")
    monkeypatch.setenv("RAPTOR_SESSION_TOKEN", "stale")
    monkeypatch.setenv("RAPTOR_REGISTRY_HOME", str(tmp_path / "borrowed"))
    before = dict(os.environ)
    env = dict(before, OPENAI_BASE_URL="http://127.0.0.1:12345")
    env.pop("_RAPTOR_TRUSTED", None)
    if trusted:
        env["_RAPTOR_TRUSTED"] = "1"
    result = run_standalone_cli(
        [sys.executable, "-I", "-c", "import json,os; print(json.dumps(dict(os.environ)))"],
        env=env, capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stderr
    child = json.loads(result.stdout)
    assert child["OPENAI_BASE_URL"] == env["OPENAI_BASE_URL"]
    assert child.get("_RAPTOR_TRUSTED") == ("1" if trusted else None)
    for name in ("_RAPTOR_SCRATCH_AUTH", "RAPTOR_SESSION_PID", "RAPTOR_SESSION_TOKEN"):
        assert name not in child
    assert child["HOME"] != before["HOME"]
    assert child["TMPDIR"] != before["TMPDIR"]
    assert child["RAPTOR_REGISTRY_HOME"] != before["RAPTOR_REGISTRY_HOME"]
    assert not Path(child["HOME"]).exists(), "owned state was not removed"
    assert dict(os.environ) == before
    assert env["_RAPTOR_SCRATCH_AUTH"] == "stale"
