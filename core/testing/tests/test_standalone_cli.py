"""Standalone child state does not adopt or mutate a launcher's state."""

import json
import os
from pathlib import Path
import sys

import pytest

from core.testing.standalone_cli import run_standalone_cli, standalone_cli_env


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


def test_explicit_owned_data_home_survives_multiple_children(tmp_path, monkeypatch):
    data_home = tmp_path / "keys"
    data_home.mkdir()
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "unrelated-parent-data"))
    before = dict(os.environ)
    program = (
        "import os,pathlib; "
        "p=pathlib.Path(os.environ['XDG_DATA_HOME'])/'owned-marker'; "
        "print(p.read_text() if p.exists() else 'fresh'); p.write_text('shared')"
    )
    for expected in ("fresh", "shared"):
        result = run_standalone_cli(
            [sys.executable, "-I", "-c", program],
            data_home=data_home, capture_output=True, text=True,
        )
        assert result.returncode == 0, result.stderr
        assert result.stdout.strip() == expected
    assert (data_home / "owned-marker").read_text() == "shared"
    assert dict(os.environ) == before


@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt])
def test_owned_environment_cleans_up_when_custom_runner_raises(tmp_path, error):
    data_home = tmp_path / "shared-data"
    data_home.mkdir()
    before = dict(os.environ)
    with pytest.raises(error):
        with standalone_cli_env(data_home=data_home) as env:
            home, scratch = Path(env["HOME"]), Path(env["TMPDIR"])
            assert home.is_dir() and scratch.is_dir()
            assert env["XDG_DATA_HOME"] == str(data_home)
            raise error("custom runner failed")
    assert not home.exists() and not scratch.exists()
    assert data_home.is_dir()
    assert dict(os.environ) == before
