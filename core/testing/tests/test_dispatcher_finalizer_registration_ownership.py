"""Scratch finalizer registration owns its directory across handoff failures."""

from pathlib import Path
import subprocess
import sys

import pytest

from core.testing.processes import run_in_process_group
from core.testing.standalone_cli import standalone_cli_env


@pytest.mark.slow
@pytest.mark.parametrize("helper", ["_owned_dir", "_inproc_dir"])
@pytest.mark.parametrize(
    "phase,outcome",
    [
        ("before", "error"),
        ("before", "interrupt"),
        ("after", "error"),
        ("after", "interrupt"),
        ("normal", "error"),
    ],
)
def test_dispatcher_fixture_finalizer_handoff_owns_directory(
    tmp_path, helper, phase, outcome
):
    root = Path(__file__).resolve().parents[3]
    script = Path(__file__).with_name("_dispatcher_finalizer_registration.py")
    with standalone_cli_env() as env:
        result = run_in_process_group(
            [
                sys.executable,
                "-I",
                str(script),
                str(root),
                str(tmp_path),
                helper,
                phase,
                outcome,
                "candidate",
            ],
            timeout=20,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    assert result.returncode == 0, result.stderr
    assert '"result": "DISPATCHER_FINALIZER_OK"' in result.stdout
    assert not result.stderr
