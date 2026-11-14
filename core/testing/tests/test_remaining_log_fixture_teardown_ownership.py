"""Remaining logging fixtures continue cleanup after one handler refuses closure."""

from pathlib import Path
import subprocess
import sys

import pytest

from core.testing.processes import run_in_process_group
from core.testing.standalone_cli import standalone_cli_env


@pytest.mark.slow
@pytest.mark.parametrize("kind", ["owners", "private-log", "private-logs"])
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
def test_remaining_logging_fixture_retires_later_owners(tmp_path, kind, phase, outcome):
    root = Path(__file__).resolve().parents[3]
    script = Path(__file__).with_name("_remaining_log_fixture_teardown.py")
    with standalone_cli_env() as env:
        result = run_in_process_group(
            [
                sys.executable,
                "-I",
                str(script),
                str(root),
                str(tmp_path),
                kind,
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
    assert '"result": "LOG_FIXTURE_TEARDOWN_OK"' in result.stdout
    assert not result.stderr
