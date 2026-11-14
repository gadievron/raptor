"""Logging fixture teardown attempts every owned handler and stream."""

from pathlib import Path
import subprocess
import sys

import pytest

from core.testing.processes import run_in_process_group
from core.testing.standalone_cli import standalone_cli_env


@pytest.mark.slow
@pytest.mark.parametrize(
    "phase,kind",
    [
        ("before", "error"),
        ("before", "interrupt"),
        ("after", "error"),
        ("after", "interrupt"),
        ("normal", "error"),
    ],
)
def test_logging_fixture_teardown_retires_later_resources(tmp_path, phase, kind):
    root = Path(__file__).resolve().parents[3]
    script = Path(__file__).with_name("_logging_fixture_teardown.py")
    with standalone_cli_env() as env:
        result = run_in_process_group(
            [
                sys.executable,
                "-I",
                str(script),
                str(root),
                str(tmp_path),
                phase,
                kind,
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
    assert result.stdout.strip() == "LOGGING_FIXTURE_TEARDOWN_OK"
    assert not result.stderr
