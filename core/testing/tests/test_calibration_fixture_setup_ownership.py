"""Calibration fixture setup restores cache state on every exit."""

from pathlib import Path
import subprocess
import sys

import pytest

from core.testing.processes import run_in_process_group
from core.testing.standalone_cli import standalone_cli_env


@pytest.mark.slow
@pytest.mark.parametrize("case", ["generation", "waiter"])
@pytest.mark.parametrize(
    "stage,outcome",
    [
        ('directory', 'error'),
        ('directory', 'interrupt'),
        ('cache', 'error'),
        ('cache', 'interrupt'),
        ('write-before', 'error'),
        ('write-before', 'interrupt'),
        ('write-after', 'error'),
        ('write-after', 'interrupt'),
        ('normal', 'error'),
    ],
)
def test_calibration_fixture_setup_restores_cache_state(
    tmp_path, case, stage, outcome
):
    root = Path(__file__).resolve().parents[3]
    script = Path(__file__).with_name("_calibration_fixture_setup.py")
    with standalone_cli_env() as env:
        result = run_in_process_group(
            [
                sys.executable,
                "-I",
                str(script),
                str(root),
                str(tmp_path),
                case,
                stage,
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
    assert '"result": "CALIBRATION_SETUP_OWNER_OK"' in result.stdout
    assert not result.stderr
