"""Nonce fixture setup restores telemetry across publication failures."""

from pathlib import Path
import subprocess
import sys

import pytest

from core.testing.processes import run_in_process_group
from core.testing.standalone_cli import standalone_cli_env


@pytest.mark.slow
@pytest.mark.parametrize(
    "stage,outcome",
    [
        ("publication", "error"),
        ("publication", "interrupt"),
        ("event", "error"),
        ("event", "interrupt"),
        ("normal", "error"),
    ],
)
def test_nonce_fixture_setup_restores_borrowed_telemetry(
    tmp_path, stage, outcome
):
    root = Path(__file__).resolve().parents[3]
    script = Path(__file__).with_name("_nonce_fixture_publication.py")
    with standalone_cli_env() as env:
        result = run_in_process_group(
            [
                sys.executable,
                "-I",
                str(script),
                str(root),
                str(tmp_path),
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
    assert '"result": "NONCE_SETUP_OWNER_OK"' in result.stdout
    assert not result.stderr
