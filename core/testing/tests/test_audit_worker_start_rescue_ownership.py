"""Audit fixture rescue preserves failures before and after thread startup."""

from pathlib import Path
import subprocess
import sys

import pytest

from core.testing.processes import run_in_process_group
from core.testing.standalone_cli import standalone_cli_env


@pytest.mark.slow
@pytest.mark.parametrize("index", range(5))
@pytest.mark.parametrize(
    "mode,kind",
    [
        ("before", "error"),
        ("before", "interrupt"),
        ("after", "error"),
        ("after", "interrupt"),
        ("normal", "error"),
    ],
)
def test_audit_worker_start_failure_preserves_primary_and_restores_state(
    tmp_path, index, mode, kind
):
    root = Path(__file__).resolve().parents[3]
    script = Path(__file__).with_name("_audit_worker_start_rescue.py")
    with standalone_cli_env() as env:
        result = run_in_process_group(
            [
                sys.executable,
                "-I",
                str(script),
                str(root),
                str(tmp_path),
                mode,
                kind,
                "candidate",
                str(index),
            ],
            timeout=20,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "AUDIT_START_RESCUE_OK"
