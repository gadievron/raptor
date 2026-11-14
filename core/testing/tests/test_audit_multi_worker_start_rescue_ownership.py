"""Two-worker audit rescue preserves partial-start failure and all-join controls."""

from pathlib import Path
import subprocess
import sys

import pytest

from core.testing.processes import run_in_process_group
from core.testing.standalone_cli import standalone_cli_env


@pytest.mark.slow
@pytest.mark.parametrize(
    "mode,kind,index",
    [
        (mode, kind, index)
        for mode in ("before", "after")
        for kind in ("error", "interrupt")
        for index in (0, 1)
    ]
    + [("normal", "error", 0)],
)
def test_audit_multi_worker_rescue_preserves_partial_start_failure(
    tmp_path, mode, kind, index
):
    root = Path(__file__).resolve().parents[3]
    script = Path(__file__).with_name("_audit_multi_worker_start_rescue.py")
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
    assert result.stdout.strip() == "AUDIT_MULTI_START_RESCUE_OK"
