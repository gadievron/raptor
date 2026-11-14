"""Final independent scratch rescue survives native fixture-close failure."""

from pathlib import Path
import subprocess
import sys

import pytest

from core.testing.processes import run_in_process_group
from core.testing.standalone_cli import standalone_cli_env


@pytest.mark.slow
def test_actual_tool_fixture_driver_runs_independent_final_rescue(tmp_path):
    root = Path(__file__).resolve().parents[3]
    script = Path(__file__).with_name("_tool_fixture_final_rescue.py")
    with standalone_cli_env() as env:
        result = run_in_process_group(
            [sys.executable, "-I", str(script), str(root), str(tmp_path), "candidate"],
            timeout=20,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "TOOL_FINAL_RESCUE_OK"
    assert "semgrep scratch cleanup incomplete:" in result.stderr
    assert "Traceback" not in result.stderr
